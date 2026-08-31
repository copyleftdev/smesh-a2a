//! Executable PostgreSQL schema-v6 durable authority adapter.
#![allow(
    clippy::if_not_else,
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use std::{
    collections::{BTreeSet, VecDeque},
    fmt::{self, Write as _},
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
    SendMessageResponse, StreamResponse, Task, TaskStatusUpdateEvent,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::{
    Hook, HookError, Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime,
};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_postgres::{NoTls, Row};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;

use crate::{
    AdmissionOutcome, AdmissionRecord, ArtifactKeyring, ArtifactMigrationPlan,
    ArtifactMigrationPlanFile, ArtifactStoreConfig, AtomicRecordCounts, AttemptDisposition,
    AuthorityCapabilities, AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown,
    AuthorizationAuditInput, AuthorizationAuditParts, AuthorizationAuditSink,
    AuthorizationDecisionEffect, AuthorizedMutation, AuthorizedTaskRead, CancellationAuthority,
    CancellationOutcome, ChangeObservation, ChangeObserver, DurableDispatchEnvelope,
    DurableReceiverResult, DurableReceiverTermination, ExecutionReservation, LeaseRenewalOutcome,
    MeshEvent, MeshRequest, OutboxAuthority, OutboxLease, OwnedTaskScope, PosixArtifactBlobStore,
    QuotaLease, QuotaLeaseAuthority, QuotaReservationInput, ReceiverAdmission, ReceiverAuthority,
    ReceiverLease, ReloadingArtifactKeyring, SendMessageAdmission, StreamTranscriptBatch,
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
const DISTRIBUTED_QUOTA_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0004_distributed_quota_authority.sql");
const DISTRIBUTED_QUOTA_MIGRATION_NAME: &str = "0004_distributed_quota_authority";
const ARTIFACT_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0005_artifact_authority.sql");
const ARTIFACT_MIGRATION_NAME: &str = "0005_artifact_authority";
const AUDIT_PROJECTION_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0006_audit_projection.sql");
const AUDIT_PROJECTION_MIGRATION_NAME: &str = "0006_audit_projection";
const CALLBACK_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0007_callback_authority.sql");
const CALLBACK_MIGRATION_NAME: &str = "0007_callback_authority";
const CALLBACK_POLICY_FENCE_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0008_callback_policy_fence.sql");
const CALLBACK_POLICY_FENCE_MIGRATION_NAME: &str = "0008_callback_policy_fence";
const AUTHORIZATION_RETENTION_MIGRATION_SQL: &str =
    include_str!("../migrations/postgres/0009_authorization_audit_retention.sql");
const AUTHORIZATION_RETENTION_MIGRATION_NAME: &str = "0009_authorization_audit_retention";
const LOGICAL_SCHEMA_VERSION: i64 = 6;
const CURRENT_SCHEMA_VERSION: i64 = 9;
const MAX_CONFIG_BYTES: usize = 4096;
const ACTIVE_CALLBACK_ENROLLMENT_EXISTS_SQL: &str = "SELECT EXISTS(SELECT 1 FROM __S__.callback_enrollments WHERE tenant_scope=$1 AND enrollment_id=$2 AND enrollment_generation=$3 AND canonical_url=$4 AND url_digest=$5 AND policy_id=$6 AND policy_revision=$7 AND policy_revision=(SELECT max(policy_revision) FROM __S__.callback_policy_snapshots))";
const CALLBACK_POLICY_FENCE_LOCK: i64 = 6_001_136_200_065;
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
static POSTGRES_CALLBACK_TERMINAL_TEST_FAULT: Mutex<Option<crate::CallbackTerminalTestFault>> =
    Mutex::new(None);

/// Deterministic loopback-only transaction faults used by integration tests.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostgresTransactionTestFault {
    SerializationFailure,
    DeadlockDetected,
    NonRetryable,
    AmbiguousCommit,
}

/// One-shot, loopback-test-only failures inside receiver artifact publication.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactPublicationTestFault {
    BeforeContentObject,
    AfterContentObject,
    BeforeChunkBatch,
    AfterChunkBatch,
    BeforeManifest,
    AfterManifest,
    BeforeProvenanceBatch,
    AfterProvenanceBatch,
    BeforeReference,
    AfterReference,
    BeforeUploadIntent,
    AfterUploadIntent,
    BeforeReceiverEffect,
    AfterReceiverEffect,
    BeforeReceiverFrames,
    AfterReceiverFrames,
    BeforeReceiverCompletion,
    AfterReceiverCompletion,
}
pub(crate) const EXPECTED_TABLES: &[&str] = &[
    "artifact_backup_inventory",
    "artifact_backup_jobs",
    "artifact_backup_key_dependencies",
    "artifact_backup_leases",
    "artifact_chunks",
    "artifact_corruption_audits",
    "artifact_gc_jobs",
    "artifact_key_audits",
    "artifact_key_generations",
    "artifact_key_rotation_plans",
    "artifact_manifests",
    "artifact_migration_plans",
    "artifact_orphan_audits",
    "artifact_orphan_candidates",
    "artifact_read_leases",
    "artifact_reencryption_jobs",
    "artifact_references",
    "artifact_restore_jobs",
    "artifact_retention_holds",
    "artifact_tombstones",
    "audit_projection_control",
    "audit_projection_outbox",
    "audit_projection_session_secret",
    "audit_projection_sessions",
    "authorization_decisions",
    "authorization_retention_diagnostics",
    "callback_attempts",
    "callback_audits",
    "callback_configs",
    "callback_deliveries",
    "callback_enrollments",
    "callback_events",
    "callback_policy_snapshots",
    "callback_tenant_scheduler",
    "callback_worker_session_secret",
    "callback_worker_sessions",
    "cancellation_intents",
    "content_objects",
    "idempotency_records",
    "list_page_tokens",
    "list_snapshot_entries",
    "list_snapshots",
    "loopback_effects",
    "outbox",
    "outbox_attempts",
    "outbox_tenant_scheduler",
    "provenance_edges",
    "quota_allocations",
    "quota_buckets",
    "quota_denial_audits",
    "quota_execution_reservations",
    "quota_intents",
    "quota_leases",
    "quota_override_audits",
    "quota_policy_reconciliation_audits",
    "quota_policy_versions",
    "quota_receipts",
    "quota_request_receipts",
    "quota_reservations",
    "receiver_frames",
    "receiver_inbox",
    "retained_authority_usage",
    "schema_migrations",
    "store_identity",
    "store_metadata",
    "stream_frames",
    "stream_transcripts",
    "task_events",
    "tasks",
    "upload_intents",
];
const TENANT_TABLES: &[&str] = &[
    "artifact_backup_inventory",
    "artifact_backup_jobs",
    "artifact_backup_key_dependencies",
    "artifact_backup_leases",
    "artifact_chunks",
    "artifact_corruption_audits",
    "artifact_gc_jobs",
    "artifact_key_audits",
    "artifact_key_generations",
    "artifact_key_rotation_plans",
    "artifact_manifests",
    "artifact_migration_plans",
    "artifact_read_leases",
    "artifact_reencryption_jobs",
    "artifact_references",
    "artifact_restore_jobs",
    "artifact_retention_holds",
    "artifact_tombstones",
    "audit_projection_outbox",
    "authorization_decisions",
    "authorization_retention_diagnostics",
    "callback_attempts",
    "callback_audits",
    "callback_configs",
    "callback_deliveries",
    "callback_enrollments",
    "callback_events",
    "callback_tenant_scheduler",
    "cancellation_intents",
    "content_objects",
    "idempotency_records",
    "list_page_tokens",
    "list_snapshot_entries",
    "list_snapshots",
    "loopback_effects",
    "outbox",
    "outbox_attempts",
    "outbox_tenant_scheduler",
    "provenance_edges",
    "quota_allocations",
    "quota_buckets",
    "quota_denial_audits",
    "quota_execution_reservations",
    "quota_intents",
    "quota_leases",
    "quota_override_audits",
    "quota_policy_reconciliation_audits",
    "quota_policy_versions",
    "quota_receipts",
    "quota_request_receipts",
    "quota_reservations",
    "receiver_frames",
    "receiver_inbox",
    "retained_authority_usage",
    "stream_frames",
    "stream_transcripts",
    "task_events",
    "tasks",
    "upload_intents",
];
const EXPECTED_CUSTOM_INDEXES: &[&str] = &[
    "artifact_backup_jobs_active",
    "artifact_backup_leases_active",
    "artifact_gc_jobs_due",
    "artifact_gc_jobs_one_active",
    "artifact_manifests_object",
    "artifact_manifests_resolve",
    "artifact_migration_checkpoint",
    "artifact_migration_one_active",
    "artifact_orphan_candidates_due",
    "artifact_read_leases_active",
    "artifact_reencryption_due",
    "artifact_references_gc",
    "artifact_references_resolve",
    "artifact_restore_one_enabled_identity",
    "artifact_retention_holds_active",
    "audit_projection_authorization_source",
    "audit_projection_claim",
    "audit_projection_tenant_claim",
    "authorization_decisions_actor_time",
    "authorization_decisions_projection_source",
    "authorization_decisions_resource_time",
    "authorization_decisions_tenant_time",
    "callback_audits_tenant_time",
    "callback_configs_task_list",
    "callback_configs_task_state",
    "callback_deliveries_claim",
    "callback_deliveries_due",
    "callback_deliveries_tenant_due",
    "callback_enrollments_url",
    "callback_tenant_scheduler_turn",
    "cancellation_intents_dispatch_requested",
    "cancellation_intents_task",
    "content_objects_dedupe",
    "content_objects_gc_due",
    "idempotency_records_task",
    "list_page_tokens_snapshot",
    "list_snapshots_expiry",
    "outbox_due",
    "outbox_leased_tenant_due",
    "outbox_pending_tenant_due",
    "outbox_task_state",
    "outbox_tenant_scheduler_eligible",
    "provenance_edges_parent",
    "quota_allocations_task_active",
    "quota_buckets_scope_lookup",
    "quota_denial_audits_expiry",
    "quota_execution_reservations_task_state",
    "quota_leases_gc",
    "quota_leases_scope_active",
    "quota_override_audits_expiry",
    "quota_policy_one_active",
    "quota_receipts_scope_lookup",
    "quota_request_receipts_mutation_lookup",
    "quota_reservations_principal_state",
    "receiver_inbox_reclaim",
    "retained_authority_usage_principal",
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
    "upload_intents_due",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationAuditCleanup {
    pub deleted: u64,
    pub projection_blocked: u64,
    /// True when at least one cutoff-eligible source row remains after this batch.
    pub has_more: bool,
    pub oldest_remaining: Option<i64>,
    pub cutoff: i64,
}

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
    audit_projection_enabled: bool,
    quota_enforcement: bool,
    quota_policy: Option<Arc<crate::QuotaPolicy>>,
    quota_reconciliation_plan: Option<Arc<crate::QuotaReconciliationPlan>>,
    push_policy: Option<Arc<crate::push::PushPolicy>>,
    max_tasks: usize,
    artifact_store: Option<Arc<ArtifactStoreConfig>>,
    artifact_migration_plan: Option<Arc<ArtifactMigrationPlan>>,
    artifact_migration_plan_file: Option<Arc<ArtifactMigrationPlanFile>>,
    transaction_test_faults: Arc<Mutex<VecDeque<PostgresTransactionTestFault>>>,
    artifact_publication_test_fault: Arc<Mutex<Option<ArtifactPublicationTestFault>>>,
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
            .field("artifact_store_configured", &self.artifact_store.is_some())
            .field(
                "artifact_migration_plan_configured",
                &self.artifact_migration_plan.is_some(),
            )
            .field(
                "artifact_migration_plan_file_configured",
                &self.artifact_migration_plan_file.is_some(),
            )
            .field("trust_injected_time", &self.trust_injected_time)
            .field("audit_projection_enabled", &self.audit_projection_enabled)
            .field("quota_enforcement", &self.quota_enforcement)
            .field("quota_policy_configured", &self.quota_policy.is_some())
            .field("push_policy_configured", &self.push_policy.is_some())
            .field(
                "quota_reconciliation_plan_configured",
                &self.quota_reconciliation_plan.is_some(),
            )
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
                "artifact_publication_test_fault_enabled",
                &self
                    .artifact_publication_test_fault
                    .lock()
                    .is_ok_and(|fault| fault.is_some()),
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
            audit_projection_enabled: false,
            quota_enforcement: false,
            quota_policy: None,
            quota_reconciliation_plan: None,
            push_policy: None,
            max_tasks: 1024,
            artifact_store: None,
            artifact_migration_plan: None,
            artifact_migration_plan_file: None,
            transaction_test_faults: Arc::new(Mutex::new(VecDeque::new())),
            artifact_publication_test_fault: Arc::new(Mutex::new(None)),
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

    /// Bind strict artifact policy. Key material and the POSIX root are
    /// preflighted before any PostgreSQL connection is acquired.
    #[must_use]
    pub fn with_artifact_store(mut self, config: ArtifactStoreConfig) -> Self {
        self.artifact_store = Some(Arc::new(config));
        self
    }

    /// Bind the exact operator-approved inline migration. Startup still fails
    /// closed until this plan has been completed by the offline operator.
    #[must_use]
    pub fn with_artifact_migration_plan(mut self, plan: ArtifactMigrationPlan) -> Self {
        self.artifact_migration_plan = Some(Arc::new(plan));
        self
    }

    /// Bind the complete private plan file, including source schema and store
    /// identity, so startup can verify the exact completed journal.
    #[must_use]
    pub fn with_artifact_migration_plan_file(mut self, plan: ArtifactMigrationPlanFile) -> Self {
        self.artifact_migration_plan = Some(Arc::new(plan.plan().clone()));
        self.artifact_migration_plan_file = Some(Arc::new(plan));
        self
    }

    /// Require server-owned quota intent on every authorized quota-bearing mutation.
    #[must_use]
    pub fn with_quota_enforcement(mut self, enabled: bool) -> Self {
        self.quota_enforcement = enabled;
        self
    }

    /// Enable connection-scoped, starts-at-enable durable audit projection.
    #[must_use]
    pub fn with_audit_projection(mut self, enabled: bool) -> Self {
        self.audit_projection_enabled = enabled;
        self
    }

    /// Install the immutable startup quota snapshot used to validate intents.
    #[must_use]
    pub fn with_quota_policy(mut self, policy: Arc<crate::QuotaPolicy>) -> Self {
        self.quota_enforcement = true;
        self.quota_policy = Some(policy);
        self
    }

    /// Bind the exact callback policy before any PostgreSQL resource is acquired.
    #[must_use]
    pub fn with_push_policy(mut self, policy: crate::push::PushPolicy) -> Self {
        self.push_policy = Some(Arc::new(policy));
        self
    }

    /// Supply an audited, digest-bound, non-destructive lower-limit drain plan.
    #[must_use]
    pub fn with_quota_reconciliation_plan(mut self, plan: crate::QuotaReconciliationPlan) -> Self {
        self.quota_reconciliation_plan = Some(Arc::new(plan));
        self
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

    /// Installs one receiver-publication checkpoint fault. It is consumed when hit.
    #[doc(hidden)]
    #[must_use]
    pub fn with_artifact_publication_test_fault(
        mut self,
        fault: ArtifactPublicationTestFault,
    ) -> Self {
        self.artifact_publication_test_fault = Arc::new(Mutex::new(Some(fault)));
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
    #[error("quota policy reconciliation is required")]
    ReconciliationRequired,
    #[error("artifact restore is incomplete; gateway startup is refused")]
    ArtifactRestoreIncomplete,
    #[error("populated inline artifact migration is required")]
    ArtifactMigrationRequired,
    #[error("artifact migration plan does not match the source authority")]
    ArtifactMigrationPlanMismatch,
    #[error("artifact migration is fenced by another operator or active work")]
    ArtifactMigrationBusy,
    #[error("artifact migration source is corrupt or unsupported")]
    ArtifactMigrationInvalidSource,
    #[error("artifact restore target is not empty")]
    ArtifactRestoreTargetNotEmpty,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArtifactMigrationOutcome {
    pub migrated_artifacts: u64,
    pub rewritten_rows: u64,
    pub completed: bool,
    pub completion_seal: Option<String>,
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
    audit_projection_enabled: bool,
    quota_enforcement: bool,
    quota_policy: Option<Arc<crate::QuotaPolicy>>,
    callback_policy: Option<Arc<crate::CallbackPolicySnapshot>>,
    transaction_test_faults: Arc<Mutex<VecDeque<PostgresTransactionTestFault>>>,
    artifact_publication_test_fault: Arc<Mutex<Option<ArtifactPublicationTestFault>>>,
    transaction_attempts: Arc<AtomicUsize>,
    artifact_blob_reads: Arc<AtomicUsize>,
    receiver_renewal_test_probe: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    artifact_store: Option<Arc<PosixArtifactBlobStore>>,
    artifact_keyring: Option<Arc<ReloadingArtifactKeyring>>,
    artifact_runtime_limits: crate::ArtifactRuntimeLimits,
    telemetry: Option<crate::telemetry::TelemetryHandle>,
    _test_cleanup: Option<Arc<PostgresTestCleanup>>,
}

#[async_trait]
impl crate::ArtifactAuthority for PostgresTaskStore {
    fn artifact_capabilities(&self) -> crate::ArtifactCapabilities {
        let enabled = self.artifact_store.is_some();
        crate::ArtifactCapabilities {
            publication: enabled,
            promotion: enabled,
            resolution: enabled,
            retention_gc: enabled,
        }
    }

    fn artifact_runtime_limits(&self) -> crate::ArtifactRuntimeLimits {
        self.artifact_runtime_limits
    }

    async fn stage_artifact(
        &self,
        registration: crate::ArtifactStageRegistration,
        plaintext: Vec<u8>,
    ) -> Result<crate::ArtifactStageRegistration, A2AError> {
        let store = self.artifact_store.clone().ok_or_else(|| {
            A2AError::unsupported_operation("artifact publication is unsupported")
        })?;
        let staged =
            tokio::task::spawn_blocking(move || store.stage_registration(registration, &plaintext))
                .await
                .map_err(|_| A2AError::internal("artifact staging worker failed"))?
                .map_err(|_| A2AError::invalid_request("artifact staging failed"))?;
        crate::artifact_production_checkpoint("publication_stage_before_receiver_transaction");
        if let Some(telemetry) = &self.telemetry {
            telemetry.artifact_event(
                crate::telemetry::EventName::ArtifactStaged,
                "ok",
                "encrypted",
                "artifact_stage",
                Some(&staged.artifact_id),
                Some(&staged.task_id),
                Some(&staged.context_id),
                Some(&staged.dispatch_id),
            );
        }
        Ok(staged)
    }

    async fn register_artifact(
        &self,
        registration: &crate::ArtifactStageRegistration,
        now: i64,
    ) -> Result<(), A2AError> {
        if self.artifact_store.is_none() {
            return Err(A2AError::unsupported_operation(
                "artifact publication is unsupported",
            ));
        }
        let r = registration.clone();
        self.run_retryable_transaction(&r.tenant_scope.clone(), None, |store, tx| {
            let r = r.clone();
            Box::pin(async move {
                let fence = store.q("SELECT pg_advisory_xact_lock(hashtextextended($1,0))");
                tx.execute(&fence, &[&r.stage_locator]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact stage fence failed")))?;
                let claimed = store.q("SELECT EXISTS(SELECT 1 FROM __S__.artifact_orphan_candidates WHERE stage_locator=$1)");
                if tx.query_one(&claimed,&[&r.stage_locator]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact stage ownership lookup failed")))?.get::<_,bool>(0) {
                    return Err(A2AError::invalid_request("artifact stage is owned by orphan cleanup"));
                }
                let now = store.effective_now(tx, now).await?;
                if r.task_revision == 0 || r.policy_revision == 0 || r.created_at > r.retain_until || r.ciphertext_length < 16 {
                    return Err(A2AError::invalid_params("invalid artifact registration"));
                }
                let key = store.q("INSERT INTO __S__.artifact_key_generations(tenant_scope,encryption_domain,key_generation,state,created_at) VALUES($1,$2,$3,'active',$4) ON CONFLICT DO NOTHING");
                tx.execute(&key, &[&r.tenant_scope,&r.encryption_domain,&r.key_generation,&now]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact key registration failed")))?;
                let nonce = r.nonce.to_vec();
                let object = store.q("INSERT INTO __S__.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,reference_count,retain_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'staged',0,$13,$14) ON CONFLICT DO NOTHING");
                let object_inserted=tx.execute(&object,&[&r.tenant_scope,&r.owner_account_id,&r.object_id,&r.content_digest,&r.classification,&r.encryption_domain,&r.key_generation,&i64::try_from(r.plaintext_length).unwrap_or(i64::MAX),&i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX),&r.ciphertext_digest,&r.final_locator,&nonce,&r.retain_until,&r.created_at]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact object registration failed")))? == 1;
                let verify = store.q("SELECT owner_account_id,content_digest,classification,encryption_domain,plaintext_length FROM __S__.content_objects WHERE tenant_scope=$1 AND object_id=$2");
                let row=tx.query_one(&verify,&[&r.tenant_scope,&r.object_id]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact object verification failed")))?;
                if row.get::<_,String>(0)!=r.owner_account_id || row.get::<_,String>(1)!=r.content_digest || row.get::<_,String>(2)!=r.classification || row.get::<_,String>(3)!=r.encryption_domain || row.get::<_,i64>(4)!=i64::try_from(r.plaintext_length).unwrap_or(i64::MAX) { return Err(A2AError::invalid_request("artifact registration conflicts with immutable state")); }
                let manifest=store.q("INSERT INTO __S__.artifact_manifests(tenant_scope,artifact_id,manifest_digest,object_id,schema_version,canonical_json,owner_account_id,task_id,context_id,message_id,dispatch_id,media_type,plaintext_length,classification,encryption_domain,policy_id,policy_revision,policy_digest,created_at,retain_until) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT DO NOTHING");
                tx.execute(&manifest,&[&r.tenant_scope,&r.artifact_id,&r.manifest_digest,&r.object_id,&r.canonical_manifest_json,&r.owner_account_id,&r.task_id,&r.context_id,&r.message_id,&r.dispatch_id,&r.media_type,&i64::try_from(r.plaintext_length).unwrap_or(i64::MAX),&r.classification,&r.encryption_domain,&r.policy_id,&i64::try_from(r.policy_revision).unwrap_or(i64::MAX),&r.policy_digest,&r.created_at,&r.retain_until]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact manifest registration failed")))?;
                let chunk_sql=store.q("INSERT INTO __S__.artifact_chunks(tenant_scope,artifact_id,ordinal,byte_offset,plaintext_length,content_digest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING");
                for chunk in &r.chunks { tx.execute(&chunk_sql,&[&r.tenant_scope,&r.artifact_id,&i32::try_from(chunk.ordinal).unwrap_or(i32::MAX),&i64::try_from(chunk.byte_offset).unwrap_or(i64::MAX),&i64::try_from(chunk.plaintext_length).unwrap_or(i64::MAX),&chunk.content_digest]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact chunk registration failed")))?; }
                let provenance_sql=store.q("INSERT INTO __S__.provenance_edges(tenant_scope,child_artifact_id,ordinal,parent_artifact_id,relation) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING");
                for edge in &r.provenance { tx.execute(&provenance_sql,&[&r.tenant_scope,&r.artifact_id,&i32::try_from(edge.ordinal).unwrap_or(i32::MAX),&edge.parent_artifact_id,&edge.relation]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact provenance registration failed")))?; }
                let reference=store.q("INSERT INTO __S__.artifact_references(tenant_scope,reference_id,artifact_id,task_id,context_id,owner_account_id,task_revision,state,retain_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9) ON CONFLICT DO NOTHING RETURNING reference_id");
                let reference_inserted=tx.query_opt(&reference,&[&r.tenant_scope,&r.reference_id,&r.artifact_id,&r.task_id,&r.context_id,&r.owner_account_id,&i64::try_from(r.task_revision).unwrap_or(i64::MAX),&r.retain_until,&r.created_at]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact reference registration failed")))?.is_some();
                if reference_inserted { let increment=store.q("UPDATE __S__.content_objects o SET reference_count=o.reference_count+1 WHERE o.tenant_scope=$1 AND o.object_id=$2"); tx.execute(&increment,&[&r.tenant_scope,&r.object_id]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact reference accounting failed")))?; }
                if object_inserted { let upload=store.q("INSERT INTO __S__.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,created_at,updated_at) VALUES($1,$2,$3,$4,'committed',$5,$6,$7,$8,1,$9,$9) ON CONFLICT DO NOTHING");
                tx.execute(&upload,&[&r.tenant_scope,&r.upload_id,&r.artifact_id,&r.object_id,&r.stage_locator,&r.final_locator,&r.ciphertext_digest,&i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX),&now]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact upload registration failed")))?; }
                Ok(())
            })
        }).await?;
        crate::artifact_production_checkpoint("receiver_commit_before_physical_promotion");
        if let Some(telemetry) = &self.telemetry {
            telemetry.artifact_event(
                crate::telemetry::EventName::ArtifactRegistered,
                "ok",
                "committed",
                "artifact_register",
                Some(&registration.artifact_id),
                Some(&registration.task_id),
                Some(&registration.context_id),
                Some(&registration.dispatch_id),
            );
        }
        Ok(())
    }

    async fn claim_artifact_promotion(
        &self,
        lease_owner: &str,
        lease_duration: i64,
        batch: usize,
    ) -> Result<Vec<crate::ArtifactPromotionClaim>, A2AError> {
        if self.artifact_store.is_none() {
            return Err(A2AError::unsupported_operation(
                "artifact promotion is unsupported",
            ));
        }
        if lease_owner.is_empty()
            || !(10..=300_000).contains(&lease_duration)
            || !(1..=1000).contains(&batch)
        {
            return Err(A2AError::invalid_params("invalid artifact promotion lease"));
        }
        let token = content_digest(&rand::random::<[u8; 24]>());
        let batch = i32::try_from(batch)
            .map_err(|_| A2AError::invalid_params("invalid artifact promotion batch"))?;
        let client = self.connection().await?;
        let sql = self.q("SELECT * FROM __S__.claim_artifact_upload($1,$2,$3,$4)");
        client
            .query(&sql, &[&lease_owner, &token, &lease_duration, &batch])
            .await
            .map_err(|_| A2AError::internal("artifact promotion claim failed"))?
            .into_iter()
            .map(|row| {
                Ok(crate::ArtifactPromotionClaim {
                    tenant_scope: row.get(0),
                    upload_id: row.get(1),
                    artifact_id: row.get(2),
                    object_id: row.get(3),
                    stage_locator: row.get(4),
                    final_locator: row.get(5),
                    ciphertext_digest: row.get(6),
                    ciphertext_length: u64::try_from(row.get::<_, i64>(7))
                        .map_err(|_| A2AError::internal("artifact promotion row corrupt"))?,
                    lease_owner: lease_owner.to_owned(),
                    lease_token: row.get(8),
                    lease_epoch: u64::try_from(row.get::<_, i64>(9))
                        .map_err(|_| A2AError::internal("artifact promotion row corrupt"))?,
                    lease_until: row.get(10),
                })
            })
            .collect()
    }

    async fn commit_artifact_promotion(
        &self,
        claim: &crate::ArtifactPromotionClaim,
    ) -> Result<bool, A2AError> {
        let blobs = self
            .artifact_store
            .clone()
            .ok_or_else(|| A2AError::unsupported_operation("artifact promotion is unsupported"))?;
        let copy = claim.clone();
        tokio::task::spawn_blocking(move || blobs.promote_claim(&copy))
            .await
            .map_err(|_| A2AError::internal("artifact promoter worker failed"))?
            .map_err(|_| A2AError::internal("artifact promotion integrity failed"))?;
        crate::artifact_production_checkpoint("physical_promotion_before_upload_ack");
        let tenant = claim.tenant_scope.clone();
        let c = claim.clone();
        self.run_retryable_transaction(&tenant,None,|store,tx| { let c=c.clone(); Box::pin(async move {
            let epoch=i64::try_from(c.lease_epoch).unwrap_or(i64::MAX);
            let q=store.q("UPDATE __S__.upload_intents SET state='available',lease_token=NULL,lease_until=NULL,updated_at=__S__.db_millis() WHERE tenant_scope=$1 AND upload_id=$2 AND state='promoting' AND lease_token=$3 AND lease_epoch=$4 AND lease_until>__S__.db_millis()");
            if tx.execute(&q,&[&c.tenant_scope,&c.upload_id,&c.lease_token,&epoch]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact promotion commit failed")))? != 1 { return Ok(false); }
            let o=store.q("UPDATE __S__.content_objects SET state='available',available_at=__S__.db_millis() WHERE tenant_scope=$1 AND object_id=$2 AND state='staged'");
            tx.execute(&o,&[&c.tenant_scope,&c.object_id]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact availability commit failed")))?;
            Ok(true)
        })}).await
    }

    async fn fail_artifact_promotion(
        &self,
        claim: &crate::ArtifactPromotionClaim,
        error_digest: &str,
    ) -> Result<bool, A2AError> {
        let tenant = claim.tenant_scope.clone();
        let c = claim.clone();
        let error = error_digest.to_owned();
        self.run_retryable_transaction(&tenant,None,|store,tx| { let c=c.clone(); let error=error.clone(); Box::pin(async move {
            let q=store.q("UPDATE __S__.upload_intents SET state='failed',last_error_digest=$1,lease_token=NULL,lease_until=NULL,updated_at=__S__.db_millis() WHERE tenant_scope=$2 AND upload_id=$3 AND state='promoting' AND lease_token=$4 AND lease_epoch=$5");
            tx.execute(&q,&[&error,&c.tenant_scope,&c.upload_id,&c.lease_token,&i64::try_from(c.lease_epoch).unwrap_or(i64::MAX)]).await.map(|n|n==1).map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact promotion failure commit failed")))
        })}).await
    }

    async fn begin_artifact_resolution(
        &self,
        scope: &OwnedTaskScope,
        artifact_id: &str,
        task_id: Option<&str>,
        owner_digest: &str,
        lease_duration: i64,
        quota_intent: Option<&crate::QuotaIntent>,
        audit: AuthorizationAuditInput,
        requested_now: i64,
    ) -> Result<Option<crate::ArtifactReadLease>, A2AError> {
        if self.artifact_store.is_none() {
            return Err(A2AError::unsupported_operation(
                "artifact resolution is unsupported",
            ));
        }
        if !(10..=300_000).contains(&lease_duration)
            || audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
        {
            return Err(A2AError::invalid_params("invalid artifact read preflight"));
        }
        if self.quota_enforcement && quota_intent.is_none() {
            return Err(crate::quota::quota_authority_unavailable());
        }
        let scope = scope.clone();
        let tenant = scope.tenant_scope().to_owned();
        let account = scope.owner_account_id().to_owned();
        let artifact_id = artifact_id.to_owned();
        let task_id = task_id.map(str::to_owned);
        let owner_digest = owner_digest.to_owned();
        let request_intent = quota_intent.cloned();
        let denial_intent = request_intent.clone();
        let egress_denial_intent = Arc::new(Mutex::new(None::<crate::QuotaIntent>));
        let transaction_egress_intent = Arc::clone(&egress_denial_intent);
        let result = self.run_retryable_transaction(&tenant,Some(&account),|store,tx|{
            let scope=scope.clone();
            let artifact_id=artifact_id.clone();
            let task_id=task_id.clone();
            let owner_digest=owner_digest.clone();
            let request_intent=request_intent.clone();
            let transaction_egress_intent=Arc::clone(&transaction_egress_intent);
            let audit=audit.clone();
            Box::pin(async move{
                let now=store.effective_now(tx,requested_now).await?;
                if let Some(intent)=request_intent.as_ref() {
                    if intent.operation()!=crate::QuotaOperation::TaskGet {
                        return Err(A2AError::invalid_params("artifact request quota intent mismatch"));
                    }
                    store.apply_quota_intent(tx,intent,scope.tenant_scope(),scope.owner_account_id(),None,now,true,None).await?;
                }
                let own=matches!(scope.visibility(),VisibilityScope::Own);
                let q=store.q("SELECT m.owner_account_id,m.task_id,m.media_type,o.content_digest,m.manifest_digest,o.plaintext_length,o.classification,o.encryption_domain,o.ciphertext_digest,o.ciphertext_length,o.backend_locator,o.nonce,o.key_generation,m.canonical_json,o.state FROM __S__.artifact_references r JOIN __S__.artifact_manifests m USING(tenant_scope,artifact_id) JOIN __S__.content_objects o USING(tenant_scope,object_id) WHERE r.tenant_scope=$1 AND r.artifact_id=$2 AND r.state='active' AND o.state IN ('available','quarantined') AND o.retain_until>=$6 AND ($3::text IS NULL OR r.task_id=$3) AND (NOT $4 OR r.owner_account_id=$5) FOR UPDATE OF o");
                let row=tx.query_opt(&q,&[&scope.tenant_scope(),&artifact_id,&task_id.as_deref(),&own,&scope.owner_account_id(),&now]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact resolution lookup failed")))?;
                let Some(row)=row else {
                    store.insert_audit(tx,audit.decided(AuthorizationDecisionEffect::Deny,"not_found_or_forbidden",None)).await?;
                    return Ok(None);
                };
                let plaintext_i64:i64=row.get(5);
                let plaintext_length=u64::try_from(plaintext_i64).map_err(|_|A2AError::internal("artifact metadata corrupt"))?;
                if let (Some(policy),Some(intent))=(store.quota_policy.as_ref(),request_intent.as_ref()) {
                    let subject=crate::QuotaSubject::new(scope.tenant_scope(),scope.owner_account_id(),intent.principal_scope.to_string()).map_err(|_|crate::quota::quota_authority_unavailable())?;
                    let egress=policy.egress_intent(&subject,&intent.semantic_id,plaintext_length.max(1),1).map_err(|_|crate::quota::quota_authority_unavailable())?;
                    *transaction_egress_intent.lock().map_err(|_|crate::quota::quota_authority_unavailable())?=Some(egress.clone());
                    store.apply_quota_intent(tx,&egress,scope.tenant_scope(),scope.owner_account_id(),None,now,true,None).await?;
                }
                if row.get::<_, &str>(14) == "quarantined" {
                    store.insert_audit(tx,audit.decided(AuthorizationDecisionEffect::Deny,"artifact_quarantined",Some(row.get(1)))).await?;
                    return Err(A2AError::internal("artifact is quarantined"));
                }
                let lease_id=content_digest(&rand::random::<[u8;24]>());
                let token=content_digest(&rand::random::<[u8;24]>());
                let until=now.checked_add(lease_duration).ok_or_else(||A2AError::invalid_params("artifact lease overflow"))?;
                let ins=store.q("INSERT INTO __S__.artifact_read_leases VALUES($1,$2,$3,1,$4,$5,'active',$6,$7)");
                tx.execute(&ins,&[&scope.tenant_scope(),&lease_id,&artifact_id,&token,&owner_digest,&until,&now]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact read lease failed")))?;
                store.insert_audit(tx,audit.decided(AuthorizationDecisionEffect::Allow,"authorized_task_reference",Some(row.get(1)))).await?;
                let nonce:Vec<u8>=row.get(11);
                let nonce:[u8;12]=nonce.try_into().map_err(|_|A2AError::internal("artifact metadata corrupt"))?;
                Ok(Some(crate::ArtifactReadLease{tenant_scope:scope.tenant_scope().to_owned(),owner_account_id:row.get(0),task_id:row.get(1),artifact_id,media_type:row.get(2),content_digest:row.get(3),manifest_digest:row.get(4),plaintext_length,classification:row.get(6),encryption_domain:row.get(7),ciphertext_digest:row.get(8),ciphertext_length:u64::try_from(row.get::<_,i64>(9)).map_err(|_|A2AError::internal("artifact metadata corrupt"))?,backend_locator:row.get(10),nonce,key_generation:row.get(12),canonical_manifest_json:row.get(13),lease_id,lease_token:token,lease_epoch:1,lease_until:until}))
            })
        }).await;
        let egress_denial_intent = egress_denial_intent
            .lock()
            .map_err(|_| crate::quota::quota_authority_unavailable())?
            .clone();
        let lease = self
            .finalize_quota_result(
                egress_denial_intent.as_ref().or(denial_intent.as_ref()),
                requested_now,
                result,
            )
            .await?;
        if lease.is_some() {
            crate::artifact_production_checkpoint("resolver_read_lease_before_blob_verify");
        }
        Ok(lease)
    }

    async fn read_artifact_resolution(
        &self,
        r: &crate::ArtifactReadLease,
    ) -> Result<Vec<u8>, A2AError> {
        self.artifact_blob_reads.fetch_add(1, Ordering::SeqCst);
        let blobs = self
            .artifact_store
            .clone()
            .ok_or_else(|| A2AError::unsupported_operation("artifact resolution is unsupported"))?;
        let lease = r.clone();
        let result = tokio::task::spawn_blocking(move || blobs.read_resolution(&lease))
            .await
            .map_err(|_| A2AError::internal("artifact resolver worker failed"))?;
        if let Ok(bytes) = result {
            Ok(bytes)
        } else {
            let tenant = r.tenant_scope.clone();
            let artifact_id = r.artifact_id.clone();
            let detection_digest = content_digest(
                format!(
                    "smesh-artifact-corruption/v1\0{}\0{}\0{}",
                    tenant, artifact_id, r.ciphertext_digest
                )
                .as_bytes(),
            );
            let audit_id = format!("corruption-{}", &detection_digest[7..39]);
            self.run_retryable_transaction(&tenant.clone(), None, |store, tx| {
                    let tenant = tenant.clone();
                    let artifact_id = artifact_id.clone();
                    let detection_digest = detection_digest.clone();
                    let audit_id = audit_id.clone();
                    Box::pin(async move {
                        let sql = store.q("WITH target AS (SELECT object_id FROM __S__.artifact_manifests WHERE tenant_scope=$1 AND artifact_id=$2), quarantined AS (UPDATE __S__.content_objects o SET state='quarantined' FROM target t WHERE o.tenant_scope=$1 AND o.object_id=t.object_id AND o.state<>'deleted' RETURNING o.object_id) INSERT INTO __S__.artifact_corruption_audits(tenant_scope,audit_id,object_id,artifact_id,detection_digest,detected_at) SELECT $1,$3,q.object_id,$2,$4,__S__.db_millis() FROM quarantined q ON CONFLICT DO NOTHING");
                        tx.execute(&sql, &[&tenant, &artifact_id, &audit_id, &detection_digest])
                            .await
                            .map_err(|e| Self::transaction_body_error(&e, A2AError::internal("artifact corruption quarantine failed")))?;
                        Ok(())
                    })
            }).await?;
            if let Some(telemetry) = &self.telemetry {
                telemetry.artifact_event(
                    crate::telemetry::EventName::ArtifactCorruptionDetected,
                    "failed",
                    "quarantined",
                    "artifact_resolve",
                    Some(&r.artifact_id),
                    Some(&r.task_id),
                    None,
                    None,
                );
            }
            Err(A2AError::internal("artifact integrity verification failed"))
        }
    }
    async fn finish_artifact_resolution(
        &self,
        r: &crate::ArtifactReadLease,
        _: u64,
        _: bool,
    ) -> Result<bool, A2AError> {
        let tenant = r.tenant_scope.clone();
        let r = r.clone();
        let committed = self.run_retryable_transaction(&tenant,None,|store,tx|{let r=r.clone();Box::pin(async move{let q=store.q("UPDATE __S__.artifact_read_leases SET state='released' WHERE tenant_scope=$1 AND lease_id=$2 AND lease_token=$3 AND lease_epoch=$4 AND state IN ('active','released')");tx.execute(&q,&[&r.tenant_scope,&r.lease_id,&r.lease_token,&i64::try_from(r.lease_epoch).unwrap_or(i64::MAX)]).await.map(|n|n==1).map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact lease finish failed")))})}).await?;
        if committed && let Some(telemetry) = &self.telemetry {
            telemetry.artifact_event(
                crate::telemetry::EventName::ArtifactResolved,
                "ok",
                "integrity_verified",
                "artifact_resolve",
                Some(&r.artifact_id),
                Some(&r.task_id),
                None,
                None,
            );
        }
        Ok(committed)
    }
    async fn place_artifact_hold(
        &self,
        h: &crate::ArtifactHold,
        _now: i64,
    ) -> Result<(), A2AError> {
        let tenant = h.tenant_scope.clone();
        let h = h.clone();
        self.run_retryable_transaction(&tenant,None,|store,tx|{let h=h.clone();Box::pin(async move{
            let lock=store.q("SELECT o.tombstone_generation FROM __S__.artifact_manifests m JOIN __S__.content_objects o USING(tenant_scope,object_id) WHERE m.tenant_scope=$1 AND m.artifact_id=$2 AND o.state='available' AND o.retain_until>=__S__.db_millis() FOR UPDATE OF o");
            if tx.query_opt(&lock,&[&h.tenant_scope,&h.artifact_id]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact hold fence failed")))?.is_none(){return Err(A2AError::invalid_params("artifact hold object unavailable"));}
            let q=store.q("INSERT INTO __S__.artifact_retention_holds VALUES($1,$2,$3,$4,$5,'active',__S__.db_millis(),$6,NULL)");
            tx.execute(&q,&[&h.tenant_scope,&h.hold_id,&h.artifact_id,&h.actor_digest,&h.reason_digest,&h.expires_at]).await.map(|_|()).map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact hold failed")))
        })}).await
    }
    async fn release_artifact_hold(
        &self,
        h: &crate::ArtifactHold,
        now: i64,
    ) -> Result<bool, A2AError> {
        let tenant = h.tenant_scope.clone();
        let h = h.clone();
        self.run_retryable_transaction(&tenant,None,|store,tx|{let h=h.clone();Box::pin(async move{let q=store.q("UPDATE __S__.artifact_retention_holds SET state='released',released_at=$1 WHERE tenant_scope=$2 AND hold_id=$3 AND artifact_id=$4 AND state='active'");tx.execute(&q,&[&now,&h.tenant_scope,&h.hold_id,&h.artifact_id]).await.map(|n|n==1).map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact hold release failed")))})}).await
    }
    async fn release_artifact_reference(
        &self,
        t: &str,
        reference: &str,
        owner: &str,
        task: &str,
        artifact: &str,
        now: i64,
    ) -> Result<bool, A2AError> {
        let tenant = t.to_owned();
        let reference = reference.to_owned();
        let owner = owner.to_owned();
        let task = task.to_owned();
        let artifact = artifact.to_owned();
        self.run_retryable_transaction(&tenant.clone(),None,|store,tx|{let tenant=tenant.clone();let reference=reference.clone();let owner=owner.clone();let task=task.clone();let artifact=artifact.clone();Box::pin(async move{let q=store.q("WITH released AS (UPDATE __S__.artifact_references SET state='released',released_at=$1 WHERE tenant_scope=$2 AND reference_id=$3 AND owner_account_id=$4 AND task_id=$5 AND artifact_id=$6 AND state='active' RETURNING tenant_scope,artifact_id), changed AS (UPDATE __S__.content_objects o SET reference_count=o.reference_count-1 FROM __S__.artifact_manifests m JOIN released r USING(tenant_scope,artifact_id) WHERE o.tenant_scope=m.tenant_scope AND o.object_id=m.object_id AND o.reference_count>0 RETURNING o.object_id) SELECT count(*)::bigint FROM released");let row=tx.query_one(&q,&[&now,&tenant,&reference,&owner,&task,&artifact]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact reference release failed")))?;Ok(row.get::<_,i64>(0)==1)})}).await
    }
    async fn claim_artifact_gc(
        &self,
        lease_owner: &str,
        lease_duration: i64,
        batch: usize,
    ) -> Result<Vec<crate::ArtifactGcClaim>, A2AError> {
        if self.artifact_store.is_none() {
            return Err(A2AError::unsupported_operation(
                "artifact gc is unsupported",
            ));
        }
        if lease_owner.is_empty()
            || !(10..=300_000).contains(&lease_duration)
            || !(1..=1000).contains(&batch)
        {
            return Err(A2AError::invalid_params("invalid artifact gc lease"));
        }
        let token = content_digest(&rand::random::<[u8; 24]>());
        let batch = i32::try_from(batch)
            .map_err(|_| A2AError::invalid_params("invalid artifact gc batch"))?;
        let client = self.connection().await?;
        let sql = self.q("SELECT * FROM __S__.claim_artifact_gc($1,$2,$3,$4)");
        client
            .query(&sql, &[&lease_owner, &token, &lease_duration, &batch])
            .await
            .map_err(|_| A2AError::internal("artifact gc claim failed"))?
            .into_iter()
            .map(|row| {
                Ok(crate::ArtifactGcClaim {
                    tenant_scope: row.get(0),
                    job_id: row.get(1),
                    object_id: row.get(2),
                    backend_locator: row.get(3),
                    tombstone_generation: u64::try_from(row.get::<_, i64>(4))
                        .map_err(|_| A2AError::internal("artifact gc row corrupt"))?,
                    lease_owner: lease_owner.to_owned(),
                    lease_token: row.get(5),
                    lease_epoch: u64::try_from(row.get::<_, i64>(6))
                        .map_err(|_| A2AError::internal("artifact gc row corrupt"))?,
                })
            })
            .collect()
    }
    async fn commit_artifact_gc(
        &self,
        claim: &crate::ArtifactGcClaim,
        deletion_receipt_digest: &str,
    ) -> Result<bool, A2AError> {
        if !deletion_receipt_digest.starts_with("sha256:") {
            return Err(A2AError::invalid_params(
                "invalid artifact deletion receipt",
            ));
        }
        let blobs = self
            .artifact_store
            .clone()
            .ok_or_else(|| A2AError::unsupported_operation("artifact gc is unsupported"))?;
        let locator = claim.backend_locator.clone();
        tokio::task::spawn_blocking(move || blobs.delete_locator(&locator))
            .await
            .map_err(|_| A2AError::internal("artifact gc worker failed"))?
            .map_err(|_| A2AError::internal("artifact blob deletion failed"))?;
        crate::artifact_production_checkpoint("gc_physical_unlink_before_finalize");
        let tenant = claim.tenant_scope.clone();
        let c = claim.clone();
        let receipt = deletion_receipt_digest.to_owned();
        let committed = self.run_retryable_transaction(&tenant,None,|store,tx| { let c=c.clone(); let receipt=receipt.clone(); Box::pin(async move {
            let epoch=i64::try_from(c.lease_epoch).unwrap_or(i64::MAX); let generation=i64::try_from(c.tombstone_generation).unwrap_or(i64::MAX);
            let job=store.q("UPDATE __S__.artifact_gc_jobs SET state='complete',lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE tenant_scope=$1 AND job_id=$2 AND object_id=$3 AND tombstone_generation=$4 AND state='leased' AND lease_owner=$5 AND lease_token=$6 AND lease_epoch=$7 AND lease_until>__S__.db_millis()");
            if tx.execute(&job,&[&c.tenant_scope,&c.job_id,&c.object_id,&generation,&c.lease_owner,&c.lease_token,&epoch]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact gc finalize failed")))? != 1 { return Ok(false); }
            let object=store.q("UPDATE __S__.content_objects SET state='deleted' WHERE tenant_scope=$1 AND object_id=$2 AND tombstone_generation=$3 AND state='deleting'");
            if tx.execute(&object,&[&c.tenant_scope,&c.object_id,&generation]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact gc object finalize failed")))? != 1 { return Err(A2AError::internal("artifact gc fence lost")); }
            let tombstone=store.q("INSERT INTO __S__.artifact_tombstones(tenant_scope,object_id,tombstone_generation,reason_digest,locator_digest,deletion_receipt_digest,tombstoned_at,deleted_at) VALUES($1,$2,$3,$4,$5,$6,__S__.db_millis(),__S__.db_millis())");
            tx.execute(&tombstone,&[&c.tenant_scope,&c.object_id,&generation,&content_digest(b"retention-expired"),&content_digest(c.backend_locator.as_bytes()),&receipt]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact tombstone append failed")))?;
            Ok(true)
        })}).await?;
        crate::artifact_production_checkpoint("gc_finalize_before_worker_ack");
        Ok(committed)
    }
    async fn fail_artifact_gc(
        &self,
        claim: &crate::ArtifactGcClaim,
        error_digest: &str,
    ) -> Result<bool, A2AError> {
        let tenant = claim.tenant_scope.clone();
        let c = claim.clone();
        let error = error_digest.to_owned();
        self.run_retryable_transaction(&tenant,None,|store,tx| { let c=c.clone(); let error=error.clone(); Box::pin(async move {
            let epoch=i64::try_from(c.lease_epoch).unwrap_or(i64::MAX); let generation=i64::try_from(c.tombstone_generation).unwrap_or(i64::MAX);
            let job=store.q("UPDATE __S__.artifact_gc_jobs SET state='pending',available_at=__S__.db_millis(),lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_digest=$1 WHERE tenant_scope=$2 AND job_id=$3 AND object_id=$4 AND tombstone_generation=$5 AND state='leased' AND lease_owner=$6 AND lease_token=$7 AND lease_epoch=$8");
            if tx.execute(&job,&[&error,&c.tenant_scope,&c.job_id,&c.object_id,&generation,&c.lease_owner,&c.lease_token,&epoch]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact gc failure commit failed")))? != 1 { return Ok(false); }
            let object=store.q("UPDATE __S__.content_objects SET state='tombstoned' WHERE tenant_scope=$1 AND object_id=$2 AND tombstone_generation=$3 AND state='deleting'");
            tx.execute(&object,&[&c.tenant_scope,&c.object_id,&generation]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact gc retry failed")))?;
            Ok(true)
        })}).await
    }

    async fn acquire_artifact_backup_lease(
        &self,
        tenant_scope: &str,
        object_id: &str,
        lease_owner: &str,
        lease_duration: i64,
    ) -> Result<crate::ArtifactBackupLease, A2AError> {
        if self.artifact_store.is_none()
            || tenant_scope.is_empty()
            || object_id.is_empty()
            || lease_owner.is_empty()
            || !(10..=86_400_000).contains(&lease_duration)
        {
            return Err(A2AError::invalid_params("invalid artifact backup lease"));
        }
        let tenant = tenant_scope.to_owned();
        let object = object_id.to_owned();
        let owner = lease_owner.to_owned();
        let lease_id = format!("backup-{}", content_digest(&rand::random::<[u8; 24]>()));
        let token = content_digest(&rand::random::<[u8; 24]>());
        self.run_retryable_transaction(&tenant.clone(), None, |store, tx| {
            let tenant = tenant.clone(); let object = object.clone(); let owner = owner.clone();
            let lease_id = lease_id.clone(); let token = token.clone();
            Box::pin(async move {
                let lock = store.q("SELECT o.tombstone_generation FROM __S__.content_objects o WHERE o.tenant_scope=$1 AND o.object_id=$2 AND o.state='available' AND o.retain_until>=__S__.db_millis() FOR UPDATE OF o");
                if tx.query_opt(&lock,&[&tenant,&object]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact backup fence failed")))?.is_none(){return Err(A2AError::invalid_params("artifact backup object unavailable"));}
                let q = store.q("INSERT INTO __S__.artifact_backup_leases(tenant_scope,lease_id,object_id,lease_owner,lease_epoch,lease_token,state,lease_until,created_at) VALUES($1,$2,$3,$4,1,$5,'active',__S__.db_millis()+$6,__S__.db_millis()) RETURNING lease_until");
                let row = tx.query_opt(&q, &[&tenant,&lease_id,&object,&owner,&token,&lease_duration]).await
                    .map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact backup lease acquire failed")))?
                    .ok_or_else(|| A2AError::invalid_params("artifact backup object unavailable"))?;
                Ok(crate::ArtifactBackupLease { tenant_scope: tenant, object_id: object, lease_id, lease_owner: owner, lease_token: token, lease_epoch: 1, lease_until: row.get(0) })
            })
        }).await
    }

    async fn renew_artifact_backup_lease(
        &self,
        lease: &crate::ArtifactBackupLease,
        lease_duration: i64,
    ) -> Result<Option<crate::ArtifactBackupLease>, A2AError> {
        if !(10..=86_400_000).contains(&lease_duration) {
            return Err(A2AError::invalid_params("invalid artifact backup renewal"));
        }
        let tenant = lease.tenant_scope.clone();
        let prior = lease.clone();
        let next_token = content_digest(&rand::random::<[u8; 24]>());
        self.run_retryable_transaction(&tenant, None, |store, tx| {
            let prior=prior.clone(); let next_token=next_token.clone();
            Box::pin(async move {
                let q=store.q("UPDATE __S__.artifact_backup_leases SET lease_epoch=lease_epoch+1,lease_token=$1,lease_until=__S__.db_millis()+$2 WHERE tenant_scope=$3 AND lease_id=$4 AND object_id=$5 AND lease_owner=$6 AND lease_token=$7 AND lease_epoch=$8 AND state='active' AND lease_until>__S__.db_millis() RETURNING lease_epoch,lease_until");
                let epoch=i64::try_from(prior.lease_epoch).unwrap_or(i64::MAX);
                let row=tx.query_opt(&q,&[&next_token,&lease_duration,&prior.tenant_scope,&prior.lease_id,&prior.object_id,&prior.lease_owner,&prior.lease_token,&epoch]).await
                    .map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact backup lease renew failed")))?;
                row.map(|row| Ok(crate::ArtifactBackupLease { lease_token: next_token, lease_epoch:u64::try_from(row.get::<_,i64>(0)).map_err(|_|A2AError::internal("artifact backup lease corrupt"))?, lease_until:row.get(1), ..prior })).transpose()
            })
        }).await
    }

    async fn release_artifact_backup_lease(
        &self,
        lease: &crate::ArtifactBackupLease,
    ) -> Result<bool, A2AError> {
        let tenant = lease.tenant_scope.clone();
        let lease = lease.clone();
        self.run_retryable_transaction(&tenant,None,|store,tx| { let lease=lease.clone(); Box::pin(async move {
            let q=store.q("UPDATE __S__.artifact_backup_leases SET state='released' WHERE tenant_scope=$1 AND lease_id=$2 AND object_id=$3 AND lease_owner=$4 AND lease_token=$5 AND lease_epoch=$6 AND state='active'");
            tx.execute(&q,&[&lease.tenant_scope,&lease.lease_id,&lease.object_id,&lease.lease_owner,&lease.lease_token,&i64::try_from(lease.lease_epoch).unwrap_or(i64::MAX)]).await
                .map(|n|n==1).map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact backup lease release failed")))
        })}).await
    }

    async fn scan_artifact_stage_orphans(
        &self,
        horizon_millis: i64,
        batch: usize,
    ) -> Result<crate::StageOrphanCleanup, A2AError> {
        if !(1..=86_400_000).contains(&horizon_millis) || !(1..=1000).contains(&batch) {
            return Err(A2AError::invalid_params("invalid artifact orphan scan"));
        }
        let blobs = self.artifact_store.clone().ok_or_else(|| {
            A2AError::unsupported_operation("artifact orphan scanning is unsupported")
        })?;
        let mut client = self.connection().await?;
        let now: i64 = client
            .query_one(&self.q("SELECT __S__.db_millis()"), &[])
            .await
            .map_err(|_| A2AError::internal("artifact orphan clock failed"))?
            .get(0);
        let cutoff = std::time::UNIX_EPOCH
            .checked_add(Duration::from_millis(
                u64::try_from(now.saturating_sub(horizon_millis)).unwrap_or(0),
            ))
            .ok_or_else(|| A2AError::internal("artifact orphan horizon failed"))?;
        let mut candidates: Vec<(String, u64)> = client
            .query(
                &self.q("SELECT stage_locator,ciphertext_length FROM __S__.artifact_orphan_candidates WHERE state='claimed' AND claim_until<=__S__.db_millis() ORDER BY claim_until,stage_locator LIMIT $1"),
                &[&i64::try_from(batch).unwrap_or(i64::MAX)],
            )
            .await
            .map_err(|_| A2AError::internal("artifact orphan recovery failed"))?
            .into_iter()
            .filter_map(|row| {
                u64::try_from(row.get::<_, i64>(1))
                    .ok()
                    .map(|bytes| (row.get(0), bytes))
            })
            .collect();
        if candidates.len() < batch {
            let remaining = batch - candidates.len();
            candidates.extend(
                blobs
                    .stage_orphan_candidates(cutoff, remaining)
                    .map_err(|_| A2AError::internal("artifact orphan enumeration failed"))?,
            );
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        candidates.dedup_by(|left, right| left.0 == right.0);
        let mut result = crate::StageOrphanCleanup::default();
        for (locator, bytes) in candidates {
            let token = content_digest(&rand::random::<[u8; 24]>());
            // Claim ownership durably while holding the same locator fence used
            // by registration.  The lease permits takeover after process death.
            // ALLOWLIST: artifact orphan claim persists before unlink.
            let tx = client
                .transaction()
                .await
                .map_err(|_| A2AError::internal("artifact orphan claim transaction failed"))?;
            let fence = self.q("SELECT pg_advisory_xact_lock(hashtextextended($1,0)),__S__.artifact_stage_locator_live($1)");
            let live: bool = tx
                .query_one(&fence, &[&locator])
                .await
                .map_err(|_| A2AError::internal("artifact orphan fence failed"))?
                .get(1);
            if live {
                tx.rollback()
                    .await
                    .map_err(|_| A2AError::internal("artifact orphan rollback failed"))?;
                continue;
            }
            let claim = self.q("INSERT INTO __S__.artifact_orphan_candidates(stage_locator,locator_digest,ciphertext_length,state,claim_token,claim_generation,claim_until,claimed_at) VALUES($1,$2,$3,'claimed',$4,1,__S__.db_millis()+30000,__S__.db_millis()) ON CONFLICT(stage_locator) DO UPDATE SET claim_token=EXCLUDED.claim_token,claim_generation=__S__.artifact_orphan_candidates.claim_generation+1,claim_until=EXCLUDED.claim_until,claimed_at=EXCLUDED.claimed_at WHERE __S__.artifact_orphan_candidates.state='claimed' AND __S__.artifact_orphan_candidates.claim_until<=__S__.db_millis() RETURNING claim_generation");
            let generation = tx
                .query_opt(
                    &claim,
                    &[
                        &locator,
                        &content_digest(locator.as_bytes()),
                        &i64::try_from(bytes).unwrap_or(i64::MAX),
                        &token,
                    ],
                )
                .await
                .map_err(|_| A2AError::internal("artifact orphan claim failed"))?
                .map(|row| row.get::<_, i64>(0));
            let Some(generation) = generation else {
                tx.rollback()
                    .await
                    .map_err(|_| A2AError::internal("artifact orphan rollback failed"))?;
                continue;
            };
            tx.commit()
                .await
                .map_err(|_| A2AError::internal("artifact orphan claim commit failed"))?;

            // Missing means a prior owner crashed after unlink.  It is still a
            // successful cleanup and must be finalized/refunded exactly once.
            let _ = blobs
                .delete_stage_orphan(&locator)
                .map_err(|_| A2AError::internal("artifact orphan deletion failed"))?;

            // ALLOWLIST: artifact orphan finalize fences exact ownership.
            let tx = client
                .transaction()
                .await
                .map_err(|_| A2AError::internal("artifact orphan finalize transaction failed"))?;
            tx.execute(
                &self.q("SELECT pg_advisory_xact_lock(hashtextextended($1,0))"),
                &[&locator],
            )
            .await
            .map_err(|_| A2AError::internal("artifact orphan finalize fence failed"))?;
            let owned = self.q("SELECT ciphertext_length FROM __S__.artifact_orphan_candidates WHERE stage_locator=$1 AND state='claimed' AND claim_token=$2 AND claim_generation=$3 FOR UPDATE");
            let Some(row) = tx
                .query_opt(&owned, &[&locator, &token, &generation])
                .await
                .map_err(|_| A2AError::internal("artifact orphan ownership failed"))?
            else {
                tx.rollback()
                    .await
                    .map_err(|_| A2AError::internal("artifact orphan rollback failed"))?;
                continue;
            };
            let durable_bytes: i64 = row.get(0);
            let audit = self.q("INSERT INTO __S__.artifact_orphan_audits(locator_digest,refunded_bytes,deleted_at) VALUES($1,$2,__S__.db_millis()) ON CONFLICT DO NOTHING");
            let inserted = tx
                .execute(
                    &audit,
                    &[&content_digest(locator.as_bytes()), &durable_bytes],
                )
                .await
                .map_err(|_| A2AError::internal("artifact orphan audit failed"))?
                == 1;
            let finalized = self.q("UPDATE __S__.artifact_orphan_candidates SET state='finalized',finalized_at=__S__.db_millis(),claim_until=__S__.db_millis() WHERE stage_locator=$1 AND state='claimed' AND claim_token=$2 AND claim_generation=$3");
            if tx
                .execute(&finalized, &[&locator, &token, &generation])
                .await
                .map_err(|_| A2AError::internal("artifact orphan finalize failed"))?
                != 1
            {
                return Err(A2AError::internal("artifact orphan ownership lost"));
            }
            tx.commit()
                .await
                .map_err(|_| A2AError::internal("artifact orphan finalize commit failed"))?;
            if inserted {
                result.deleted += 1;
                result.refunded_bytes = result
                    .refunded_bytes
                    .saturating_add(u64::try_from(durable_bytes).unwrap_or(0));
            }
        }
        Ok(result)
    }
}

impl PostgresTaskStore {
    /// Arms one named terminal-enqueue fault; consumed only at the exact checkpoint.
    #[doc(hidden)]
    pub fn set_callback_terminal_test_fault(
        &self,
        fault: crate::CallbackTerminalTestFault,
    ) -> Result<(), A2AError> {
        if !self.trust_injected_time {
            return Err(A2AError::invalid_request(
                "callback terminal fault injection is disabled",
            ));
        }
        *POSTGRES_CALLBACK_TERMINAL_TEST_FAULT
            .lock()
            .map_err(|_| A2AError::internal("callback terminal fault lock failed"))? = Some(fault);
        Ok(())
    }

    #[must_use]
    pub fn with_telemetry(mut self, telemetry: Option<crate::telemetry::TelemetryHandle>) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Verify and restore an encrypted artifact root against offline restored PostgreSQL metadata.
    pub async fn restore_artifacts(
        config: PostgresStoreConfig,
        plan: &crate::ArtifactRestorePlanFile,
    ) -> Result<crate::ArtifactRestoreOutcome, PostgresStoreError> {
        if config.schema.as_ref() != plan.target_schema() {
            return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
        }
        let artifact = config
            .artifact_store
            .as_ref()
            .ok_or(PostgresStoreError::InvalidConfig)?;
        if artifact.root() != plan.target_root() {
            return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
        }
        let keyring = Arc::new(
            ReloadingArtifactKeyring::open(artifact.keyring_path())
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let target = Arc::new(
            PosixArtifactBlobStore::open(artifact.root(), keyring.clone())
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let source = Arc::new(
            PosixArtifactBlobStore::open(plan.source_root(), keyring)
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let insecure = validate_tls(&config)?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        if insecure {
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_restore_executor::execute(
                &mut client,
                &config.schema,
                source,
                target,
                plan,
                config.audit_projection_enabled,
            )
            .await;
            let _ = client
                .query_one(
                    "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                    &[&format!(
                        "smesh-artifact-restore:{}:{}",
                        config.schema,
                        plan.restore_id()
                    )],
                )
                .await;
            drop(client);
            driver.abort();
            result
        } else {
            let connector = native_tls_connector()?;
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(connector))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_restore_executor::execute(
                &mut client,
                &config.schema,
                source,
                target,
                plan,
                config.audit_projection_enabled,
            )
            .await;
            let _ = client
                .query_one(
                    "SELECT pg_advisory_unlock(hashtextextended($1,0))",
                    &[&format!(
                        "smesh-artifact-restore:{}:{}",
                        config.schema,
                        plan.restore_id()
                    )],
                )
                .await;
            drop(client);
            driver.abort();
            result
        }
    }

    /// Atomically activate a validated keyring generation and join its fenced re-encryption work.
    pub async fn rotate_artifact_key(
        config: PostgresStoreConfig,
        plan: &crate::ArtifactKeyRotationPlanFile,
        lease_owner: &str,
    ) -> Result<crate::ArtifactKeyRotationOutcome, PostgresStoreError> {
        if config.schema.as_ref() != plan.source_schema() {
            return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
        }
        let artifact = config
            .artifact_store
            .as_ref()
            .ok_or(PostgresStoreError::InvalidConfig)?;
        let keyring = Arc::new(
            ReloadingArtifactKeyring::open(artifact.keyring_path())
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        if keyring.active_generation() != plan.plan().new_generation()
            || keyring.key(plan.plan().old_generation()).is_err()
        {
            return Err(PostgresStoreError::InvalidConfig);
        }
        let blobs = Arc::new(
            PosixArtifactBlobStore::open(artifact.root(), keyring.clone())
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let insecure = validate_tls(&config)?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        if insecure {
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_reencryption_executor::execute(
                &mut client,
                &config.schema,
                blobs,
                keyring,
                plan,
                lease_owner,
            )
            .await;
            drop(client);
            driver.abort();
            result
        } else {
            let connector = native_tls_connector()?;
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(connector))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_reencryption_executor::execute(
                &mut client,
                &config.schema,
                blobs,
                keyring,
                plan,
                lease_owner,
            )
            .await;
            drop(client);
            driver.abort();
            result
        }
    }

    /// Execute a coherent verified physical artifact backup without starting a runtime.
    pub async fn backup_artifacts(
        config: PostgresStoreConfig,
        plan: &crate::ArtifactBackupPlanFile,
        lease_owner: &str,
    ) -> Result<crate::ArtifactBackupOutcome, PostgresStoreError> {
        if config.schema.as_ref() != plan.source_schema() {
            return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
        }
        let artifact = config
            .artifact_store
            .as_ref()
            .ok_or(PostgresStoreError::InvalidConfig)?;
        let keyring = Arc::new(
            ReloadingArtifactKeyring::open(artifact.keyring_path())
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let blobs = Arc::new(
            PosixArtifactBlobStore::open(artifact.root(), keyring)
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let insecure = validate_tls(&config)?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        if insecure {
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_backup_executor::execute(
                &mut client,
                &config.schema,
                blobs,
                plan,
                lease_owner,
            )
            .await;
            drop(client);
            driver.abort();
            result
        } else {
            let connector = native_tls_connector()?;
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(connector))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_backup_executor::execute(
                &mut client,
                &config.schema,
                blobs,
                plan,
                lease_owner,
            )
            .await;
            drop(client);
            driver.abort();
            result
        }
    }

    /// Execute the explicit populated inline-artifact migration without starting
    /// a gateway runtime. The plan and artifact keyring are preflighted before
    /// the database connection; the executor owns only a fenced operator lease.
    pub async fn migrate_inline_artifacts(
        config: PostgresStoreConfig,
        plan: &crate::ArtifactMigrationPlanFile,
        lease_owner: &str,
    ) -> Result<ArtifactMigrationOutcome, PostgresStoreError> {
        if config.schema.as_ref() != plan.source_schema() {
            return Err(PostgresStoreError::ArtifactMigrationPlanMismatch);
        }
        let artifact = config
            .artifact_store
            .as_ref()
            .ok_or(PostgresStoreError::InvalidConfig)?;
        let keyring = Arc::new(
            ReloadingArtifactKeyring::open(artifact.keyring_path())
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let blobs = Arc::new(
            PosixArtifactBlobStore::open(artifact.root(), keyring)
                .map_err(|_| PostgresStoreError::InvalidConfig)?,
        );
        let insecure = validate_tls(&config)?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        if insecure {
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (cursor_key, _) = validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_migration_executor::execute(
                &mut client,
                &config.schema,
                blobs,
                plan,
                lease_owner,
                &cursor_key,
            )
            .await;
            drop(client);
            driver.abort();
            result
        } else {
            let connector = native_tls_connector()?;
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(connector))
                    .await
                    .map_err(|_| PostgresStoreError::Unavailable)?
                    .map_err(|_| PostgresStoreError::Unavailable)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (cursor_key, _) = validate_catalog(&mut client, &config.schema).await?;
            let result = crate::artifact_migration_executor::execute(
                &mut client,
                &config.schema,
                blobs,
                plan,
                lease_owner,
                &cursor_key,
            )
            .await;
            drop(client);
            driver.abort();
            result
        }
    }

    pub async fn open(config: PostgresStoreConfig) -> Result<Self, PostgresStoreError> {
        if config.trust_injected_time && !config.test_only_insecure_loopback {
            return Err(PostgresStoreError::InvalidConfig);
        }
        let artifact_runtime_limits = config.artifact_store.as_ref().map_or_else(
            crate::ArtifactRuntimeLimits::default,
            |artifact| crate::ArtifactRuntimeLimits {
                max_artifact_bytes: artifact.max_artifact_bytes(),
                retention_millis: artifact.retention_millis(),
                read_lease_millis: artifact.read_lease_millis(),
                worker_batch: artifact.worker_batch() as usize,
            },
        );
        let (artifact_store, artifact_keyring) =
            if let Some(artifact) = config.artifact_store.as_ref() {
                let keyring = Arc::new(
                    ReloadingArtifactKeyring::open(artifact.keyring_path())
                        .map_err(|_| PostgresStoreError::InvalidConfig)?,
                );
                let store = Arc::new(
                    PosixArtifactBlobStore::open_config(artifact, keyring.clone())
                        .map_err(|_| PostgresStoreError::InvalidConfig)?,
                );
                (Some(store), Some(keyring))
            } else {
                (None, None)
            };
        let insecure = validate_tls(&config)?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        let mut runtime_pg = tokio_postgres::Config::from_str(&config.runtime_url)
            .map_err(|_| PostgresStoreError::InvalidConfig)?;
        // Runtime login is NOINHERIT by policy. Every pooled connection must enter
        // the schema-scoped generated role before issuing any authority query.
        runtime_pg.options(format!("-c role={}_runtime", config.schema));
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
        validate_runtime_login(&migration, &config.schema, &runtime_user)
            .await
            .inspect_err(|_| {
                eprintln!("smesh.postgres.validation_failed category=runtime_login_pre_migrate");
            })?;
        migrate(&mut migration, &config.schema, &runtime_user)
            .await
            .inspect_err(|_| {
                eprintln!("smesh.postgres.validation_failed category=migrate");
            })?;
        if config.audit_projection_enabled {
            let changed = migration
                .execute(
                    &format!(
                        "UPDATE {}.audit_projection_control SET enabled=true WHERE singleton=1 AND NOT EXISTS(SELECT 1 FROM {}.artifact_restore_jobs WHERE state='restoring')",
                        config.schema, config.schema
                    ),
                    &[],
                )
                .await
                .map_err(|_| PostgresStoreError::Initialization)?;
            if changed != 1 {
                return Err(PostgresStoreError::ArtifactMigrationBusy);
            }
        }
        let projection_proof = if config.audit_projection_enabled {
            Some(
                migration
                    .query_one(
                        &format!(
                            "SELECT proof FROM {}.audit_projection_session_secret WHERE singleton=1",
                            config.schema
                        ),
                        &[],
                    )
                    .await
                    .map_err(|_| PostgresStoreError::Initialization)?
                    .get::<_, String>(0),
            )
        } else {
            None
        };

        validate_runtime_login(&migration, &config.schema, &runtime_user)
            .await
            .inspect_err(|_| {
                eprintln!("smesh.postgres.validation_failed category=runtime_login_post_migrate");
            })?;

        let (cursor_key, receipt_key) = validate_catalog(&mut migration, &config.schema)
            .await
            .inspect_err(|_| {
                eprintln!("smesh.postgres.validation_failed category=catalog");
            })?;

        if let Some(keyring) = artifact_keyring.as_ref() {
            migration
                .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            let generations = migration
                .query(
                    &format!(
                        "SELECT DISTINCT key_generation FROM {}.content_objects WHERE state<>'deleted' UNION SELECT DISTINCT d.key_generation FROM {}.artifact_backup_key_dependencies d JOIN {}.artifact_backup_jobs b USING(tenant_scope,backup_id) WHERE b.state='sealed' AND d.released_at IS NULL AND d.required_until>{}.db_millis() ORDER BY key_generation",
                        config.schema, config.schema, config.schema, config.schema
                    ),
                    &[],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            migration
                .batch_execute("SELECT set_config('smesh.internal_global','',false)")
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            if generations
                .iter()
                .any(|row| keyring.key(row.get::<_, &str>(0)).is_err())
            {
                return Err(PostgresStoreError::InvalidSchema);
            }
        }
        if config.artifact_store.is_some() {
            let plan_id = config
                .artifact_migration_plan
                .as_ref()
                .map_or("", |plan| plan.plan_id());
            let required: bool = migration
                .query_one(
                    &format!(
                        "SELECT {}.artifact_inline_migration_required($1)",
                        config.schema
                    ),
                    &[&plan_id],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?
                .get(0);
            if required {
                return Err(PostgresStoreError::ArtifactMigrationRequired);
            }
            migration
                .batch_execute("SELECT set_config('smesh.internal_global','claim-v1',false)")
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            let store_id: Vec<u8> = migration
                .query_one(
                    &format!(
                        "SELECT store_id FROM {}.store_identity WHERE singleton=1",
                        config.schema
                    ),
                    &[],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?
                .get(0);
            let store_identity =
                store_id
                    .iter()
                    .fold(String::from("sha256:"), |mut identity, byte| {
                        write!(&mut identity, "{byte:02x}").expect("writing to String cannot fail");
                        identity
                    });
            if let Some(plan) = config.artifact_migration_plan.as_ref() {
                crate::artifact_migration_executor::verify_completed_plan(
                    &migration,
                    &config.schema,
                    &store_identity,
                    plan,
                )
                .await?;
            }
            if let Some(file) = config.artifact_migration_plan_file.as_ref() {
                if file.source_schema() != config.schema.as_ref()
                    || file.source_store_id().to_string() != store_identity
                {
                    return Err(PostgresStoreError::ArtifactMigrationRequired);
                }
                crate::artifact_migration_executor::verify_completed_plan(
                    &migration,
                    &config.schema,
                    &store_identity,
                    file.plan(),
                )
                .await?;
            }
            migration
                .batch_execute("SELECT set_config('smesh.internal_global','',false)")
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
        }
        reconcile_quota_policy(
            &mut migration,
            &config.schema,
            config.quota_policy.as_deref(),
            config.quota_reconciliation_plan.as_deref(),
        )
        .await
        .inspect_err(|_| {
            eprintln!("smesh.postgres.validation_failed category=quota_reconcile");
        })?;
        let callback_policy = reconcile_callback_policy(
            &mut migration,
            &config.schema,
            config.push_policy.as_deref(),
        )
        .await
        .inspect_err(|_| {
            eprintln!("smesh.postgres.validation_failed category=callback_reconcile");
        })?;
        let callback_worker_proof = if callback_policy.is_some() {
            Some(
                migration
                    .query_one(
                        &format!(
                            "SELECT proof FROM {}.callback_worker_session_secret WHERE singleton=1",
                            config.schema
                        ),
                        &[],
                    )
                    .await
                    .map_err(|_| PostgresStoreError::Initialization)?
                    .get::<_, String>(0),
            )
        } else {
            None
        };

        drop(migration);
        driver.abort();
        let mut pool_builder = Pool::builder(manager)
            .max_size(config.pool_size)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(config.acquire_timeout))
            .create_timeout(Some(config.connect_timeout))
            .recycle_timeout(Some(config.acquire_timeout));
        if let Some(proof) = projection_proof {
            let sql = Arc::new(format!(
                "SELECT {}.register_audit_projection_session($1)",
                config.schema
            ));
            let proof = Arc::new(proof);
            pool_builder = pool_builder.post_create(Hook::async_fn(move |client, _| {
                let sql = Arc::clone(&sql);
                let proof = Arc::clone(&proof);
                Box::pin(async move {
                    client
                        .query_one(sql.as_str(), &[&proof.as_str()])
                        .await
                        .map(|_| ())
                        .map_err(|_| HookError::message("projection session registration failed"))
                })
            }));
        }
        if let Some(proof) = callback_worker_proof {
            let sql = Arc::new(format!(
                "SELECT {}.register_callback_worker_session($1)",
                config.schema
            ));
            let proof = Arc::new(proof);
            pool_builder = pool_builder.post_create(Hook::async_fn(move |client, _| {
                let sql = Arc::clone(&sql);
                let proof = Arc::clone(&proof);
                Box::pin(async move {
                    client
                        .query_one(sql.as_str(), &[&proof.as_str()])
                        .await
                        .map(|_| ())
                        .map_err(|_| {
                            HookError::message("callback worker session registration failed")
                        })
                })
            }));
        }
        let pool = pool_builder
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
        let restore_incomplete: bool = validation
            .query_one(
                &format!("SELECT {}.artifact_restore_incomplete()", config.schema),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .get(0);
        if restore_incomplete {
            return Err(PostgresStoreError::ArtifactRestoreIncomplete);
        }

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
        let mut quota_policy_mismatch = false;
        for row in tenants {
            let tenant: String = row.get(0);
            validation
                .query_one(
                    "SELECT set_config('smesh.tenant_scope',$1,true), set_config('smesh.account_id','',true)",
                    &[&tenant],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            let restore_incomplete: bool = validation
                .query_one(
                    &format!("SELECT EXISTS(SELECT 1 FROM {}.artifact_restore_jobs WHERE tenant_scope=$1 AND state IN ('restoring','verified'))", config.schema),
                    &[&tenant],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?
                .get(0);
            if restore_incomplete {
                return Err(PostgresStoreError::ArtifactRestoreIncomplete);
            }
            let retained = validation
                .query_one(
                    &format!("SELECT COALESCE((SELECT retained_bytes FROM {}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1),-1),{}.retained_authority_oracle($1,NULL)+{}.artifact_retained_oracle($1,NULL)+{}.callback_retained_oracle($1,NULL)", config.schema, config.schema, config.schema, config.schema),
                    &[&tenant],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            let materialized: i64 = retained.get(0);
            let oracle: i64 = retained.get(1);
            if materialized < 0 || materialized != oracle || oracle > 64 * 1024 * 1024 {
                eprintln!("smesh.postgres.validation_failed category=retained_tenant");
                quota_policy_mismatch = true;
                break;
            }
            let account_rows = validation
                .query(
                    &format!("SELECT scopes.scope_id,COALESCE(u.retained_bytes,-1),{}.retained_authority_account_oracle($1,scopes.scope_id)+{}.artifact_retained_account_oracle($1,scopes.scope_id)+{}.callback_retained_account_oracle($1,scopes.scope_id) FROM (SELECT DISTINCT {}.authority_retained_scopes_bounded($1,'account') scope_id UNION SELECT DISTINCT {}.callback_retained_scopes_bounded($1,'account') scope_id UNION SELECT scope_id FROM {}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='account') scopes LEFT JOIN {}.retained_authority_usage u ON u.tenant_scope=$1 AND u.scope_kind='account' AND u.scope_id=scopes.scope_id ORDER BY scopes.scope_id", config.schema, config.schema, config.schema, config.schema, config.schema, config.schema, config.schema),
                    &[&tenant],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            if account_rows
                .iter()
                .any(|row| row.get::<_, i64>(1) < 0 || row.get::<_, i64>(1) != row.get::<_, i64>(2))
            {
                eprintln!("smesh.postgres.validation_failed category=retained_account");
                quota_policy_mismatch = true;
                break;
            }
            let principal_rows = validation
                .query(
                    &format!("SELECT scopes.scope_id,COALESCE(u.retained_bytes,-1),{}.retained_authority_oracle($1,scopes.scope_id)+{}.artifact_retained_oracle($1,scopes.scope_id)+{}.callback_retained_oracle($1,scopes.scope_id) FROM (SELECT DISTINCT {}.authority_retained_scopes_bounded($1,'principal') scope_id UNION SELECT DISTINCT {}.callback_retained_scopes_bounded($1,'principal') scope_id UNION SELECT scope_id FROM {}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='principal') scopes LEFT JOIN {}.retained_authority_usage u ON u.tenant_scope=$1 AND u.scope_kind='principal' AND u.scope_id=scopes.scope_id ORDER BY scopes.scope_id", config.schema, config.schema, config.schema, config.schema, config.schema, config.schema, config.schema),
                    &[&tenant],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            if principal_rows
                .iter()
                .any(|row| row.get::<_, i64>(1) < 0 || row.get::<_, i64>(1) != row.get::<_, i64>(2))
            {
                eprintln!("smesh.postgres.validation_failed category=retained_principal");
                quota_policy_mismatch = true;
                break;
            }
            if let Some(policy) = config.quota_policy.as_ref() {
                let rows = validation
                    .query(
                        &format!(
                            "SELECT policy_id,policy_revision,policy_digest FROM {}.quota_policy_versions WHERE tenant_scope=$1 AND lifecycle='active'",
                            config.schema
                        ),
                        &[&tenant],
                    )
                    .await
                    .map_err(|_| PostgresStoreError::InvalidSchema)?;
                if !rows.is_empty()
                    && (rows.len() != 1
                        || rows[0].get::<_, String>(0) != policy.policy_id()
                        || rows[0].get::<_, i64>(1)
                            != i64::try_from(policy.revision())
                                .map_err(|_| PostgresStoreError::InvalidSchema)?
                        || rows[0].get::<_, String>(2) != policy.digest())
                {
                    eprintln!("smesh.postgres.validation_failed category=quota_snapshot");
                    quota_policy_mismatch = true;
                    break;
                }
            }
            validate_semantics(&*validation, &config.schema, &cursor_key)
                .await
                .inspect_err(|_| {
                    eprintln!("smesh.postgres.validation_failed category=semantics");
                })?;
        }
        validation
            .rollback()
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        if quota_policy_mismatch {
            return Err(PostgresStoreError::InvalidSchema);
        }
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
            audit_projection_enabled: config.audit_projection_enabled,
            quota_enforcement: config.quota_enforcement,
            quota_policy: config.quota_policy,
            callback_policy,
            transaction_test_faults: config.transaction_test_faults,
            artifact_publication_test_fault: config.artifact_publication_test_fault,
            transaction_attempts: Arc::new(AtomicUsize::new(0)),
            artifact_blob_reads: Arc::new(AtomicUsize::new(0)),
            receiver_renewal_test_probe: config.receiver_renewal_test_probe,
            artifact_store,
            artifact_keyring,
            artifact_runtime_limits,
            telemetry: None,
            _test_cleanup: config.test_cleanup,
        })
    }

    /// Atomically reload the no-follow keyring only after the replacement can
    /// decrypt every generation referenced by any live production object.
    pub async fn reload_artifact_keyring(&self) -> Result<(), PostgresStoreError> {
        let keyring = self
            .artifact_keyring
            .as_ref()
            .ok_or(PostgresStoreError::InvalidConfig)?;
        let mut object = tokio::time::timeout(self.acquire_timeout, self.pool.get())
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?
            .map_err(|_| PostgresStoreError::Unavailable)?;
        // ALLOWLIST: read-only tenant/key-generation snapshot before atomic reload.
        let tx = object
            .transaction()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        tx.batch_execute("SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='5s'")
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        let tenants = tx
            .query(
                &format!("SELECT * FROM {}.authority_tenants_bounded()", self.schema),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let mut generations = BTreeSet::new();
        for row in tenants {
            let tenant: String = row.get(0);
            tx.query_one(
                "SELECT set_config('smesh.tenant_scope',$1,true),set_config('smesh.account_id','',true)",
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
            for generation in tx
                .query(
                    &self.q("SELECT DISTINCT key_generation FROM __S__.content_objects WHERE state<>'deleted' UNION SELECT DISTINCT d.key_generation FROM __S__.artifact_backup_key_dependencies d JOIN __S__.artifact_backup_jobs b USING(tenant_scope,backup_id) WHERE b.state='sealed' AND d.released_at IS NULL AND d.required_until>__S__.db_millis() ORDER BY key_generation"),
                    &[],
                )
                .await
                .map_err(|_| PostgresStoreError::InvalidSchema)?
            {
                generations.insert(generation.get::<_, String>(0));
            }
        }
        tx.rollback()
            .await
            .map_err(|_| PostgresStoreError::Unavailable)?;
        keyring
            .reload_if(|candidate| {
                if generations
                    .iter()
                    .any(|generation| candidate.key(generation).is_err())
                {
                    Err(crate::ArtifactStoreError::Unavailable)
                } else {
                    Ok(())
                }
            })
            .map_err(|_| PostgresStoreError::InvalidConfig)
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

    /// Read the O(1) materialized tenant and optional principal retained-byte totals.
    #[doc(hidden)]
    pub async fn retained_authority_bytes(
        &self,
        tenant: &str,
        principal: Option<&str>,
    ) -> Result<(u64, u64), A2AError> {
        let tenant = tenant.to_owned();
        let principal = principal.map(str::to_owned);
        self.run_retryable_transaction(&tenant.clone(), None, |store, tx| {
            let tenant = tenant.clone();
            let principal = principal.clone();
            Box::pin(async move {
                let sql = store.q("SELECT COALESCE((SELECT retained_bytes FROM __S__.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1),0),COALESCE((SELECT retained_bytes FROM __S__.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='principal' AND scope_id=$2),0)");
                let row = tx
                    .query_one(&sql, &[&tenant, &principal])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("retained authority diagnostics query failed")))?;
                let tenant_bytes: i64 = row.get(0);
                let principal_bytes: i64 = row.get(1);
                Ok((
                    u64::try_from(tenant_bytes)
                        .map_err(|_| A2AError::internal("retained tenant counter is corrupt"))?,
                    u64::try_from(principal_bytes)
                        .map_err(|_| A2AError::internal("retained principal counter is corrupt"))?,
                ))
            })
        }).await
    }

    /// Delete at most `max_rows` independently safe, expired quota evidence rows.
    #[doc(hidden)]
    pub async fn gc_quota_authority(&self, now: i64, max_rows: u32) -> Result<u64, A2AError> {
        if !(1..=1000).contains(&max_rows) {
            return Err(A2AError::invalid_params(
                "quota GC max_rows must be between 1 and 1000",
            ));
        }
        let max_rows = i32::try_from(max_rows).unwrap_or(i32::MAX);
        self.run_retryable_transaction("", None, |store, tx| {
            Box::pin(async move {
                tx.batch_execute("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'")
                    .await
                    .map_err(|error| {
                        Self::transaction_body_error(
                            &error,
                            A2AError::internal("quota GC watchdog setup failed"),
                        )
                    })?;
                let sql = store.q("SELECT __S__.gc_quota_authority_bounded($1,$2)");
                let removed: i32 = tx
                    .query_one(&sql, &[&now, &max_rows])
                    .await
                    .map_err(|error| {
                        Self::transaction_body_error(&error, A2AError::internal("quota GC failed"))
                    })?
                    .get(0);
                u64::try_from(removed).map_err(|_| A2AError::internal("quota GC result is corrupt"))
            })
        })
        .await
    }

    /// Read one indexed bucket total for deterministic quota evidence.
    #[doc(hidden)]
    pub async fn quota_used_units(
        &self,
        tenant: &str,
        scope_kind: crate::QuotaScopeKind,
        scope_id: &str,
        operation: crate::QuotaOperation,
        dimension: crate::QuotaDimension,
    ) -> Result<u64, A2AError> {
        let mut connection = self.connection().await?;
        // ALLOWLIST: read-only indexed quota diagnostics for deterministic evidence.
        let tx = connection
            .transaction()
            .await
            .map_err(|_| A2AError::internal("quota diagnostics transaction failed"))?;
        self.set_tenant(&tx, tenant, None).await?;
        let sql = self.q("SELECT COALESCE(sum(used_units),0)::bigint FROM __S__.quota_buckets WHERE tenant_scope=$1 AND scope_kind=$2 AND scope_id=$3 AND operation=$4 AND dimension=$5");
        let used: i64 = tx
            .query_one(
                &sql,
                &[
                    &tenant,
                    &scope_kind.as_str(),
                    &scope_id,
                    &operation.as_str(),
                    &dimension.as_str(),
                ],
            )
            .await
            .map_err(|_| A2AError::internal("quota diagnostics query failed"))?
            .get(0);
        tx.rollback()
            .await
            .map_err(|_| A2AError::internal("quota diagnostics rollback failed"))?;
        u64::try_from(used).map_err(|_| A2AError::internal("quota diagnostics are corrupt"))
    }

    /// Count durable digest-only quota denials for deterministic evidence.
    #[doc(hidden)]
    pub async fn quota_denial_count(&self, tenant: &str) -> Result<u64, A2AError> {
        let tenant = tenant.to_owned();
        self.run_retryable_transaction(&tenant.clone(), None, |store, tx| {
            let tenant = tenant.clone();
            Box::pin(async move {
                let sql = store.q(
                    "SELECT count(*)::bigint FROM __S__.quota_denial_audits WHERE tenant_scope=$1",
                );
                let count: i64 = tx
                    .query_one(&sql, &[&tenant])
                    .await
                    .map_err(|_| A2AError::internal("quota denial diagnostics query failed"))?
                    .get(0);
                u64::try_from(count)
                    .map_err(|_| A2AError::internal("quota denial diagnostics are corrupt"))
            })
        })
        .await
    }

    /// Number of whole-transaction attempts made by this store instance.
    #[doc(hidden)]
    #[must_use]
    pub fn transaction_attempts(&self) -> usize {
        self.transaction_attempts.load(Ordering::SeqCst)
    }

    /// Number of artifact blob reads attempted by this store instance.
    #[doc(hidden)]
    #[must_use]
    pub fn artifact_blob_read_count(&self) -> usize {
        self.artifact_blob_reads.load(Ordering::SeqCst)
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

    /// Holds one tenant's materialized retained counter row inside a real transaction.
    #[doc(hidden)]
    pub async fn hold_test_tenant_counter_transaction(
        &self,
        tenant: &str,
        account: &str,
        acquired: Arc<tokio::sync::Barrier>,
        release: Arc<tokio::sync::Barrier>,
    ) -> Result<(), A2AError> {
        if !self.trust_injected_time {
            return Err(A2AError::internal(
                "test tenant transaction hold is disabled",
            ));
        }
        self.run_retryable_transaction(tenant, Some(account), |store, tx| {
            let tenant = tenant.to_owned();
            let acquired = Arc::clone(&acquired);
            let release = Arc::clone(&release);
            Box::pin(async move {
                let sql = store.q("SELECT retained_bytes FROM __S__.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1 FOR UPDATE");
                tx.query_one(&sql, &[&tenant]).await.map_err(|error| {
                    Self::transaction_body_error(&error, A2AError::internal("test tenant counter lock failed"))
                })?;
                acquired.wait().await;
                release.wait().await;
                Ok(())
            })
        }).await
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

    /// Arms one loopback-only receiver publication fault for exhaustive integration evidence.
    #[doc(hidden)]
    pub fn set_artifact_publication_test_fault(
        &self,
        fault: ArtifactPublicationTestFault,
    ) -> Result<(), A2AError> {
        if !self.trust_injected_time {
            return Err(A2AError::invalid_request(
                "artifact publication fault injection is disabled",
            ));
        }
        let mut configured = self
            .artifact_publication_test_fault
            .lock()
            .map_err(|_| A2AError::internal("artifact publication fault lock failed"))?;
        *configured = Some(fault);
        Ok(())
    }

    fn publication_fault(&self, point: ArtifactPublicationTestFault) -> Result<(), A2AError> {
        if !self.trust_injected_time {
            return Ok(());
        }
        let mut configured = self
            .artifact_publication_test_fault
            .lock()
            .map_err(|_| A2AError::internal("artifact publication fault lock failed"))?;
        if configured.as_ref() == Some(&point) {
            configured.take();
            return Err(A2AError::internal("injected artifact publication fault"));
        }
        Ok(())
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
        let quota_required = self.quota_enforcement && account.is_some();
        let infrastructure_error = |error: A2AError| {
            if quota_required && error.code == -32_603 {
                crate::quota::quota_authority_unavailable()
            } else {
                error
            }
        };
        for attempt in 1..=MAX_TRANSACTION_ATTEMPTS {
            self.transaction_attempts.fetch_add(1, Ordering::SeqCst);
            let mut client = self.connection().await.map_err(infrastructure_error)?;
            // ALLOWLIST: the central whole-transaction retry runner owns this site.
            let tx = client.transaction().await.map_err(|_| {
                infrastructure_error(A2AError::internal("PostgreSQL transaction failed"))
            })?;
            if tenant.is_empty() {
                // Global workers still run as the restricted runtime role. The only
                // cross-tenant authority is inside fixed-search-path SECURITY DEFINER
                // procedures that return one bounded row or one boolean.
                tx.batch_execute(&format!("SET LOCAL ROLE {}_runtime; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'", self.schema))
                    .await
                    .map_err(|_| infrastructure_error(A2AError::internal("failed to select PostgreSQL runtime role")))?;
                tx.query_one(
                    "SELECT set_config('smesh.tenant_scope','',true), set_config('smesh.account_id','',true)",
                    &[],
                )
                .await
                .map_err(|_| infrastructure_error(
                    A2AError::internal("failed to establish PostgreSQL tenant context")
                ))?;
            } else {
                self.set_tenant(&tx, tenant, account)
                    .await
                    .map_err(infrastructure_error)?;
            }

            let test_fault = self.next_transaction_test_fault();
            match test_fault {
                Some(
                    PostgresTransactionTestFault::SerializationFailure
                    | PostgresTransactionTestFault::DeadlockDetected,
                ) => {
                    let _ = tx.rollback().await;
                    if attempt == MAX_TRANSACTION_ATTEMPTS {
                        return Err(infrastructure_error(A2AError::internal(
                            "PostgreSQL transaction retry limit reached",
                        )));
                    }
                    continue;
                }
                Some(PostgresTransactionTestFault::NonRetryable) => {
                    let _ = tx.rollback().await;
                    return Err(infrastructure_error(A2AError::internal(
                        "PostgreSQL transaction failed",
                    )));
                }
                Some(PostgresTransactionTestFault::AmbiguousCommit) | None => {}
            }

            match operation(self, &tx).await {
                Ok(value) => {
                    if test_fault == Some(PostgresTransactionTestFault::AmbiguousCommit) {
                        // The test checkpoint is immediately before commit: the closure has run,
                        // but rollback proves no mutation escaped and the command is not retried.
                        let _ = tx.rollback().await;
                        return Err(infrastructure_error(A2AError::internal(
                            "PostgreSQL transaction commit failed",
                        )));
                    }
                    // A commit error is potentially ambiguous and is deliberately never retried.
                    tx.commit().await.map_err(|_| {
                        infrastructure_error(A2AError::internal(
                            "PostgreSQL transaction commit failed",
                        ))
                    })?;
                    return Ok(value);
                }
                Err(error) if error.message == RETRYABLE_TRANSACTION_MARKER => {
                    let _ = tx.rollback().await;
                    if attempt == MAX_TRANSACTION_ATTEMPTS {
                        return Err(infrastructure_error(A2AError::internal(
                            "PostgreSQL transaction retry limit reached",
                        )));
                    }
                }
                Err(error) => {
                    let _ = tx.rollback().await;
                    return Err(infrastructure_error(error));
                }
            }
        }
        Err(infrastructure_error(A2AError::internal(
            "PostgreSQL transaction retry limit reached",
        )))
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

    async fn apply_replay_request_charges(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        policy: &crate::QuotaPolicy,
        intent: &crate::QuotaIntent,
        tenant: &str,
        mutation_binding: &str,
        now: i64,
    ) -> Result<(), A2AError> {
        let entropy: [u8; 32] = rand::random();
        let invocation_id = content_digest(
            [mutation_binding.as_bytes(), &now.to_be_bytes(), &entropy]
                .concat()
                .as_slice(),
        );
        for charge in intent.charges().iter().filter(|charge| {
            matches!(
                charge.dimension,
                crate::QuotaDimension::RequestCount | crate::QuotaDimension::InputBytes
            )
        }) {
            let units = i64::try_from(charge.units)
                .map_err(|_| A2AError::invalid_request("invalid quota units"))?;
            let capacity = i64::try_from(policy.limit_at(
                charge.scope_kind,
                charge.scope_id.as_ref(),
                intent.operation(),
                charge.dimension,
                now,
            ))
            .map_err(|_| A2AError::invalid_request("invalid quota capacity"))?;
            let window_millis = charge
                .window_millis
                .map(|value| i64::try_from(value).unwrap_or(i64::MAX));
            let window_start = if charge.algorithm == crate::QuotaAlgorithm::TokenBucket {
                0
            } else {
                window_millis.map_or(0, |window| now.div_euclid(window) * window)
            };
            let insert = self.q("INSERT INTO __S__.quota_buckets(tenant_scope,policy_digest,scope_kind,scope_id,operation,dimension,algorithm,window_start,window_millis,capacity,used_units,available_tokens,last_refill_at,refill_numerator,refill_period_millis,refill_remainder,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint,$10,0,CASE WHEN $7::text='tokenBucket' THEN $10::bigint END,CASE WHEN $7::text='tokenBucket' THEN $11::bigint END,CASE WHEN $7::text='tokenBucket' THEN $10::bigint END,CASE WHEN $7::text='tokenBucket' THEN $9::bigint END,CASE WHEN $7::text='tokenBucket' THEN 0::bigint END,$11) ON CONFLICT DO NOTHING");
            tx.execute(
                &insert,
                &[
                    &tenant,
                    &intent.policy_digest(),
                    &charge.scope_kind.as_str(),
                    &charge.scope_id.as_ref(),
                    &intent.operation().as_str(),
                    &charge.dimension.as_str(),
                    &charge.algorithm.as_str(),
                    &window_start,
                    &window_millis,
                    &capacity,
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(&error, crate::quota::quota_authority_unavailable())
            })?;
            let update = self.q("UPDATE __S__.quota_buckets SET used_units=used_units+$8,capacity=$10,updated_at=$9 WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind=$3 AND scope_id=$4 AND operation=$5 AND dimension=$6 AND window_start=$7 AND used_units <= $10::bigint-$8::bigint RETURNING used_units");
            if tx
                .query_opt(
                    &update,
                    &[
                        &tenant,
                        &intent.policy_digest(),
                        &charge.scope_kind.as_str(),
                        &charge.scope_id.as_ref(),
                        &intent.operation().as_str(),
                        &charge.dimension.as_str(),
                        &window_start,
                        &units,
                        &now,
                        &capacity,
                    ],
                )
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        crate::quota::quota_authority_unavailable(),
                    )
                })?
                .is_none()
            {
                return Err(crate::quota::quota_exceeded());
            }
            let receipt = self.q("INSERT INTO __S__.quota_request_receipts(tenant_scope,invocation_id,mutation_binding_digest,policy_digest,scope_kind,scope_id,operation,dimension,window_start,units,capacity,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)");
            tx.execute(
                &receipt,
                &[
                    &tenant,
                    &invocation_id,
                    &mutation_binding,
                    &intent.policy_digest(),
                    &charge.scope_kind.as_str(),
                    &charge.scope_id.as_ref(),
                    &intent.operation().as_str(),
                    &charge.dimension.as_str(),
                    &window_start,
                    &units,
                    &capacity,
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(&error, crate::quota::quota_authority_unavailable())
            })?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_quota_intent(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        intent: &crate::QuotaIntent,
        tenant: &str,
        account: &str,
        task_id: Option<&str>,
        now: i64,
        insert_if_missing: bool,
        request: Option<&SendMessageRequest>,
    ) -> Result<(), A2AError> {
        let policy = self
            .quota_policy
            .as_ref()
            .ok_or_else(crate::quota::quota_authority_unavailable)?;
        if intent.tenant_scope.as_ref() != tenant
            || intent.account_id.as_ref() != account
            || intent.policy_id() != policy.policy_id()
            || intent.policy_revision() != policy.revision()
            || intent.policy_digest() != policy.digest()
        {
            return Err(A2AError::invalid_request("quota intent binding mismatch"));
        }
        let subject = crate::QuotaSubject::new(tenant, account, intent.principal_scope.as_ref())
            .map_err(|_| A2AError::invalid_request("quota intent binding mismatch"))?;
        let input_bytes = request.map_or(Ok(0), |request| {
            u64::try_from(
                serde_json::to_vec(request)
                    .map_err(|_| A2AError::internal("failed to measure quota input"))?
                    .len(),
            )
            .map_err(|_| A2AError::invalid_request("quota input is too large"))
        })?;
        let expected = if intent.operation() == crate::QuotaOperation::PublicEgress {
            let bytes = intent
                .charges()
                .iter()
                .find(|charge| {
                    charge.scope_kind == crate::QuotaScopeKind::Tenant
                        && charge.dimension == crate::QuotaDimension::OutputBytes
                })
                .map_or(0, |charge| charge.units);
            let events = intent
                .charges()
                .iter()
                .find(|charge| {
                    charge.scope_kind == crate::QuotaScopeKind::Tenant
                        && charge.dimension == crate::QuotaDimension::EventCount
                })
                .map_or(0, |charge| charge.units);
            policy.egress_intent(&subject, &intent.semantic_id, bytes, events)
        } else if intent.charges.iter().any(|charge| {
            matches!(
                charge.dimension,
                crate::QuotaDimension::ConcurrentStreams
                    | crate::QuotaDimension::ConcurrentSubscriptions
            )
        }) {
            let kind = if intent
                .charges
                .iter()
                .any(|charge| charge.dimension == crate::QuotaDimension::ConcurrentStreams)
            {
                crate::QuotaLeaseKind::MessageStream
            } else {
                crate::QuotaLeaseKind::TaskSubscription
            };
            policy.lease_intent(
                &subject,
                kind,
                &intent.semantic_id,
                intent.operation() == crate::QuotaOperation::Reconnect,
            )
        } else {
            policy.operation_intent(
                &subject,
                intent.operation(),
                &intent.semantic_id,
                input_bytes,
            )
        }
        .map_err(|_| A2AError::invalid_request("quota intent binding mismatch"))?;
        if &expected != intent {
            return Err(A2AError::invalid_request("quota intent binding mismatch"));
        }
        let lookup = self.q("SELECT i.binding_digest,i.account_id,i.principal_scope,i.operation,i.semantic_id,i.task_id,i.policy_id,i.policy_revision,i.policy_digest,p.canonical_json FROM __S__.quota_intents i JOIN __S__.quota_policy_versions p ON p.tenant_scope=i.tenant_scope AND p.policy_id=i.policy_id AND p.policy_revision=i.policy_revision WHERE i.tenant_scope=$1 AND (i.binding_digest=$2 OR (i.operation=$3 AND i.semantic_id=$4 AND i.account_id=$5 AND i.principal_scope=$6)) ORDER BY (i.binding_digest=$2) DESC LIMIT 1");
        if let Some(row) = tx
            .query_opt(
                &lookup,
                &[
                    &tenant,
                    &intent.binding_digest(),
                    &intent.operation().as_str(),
                    &intent.semantic_id.as_ref(),
                    &account,
                    &intent.principal_scope.as_ref(),
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota intent lookup failed"),
                )
            })?
        {
            let mutation_binding: String = row.get(0);
            let exact = row.get::<_, String>(1) == account
                && row.get::<_, String>(2) == intent.principal_scope.as_ref()
                && row.get::<_, String>(3) == intent.operation().as_str()
                && row.get::<_, String>(4) == intent.semantic_id.as_ref()
                && row.get::<_, Option<String>>(5).as_deref() == task_id;
            if !exact {
                return Err(A2AError::invalid_request("quota intent key conflict"));
            }
            let stored_policy = crate::QuotaPolicy::from_json(row.get::<_, String>(9).as_bytes())
                .map_err(|_| crate::quota::quota_authority_unavailable())?;
            let stored_revision = u64::try_from(row.get::<_, i64>(7))
                .map_err(|_| crate::quota::quota_authority_unavailable())?;
            if row.get::<_, String>(6) != stored_policy.policy_id()
                || stored_revision != stored_policy.revision()
                || row.get::<_, String>(8) != stored_policy.digest()
            {
                return Err(crate::quota::quota_authority_unavailable());
            }
            let stored_intent = if intent.operation() == crate::QuotaOperation::PublicEgress {
                let bytes = intent
                    .charges()
                    .iter()
                    .find(|charge| {
                        charge.scope_kind == crate::QuotaScopeKind::Tenant
                            && charge.dimension == crate::QuotaDimension::OutputBytes
                    })
                    .map_or(0, |charge| charge.units);
                let events = intent
                    .charges()
                    .iter()
                    .find(|charge| {
                        charge.scope_kind == crate::QuotaScopeKind::Tenant
                            && charge.dimension == crate::QuotaDimension::EventCount
                    })
                    .map_or(0, |charge| charge.units);
                stored_policy.egress_intent(&subject, &intent.semantic_id, bytes, events)
            } else if intent.charges.iter().any(|charge| {
                matches!(
                    charge.dimension,
                    crate::QuotaDimension::ConcurrentStreams
                        | crate::QuotaDimension::ConcurrentSubscriptions
                )
            }) {
                let kind = if intent
                    .charges
                    .iter()
                    .any(|charge| charge.dimension == crate::QuotaDimension::ConcurrentStreams)
                {
                    crate::QuotaLeaseKind::MessageStream
                } else {
                    crate::QuotaLeaseKind::TaskSubscription
                };
                stored_policy.lease_intent(
                    &subject,
                    kind,
                    &intent.semantic_id,
                    intent.operation() == crate::QuotaOperation::Reconnect,
                )
            } else {
                stored_policy.operation_intent(
                    &subject,
                    intent.operation(),
                    &intent.semantic_id,
                    input_bytes,
                )
            }
            .map_err(|_| A2AError::invalid_request("quota intent binding mismatch"))?;
            if stored_intent.binding_digest() != mutation_binding {
                return Err(crate::quota::quota_authority_unavailable());
            }
            return self
                .apply_replay_request_charges(
                    tx,
                    &stored_policy,
                    &stored_intent,
                    tenant,
                    &mutation_binding,
                    now,
                )
                .await;
        }
        if !insert_if_missing {
            return Err(A2AError::invalid_request(
                "quota intent is required for replay",
            ));
        }
        let policy_insert = self.q("INSERT INTO __S__.quota_policy_versions(tenant_scope,policy_id,policy_revision,policy_digest,canonical_json,created_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_scope,policy_id,policy_revision) DO NOTHING");
        tx.execute(
            &policy_insert,
            &[
                &tenant,
                &policy.policy_id(),
                &i64::try_from(policy.revision())
                    .map_err(|_| A2AError::invalid_request("invalid quota revision"))?,
                &policy.digest(),
                &policy.canonical_json(),
                &now,
            ],
        )
        .await
        .map_err(|error| {
            Self::transaction_body_error(
                &error,
                A2AError::internal("quota policy snapshot insert failed"),
            )
        })?;
        for value in policy.overrides() {
            let override_insert = self.q("INSERT INTO __S__.quota_override_audits(tenant_scope,override_id,actor_digest,reason_digest,scope_kind,scope_id_digest,operation,dimension,old_limit,new_limit,policy_revision,policy_digest,effective_at,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT(tenant_scope,override_id) DO NOTHING");
            tx.execute(
                &override_insert,
                &[
                    &tenant,
                    &value.override_id,
                    &content_digest(value.actor.as_bytes()),
                    &content_digest(value.reason.as_bytes()),
                    &value.scope_kind.as_str(),
                    &content_digest(value.scope_id.as_bytes()),
                    &value.operation.as_str(),
                    &value.dimension.as_str(),
                    &i64::try_from(value.old_limit)
                        .map_err(|_| A2AError::invalid_request("invalid quota override"))?,
                    &i64::try_from(value.new_limit)
                        .map_err(|_| A2AError::invalid_request("invalid quota override"))?,
                    &i64::try_from(policy.revision())
                        .map_err(|_| A2AError::invalid_request("invalid quota override"))?,
                    &policy.digest(),
                    &value.effective_at,
                    &value.expires_at,
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota override audit insert failed"),
                )
            })?;
        }
        let intent_insert = self.q("INSERT INTO __S__.quota_intents(tenant_scope,binding_digest,account_id,principal_scope,operation,semantic_id,policy_id,policy_revision,policy_digest,task_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)");
        tx.execute(
            &intent_insert,
            &[
                &tenant,
                &intent.binding_digest(),
                &account,
                &intent.principal_scope.as_ref(),
                &intent.operation().as_str(),
                &intent.semantic_id.as_ref(),
                &intent.policy_id(),
                &i64::try_from(intent.policy_revision())
                    .map_err(|_| A2AError::invalid_request("invalid quota revision"))?,
                &intent.policy_digest(),
                &task_id,
                &now,
            ],
        )
        .await
        .map_err(|error| {
            Self::transaction_body_error(&error, A2AError::internal("quota intent insert failed"))
        })?;
        for charge in intent.charges.iter() {
            let units = i64::try_from(charge.units)
                .map_err(|_| A2AError::invalid_request("invalid quota units"))?;
            let effective_capacity = policy.limit_at(
                charge.scope_kind,
                charge.scope_id.as_ref(),
                intent.operation(),
                charge.dimension,
                now,
            );
            let capacity = i64::try_from(effective_capacity)
                .map_err(|_| A2AError::invalid_request("invalid quota capacity"))?;
            let window_millis = charge
                .window_millis
                .map(|value| i64::try_from(value).unwrap_or(i64::MAX));
            let window_start = if charge.algorithm == crate::QuotaAlgorithm::TokenBucket {
                0
            } else {
                window_millis.map_or(0, |window| now.div_euclid(window) * window)
            };
            let insert = self.q("INSERT INTO __S__.quota_buckets(tenant_scope,policy_digest,scope_kind,scope_id,operation,dimension,algorithm,window_start,window_millis,capacity,used_units,available_tokens,last_refill_at,refill_numerator,refill_period_millis,refill_remainder,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint,$10,0,CASE WHEN $7::text='tokenBucket' THEN $10::bigint END,CASE WHEN $7::text='tokenBucket' THEN $11::bigint END,CASE WHEN $7::text='tokenBucket' THEN $10::bigint END,CASE WHEN $7::text='tokenBucket' THEN $9::bigint END,CASE WHEN $7::text='tokenBucket' THEN 0::bigint END,$11) ON CONFLICT DO NOTHING");
            tx.execute(
                &insert,
                &[
                    &tenant,
                    &intent.policy_digest(),
                    &charge.scope_kind.as_str(),
                    &charge.scope_id.as_ref(),
                    &intent.operation().as_str(),
                    &charge.dimension.as_str(),
                    &charge.algorithm.as_str(),
                    &window_start,
                    &window_millis,
                    &capacity,
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota bucket create failed"),
                )
            })?;
            let capacity_update = self.q("UPDATE __S__.quota_buckets SET used_units=CASE WHEN algorithm='tokenBucket' THEN $8-LEAST(available_tokens,$8) WHEN algorithm='gauge' THEN LEAST(used_units,$8) ELSE used_units END,available_tokens=CASE WHEN algorithm='tokenBucket' THEN LEAST(available_tokens,$8) END,refill_numerator=CASE WHEN algorithm='tokenBucket' THEN $8 END,capacity=$8,updated_at=GREATEST($9,updated_at) WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind=$3 AND scope_id=$4 AND operation=$5 AND dimension=$6 AND window_start=$7 AND capacity<>$8 AND (algorithm IN ('tokenBucket','gauge') OR used_units<=$8)");
            tx.execute(
                &capacity_update,
                &[
                    &tenant,
                    &intent.policy_digest(),
                    &charge.scope_kind.as_str(),
                    &charge.scope_id.as_ref(),
                    &intent.operation().as_str(),
                    &charge.dimension.as_str(),
                    &window_start,
                    &capacity,
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota override capacity update failed"),
                )
            })?;
            let authoritative_live = match charge.dimension {
                crate::QuotaDimension::ConcurrentActiveWork => Some(self.q(
                    "SELECT COALESCE(sum(a.units),0)::bigint FROM __S__.quota_allocations a JOIN __S__.quota_intents i USING(tenant_scope,binding_digest) WHERE a.tenant_scope=$1 AND a.scope_kind=$2 AND a.scope_id=$3 AND a.dimension=$4 AND a.state='active' AND i.operation=$5 AND $6::bigint IS NOT NULL",
                )),
                crate::QuotaDimension::ConcurrentStreams
                | crate::QuotaDimension::ConcurrentSubscriptions => Some(self.q(
                    "SELECT COALESCE(sum(r.units),0)::bigint FROM __S__.quota_leases l JOIN __S__.quota_receipts r USING(tenant_scope,binding_digest) WHERE l.tenant_scope=$1 AND r.scope_kind=$2 AND r.scope_id=$3 AND r.dimension=$4 AND l.state='active' AND l.lease_until>$6 AND l.operation=$5",
                )),
                crate::QuotaDimension::OutputBytes | crate::QuotaDimension::EventCount
                    if matches!(
                        intent.operation(),
                        crate::QuotaOperation::TaskCreate | crate::QuotaOperation::TaskContinue
                    ) => Some(self.q(
                        "SELECT COALESCE(sum(r.units),0)::bigint FROM __S__.quota_execution_reservations q JOIN __S__.quota_receipts r USING(tenant_scope,binding_digest) WHERE q.tenant_scope=$1 AND r.scope_kind=$2 AND r.scope_id=$3 AND r.dimension=$4 AND q.state='reserved' AND q.operation=$5 AND $6::bigint IS NOT NULL",
                    )),
                _ => None,
            };
            if let Some(authoritative_live) = authoritative_live {
                let lock = self.q("SELECT used_units FROM __S__.quota_buckets WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind=$3 AND scope_id=$4 AND operation=$5 AND dimension=$6 AND window_start=$7 FOR UPDATE");
                tx.query_one(
                    &lock,
                    &[
                        &tenant,
                        &intent.policy_digest(),
                        &charge.scope_kind.as_str(),
                        &charge.scope_id.as_ref(),
                        &intent.operation().as_str(),
                        &charge.dimension.as_str(),
                        &window_start,
                    ],
                )
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        crate::quota::quota_authority_unavailable(),
                    )
                })?;
                let live: i64 = tx
                    .query_one(
                        &authoritative_live,
                        &[
                            &tenant,
                            &charge.scope_kind.as_str(),
                            &charge.scope_id.as_ref(),
                            &charge.dimension.as_str(),
                            &intent.operation().as_str(),
                            &now,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        Self::transaction_body_error(
                            &error,
                            crate::quota::quota_authority_unavailable(),
                        )
                    })?
                    .get(0);
                if live > capacity - units {
                    return Err(crate::quota::quota_exceeded());
                }
            }
            let update = if charge.algorithm == crate::QuotaAlgorithm::TokenBucket {
                self.q("WITH refill AS (SELECT b.*,LEAST(b.capacity::numeric,b.available_tokens::numeric+floor((GREATEST($9-b.last_refill_at,0)::numeric*b.refill_numerator::numeric+b.refill_remainder::numeric)/b.refill_period_millis::numeric)::bigint)::bigint AS refilled,(GREATEST($9-b.last_refill_at,0)::numeric*b.refill_numerator::numeric+b.refill_remainder::numeric) AS refill_total FROM __S__.quota_buckets b WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind=$3 AND scope_id=$4 AND operation=$5 AND dimension=$6 AND window_start=$7 AND capacity=$10 FOR UPDATE), charged AS (UPDATE __S__.quota_buckets b SET available_tokens=r.refilled-$8,used_units=b.capacity-(r.refilled-$8),last_refill_at=GREATEST($9,b.last_refill_at),refill_remainder=CASE WHEN r.refilled=b.capacity THEN 0 ELSE mod(r.refill_total,b.refill_period_millis::numeric)::bigint END,updated_at=GREATEST($9,b.updated_at) FROM refill r WHERE b.tenant_scope=r.tenant_scope AND b.policy_digest=r.policy_digest AND b.scope_kind=r.scope_kind AND b.scope_id=r.scope_id AND b.operation=r.operation AND b.dimension=r.dimension AND b.window_start=r.window_start AND r.refilled >= $8 RETURNING b.used_units) SELECT used_units FROM charged")
            } else if charge.algorithm == crate::QuotaAlgorithm::Gauge {
                self.q("UPDATE __S__.quota_buckets SET used_units=LEAST(used_units,$10::bigint-$8::bigint)+$8,updated_at=GREATEST($9,updated_at) WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind=$3 AND scope_id=$4 AND operation=$5 AND dimension=$6 AND window_start=$7 AND capacity=$10 RETURNING used_units")
            } else {
                self.q("UPDATE __S__.quota_buckets SET used_units=used_units+$8,updated_at=GREATEST($9,updated_at) WHERE tenant_scope=$1 AND policy_digest=$2 AND scope_kind=$3 AND scope_id=$4 AND operation=$5 AND dimension=$6 AND window_start=$7 AND capacity=$10 AND used_units <= capacity-$8 RETURNING used_units")
            };
            if tx
                .query_opt(
                    &update,
                    &[
                        &tenant,
                        &intent.policy_digest(),
                        &charge.scope_kind.as_str(),
                        &charge.scope_id.as_ref(),
                        &intent.operation().as_str(),
                        &charge.dimension.as_str(),
                        &window_start,
                        &units,
                        &now,
                        &capacity,
                    ],
                )
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("quota bucket charge failed"),
                    )
                })?
                .is_none()
            {
                return Err(crate::quota::quota_exceeded());
            }
            let receipt = self.q("INSERT INTO __S__.quota_receipts(tenant_scope,binding_digest,scope_kind,scope_id,dimension,algorithm,window_start,units,capacity,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)");
            tx.execute(
                &receipt,
                &[
                    &tenant,
                    &intent.binding_digest(),
                    &charge.scope_kind.as_str(),
                    &charge.scope_id.as_ref(),
                    &charge.dimension.as_str(),
                    &charge.algorithm.as_str(),
                    &window_start,
                    &units,
                    &capacity,
                    &now,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota receipt insert failed"),
                )
            })?;
            if charge.algorithm == crate::QuotaAlgorithm::Gauge && task_id.is_some() {
                let allocation = self.q("INSERT INTO __S__.quota_allocations(tenant_scope,binding_digest,scope_kind,scope_id,dimension,task_id,units,state) VALUES($1,$2,$3,$4,$5,$6,$7,'active')");
                tx.execute(
                    &allocation,
                    &[
                        &tenant,
                        &intent.binding_digest(),
                        &charge.scope_kind.as_str(),
                        &charge.scope_id.as_ref(),
                        &charge.dimension.as_str(),
                        &task_id,
                        &units,
                    ],
                )
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("quota allocation insert failed"),
                    )
                })?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn bind_execution_reservation(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        intent: &crate::QuotaIntent,
        task_id: &str,
        message_id: &str,
        dispatch_id: &str,
        now: i64,
        insert_if_missing: bool,
    ) -> Result<(String, crate::ExecutionBudget), A2AError> {
        if !insert_if_missing {
            let replay_lookup = self.q("SELECT reservation_id,reserved_output_bytes,reserved_event_count,account_id,principal_scope,operation,task_id,message_id,dispatch_id FROM __S__.quota_execution_reservations WHERE tenant_scope=$1 AND dispatch_id=$2");
            let row = tx
                .query_opt(
                    &replay_lookup,
                    &[&intent.tenant_scope.as_ref(), &dispatch_id],
                )
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("execution reservation replay lookup failed"),
                    )
                })?
                .ok_or_else(|| {
                    A2AError::invalid_request("execution reservation is required for replay")
                })?;
            if row.get::<_, String>(3) != intent.account_id.as_ref()
                || row.get::<_, String>(4) != intent.principal_scope.as_ref()
                || row.get::<_, String>(5) != intent.operation().as_str()
                || row.get::<_, String>(6) != task_id
                || row.get::<_, String>(7) != message_id
                || row.get::<_, String>(8) != dispatch_id
            {
                return Err(A2AError::invalid_request(
                    "execution reservation key conflict",
                ));
            }
            let budget = crate::ExecutionBudget::new(
                u64::try_from(row.get::<_, i64>(1))
                    .map_err(|_| A2AError::internal("stored execution output budget is corrupt"))?,
                u64::try_from(row.get::<_, i64>(2))
                    .map_err(|_| A2AError::internal("stored execution event budget is corrupt"))?,
            )
            .map_err(|_| A2AError::internal("stored execution budget is corrupt"))?;
            return Ok((row.get(0), budget));
        }
        let budget = intent
            .execution_budget()
            .ok_or_else(|| A2AError::invalid_request("execution quota budget is missing"))?;
        let reservation_id = content_digest(
            format!(
                "execution-reservation-v1\0{}\0{}",
                intent.tenant_scope,
                intent.binding_digest()
            )
            .as_bytes(),
        );
        let lookup = self.q("SELECT binding_digest,policy_id,policy_revision,policy_digest,account_id,principal_scope,operation,task_id,message_id,dispatch_id,reserved_output_bytes,reserved_event_count,reservation_version FROM __S__.quota_execution_reservations WHERE tenant_scope=$1 AND reservation_id=$2");
        if let Some(row) = tx
            .query_opt(&lookup, &[&intent.tenant_scope.as_ref(), &reservation_id])
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("execution reservation lookup failed"),
                )
            })?
        {
            let exact = row.get::<_, String>(0) == intent.binding_digest()
                && row.get::<_, String>(1) == intent.policy_id()
                && row.get::<_, i64>(2) == i64::try_from(intent.policy_revision()).unwrap_or(-1)
                && row.get::<_, String>(3) == intent.policy_digest()
                && row.get::<_, String>(4) == intent.account_id.as_ref()
                && row.get::<_, String>(5) == intent.principal_scope.as_ref()
                && row.get::<_, String>(6) == intent.operation().as_str()
                && row.get::<_, String>(7) == task_id
                && row.get::<_, String>(8) == message_id
                && row.get::<_, String>(9) == dispatch_id
                && row.get::<_, i64>(10) == i64::try_from(budget.max_output_bytes()).unwrap_or(-1)
                && row.get::<_, i64>(11) == i64::try_from(budget.max_event_count()).unwrap_or(-1)
                && row.get::<_, i64>(12) == 1;
            return if exact {
                Ok((reservation_id, budget))
            } else {
                Err(A2AError::invalid_request(
                    "execution reservation key conflict",
                ))
            };
        }
        let insert = self.q("INSERT INTO __S__.quota_execution_reservations(tenant_scope,reservation_id,reservation_version,binding_digest,policy_id,policy_revision,policy_digest,account_id,principal_scope,operation,task_id,message_id,dispatch_id,reserved_output_bytes,reserved_event_count,state,created_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'reserved',$15)");
        tx.execute(
            &insert,
            &[
                &intent.tenant_scope.as_ref(),
                &reservation_id,
                &intent.binding_digest(),
                &intent.policy_id(),
                &i64::try_from(intent.policy_revision())
                    .map_err(|_| A2AError::invalid_request("invalid quota revision"))?,
                &intent.policy_digest(),
                &intent.account_id.as_ref(),
                &intent.principal_scope.as_ref(),
                &intent.operation().as_str(),
                &task_id,
                &message_id,
                &dispatch_id,
                &i64::try_from(budget.max_output_bytes())
                    .map_err(|_| A2AError::invalid_request("invalid output budget"))?,
                &i64::try_from(budget.max_event_count())
                    .map_err(|_| A2AError::invalid_request("invalid event budget"))?,
                &now,
            ],
        )
        .await
        .map_err(|error| {
            Self::transaction_body_error(
                &error,
                A2AError::internal("execution reservation insert failed"),
            )
        })?;
        Ok((reservation_id, budget))
    }

    async fn settle_execution_reservation(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        lease: &OutboxLease,
        reason: &str,
        now: i64,
    ) -> Result<(), A2AError> {
        let Some(reservation) = &lease.execution_reservation else {
            return if self.quota_enforcement {
                Err(A2AError::internal(
                    "terminal workflow has no execution reservation",
                ))
            } else {
                Ok(())
            };
        };
        let measured_sql = self.q("SELECT state,measured_output_bytes,measured_event_count FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 AND task_id=$3 AND quota_reservation_id=$4 FOR UPDATE");
        let measured = tx
            .query_opt(
                &measured_sql,
                &[
                    &lease.tenant_scope,
                    &lease.dispatch_id,
                    &lease.task_id,
                    &reservation.reservation_id,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("execution measurement lookup failed"),
                )
            })?
            .ok_or_else(|| A2AError::internal("terminal workflow has no receiver measurement"))?;
        if measured.get::<_, String>(0) != "completed" {
            return Err(A2AError::internal("receiver measurement is not complete"));
        }
        let actual_output: i64 = measured
            .get::<_, Option<i64>>(1)
            .ok_or_else(|| A2AError::internal("receiver output measurement is missing"))?;
        let actual_events: i64 = measured
            .get::<_, Option<i64>>(2)
            .ok_or_else(|| A2AError::internal("receiver event measurement is missing"))?;
        let reservation_sql = self.q("SELECT state,actual_output_bytes,actual_event_count,binding_digest,reserved_output_bytes,reserved_event_count FROM __S__.quota_execution_reservations WHERE tenant_scope=$1 AND reservation_id=$2 AND reservation_version=$3 AND task_id=$4 AND dispatch_id=$5 FOR UPDATE");
        let row = tx
            .query_one(
                &reservation_sql,
                &[
                    &lease.tenant_scope,
                    &reservation.reservation_id,
                    &i64::try_from(reservation.reservation_version).unwrap_or(i64::MAX),
                    &lease.task_id,
                    &lease.dispatch_id,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("execution reservation settlement lookup failed"),
                )
            })?;
        if row.get::<_, String>(3) != reservation.binding_digest
            || row.get::<_, i64>(4)
                != i64::try_from(reservation.budget.max_output_bytes()).unwrap_or(-1)
            || row.get::<_, i64>(5)
                != i64::try_from(reservation.budget.max_event_count()).unwrap_or(-1)
        {
            return Err(A2AError::internal(
                "execution reservation settlement binding is corrupt",
            ));
        }
        if row.get::<_, String>(0) == "settled" {
            if row.get::<_, Option<i64>>(1) == Some(actual_output)
                && row.get::<_, Option<i64>>(2) == Some(actual_events)
            {
                return Ok(());
            }
            return Err(A2AError::internal(
                "execution reservation settlement conflicts",
            ));
        }
        let receipts = tx.query(
            &self.q("SELECT r.scope_kind,r.scope_id,r.dimension,r.window_start,r.units,i.policy_digest,i.operation FROM __S__.quota_receipts r JOIN __S__.quota_intents i USING(tenant_scope,binding_digest) WHERE r.tenant_scope=$1 AND r.binding_digest=$2 AND r.dimension IN ('outputBytes','eventCount') ORDER BY r.scope_kind,r.dimension"),
            &[&lease.tenant_scope, &reservation.binding_digest],
        ).await.map_err(|error| Self::transaction_body_error(&error, A2AError::internal("execution reservation receipts lookup failed")))?;
        if receipts.len() != 6 {
            return Err(A2AError::internal(
                "execution reservation receipts are corrupt",
            ));
        }
        for receipt in receipts {
            let dimension: String = receipt.get(2);
            let units: i64 = receipt.get(4);
            let actual = if dimension == "outputBytes" {
                actual_output
            } else {
                actual_events
            };
            let refund = units.checked_sub(actual).ok_or_else(|| {
                A2AError::internal("execution reservation measured usage exceeds receipt")
            })?;
            if refund == 0 {
                continue;
            }
            let update = self.q("UPDATE __S__.quota_buckets SET used_units=used_units-$1,updated_at=$2 WHERE tenant_scope=$3 AND policy_digest=$4 AND scope_kind=$5 AND scope_id=$6 AND operation=$7 AND dimension=$8 AND window_start=$9 AND used_units>=$1");
            if tx
                .execute(
                    &update,
                    &[
                        &refund,
                        &now,
                        &lease.tenant_scope,
                        &receipt.get::<_, String>(5),
                        &receipt.get::<_, String>(0),
                        &receipt.get::<_, String>(1),
                        &receipt.get::<_, String>(6),
                        &dimension,
                        &receipt.get::<_, i64>(3),
                    ],
                )
                .await
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("execution reservation refund failed"),
                    )
                })?
                != 1
            {
                return Err(A2AError::internal(
                    "execution reservation refund fence is stale",
                ));
            }
        }
        let settle = self.q("UPDATE __S__.quota_execution_reservations SET state='settled',actual_output_bytes=$1,actual_event_count=$2,settlement_reason=$3,settled_at=$4 WHERE tenant_scope=$5 AND reservation_id=$6 AND state='reserved'");
        if tx
            .execute(
                &settle,
                &[
                    &actual_output,
                    &actual_events,
                    &reason,
                    &now,
                    &lease.tenant_scope,
                    &reservation.reservation_id,
                ],
            )
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("execution reservation settlement failed"),
                )
            })?
            != 1
        {
            return Err(A2AError::internal(
                "execution reservation settlement fence is stale",
            ));
        }
        Ok(())
    }

    async fn reclaim_expired_quota_leases(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        tenant: &str,
        now: i64,
        batch_size: u32,
    ) -> Result<u64, A2AError> {
        if !(1..=1000).contains(&batch_size) {
            return Err(A2AError::invalid_params(
                "quota lease reclaim batch_size must be between 1 and 1000",
            ));
        }
        let batch_size = i64::from(batch_size);
        let sql = self.q("WITH selected AS MATERIALIZED (
          SELECT tenant_scope,lease_id FROM __S__.quota_leases
           WHERE tenant_scope=$1 AND state='active' AND lease_until<=$2
           ORDER BY lease_until,lease_id FOR UPDATE SKIP LOCKED LIMIT $3
        ), expired AS (
          UPDATE __S__.quota_leases l SET state='expired',updated_at=$2 FROM selected s
           WHERE l.tenant_scope=s.tenant_scope AND l.lease_id=s.lease_id
           RETURNING l.binding_digest
        ), released AS (
          SELECT i.policy_digest,i.operation,r.scope_kind,r.scope_id,r.dimension,r.window_start,sum(r.units)::bigint units
            FROM expired e JOIN __S__.quota_receipts r ON r.tenant_scope=$1 AND r.binding_digest=e.binding_digest
            JOIN __S__.quota_intents i ON i.tenant_scope=r.tenant_scope AND i.binding_digest=r.binding_digest
           WHERE r.dimension IN ('concurrentStreams','concurrentSubscriptions')
           GROUP BY i.policy_digest,i.operation,r.scope_kind,r.scope_id,r.dimension,r.window_start
        ), adjusted AS (
          UPDATE __S__.quota_buckets b SET used_units=GREATEST(b.used_units-released.units,0),updated_at=$2
            FROM released WHERE b.tenant_scope=$1 AND b.policy_digest=released.policy_digest
             AND b.operation=released.operation AND b.scope_kind=released.scope_kind
             AND b.scope_id=released.scope_id AND b.dimension=released.dimension
             AND b.window_start=released.window_start RETURNING b.policy_digest
        ) SELECT count(*)::bigint FROM expired");
        let reclaimed: i64 = tx
            .query_one(&sql, &[&tenant, &now, &batch_size])
            .await
            .map_err(|error| {
                Self::transaction_body_error(
                    &error,
                    A2AError::internal("quota lease expiry reclaim failed"),
                )
            })?
            .get(0);
        u64::try_from(reclaimed)
            .map_err(|_| A2AError::internal("quota lease reclaim count is corrupt"))
    }

    async fn append_quota_denial_audit(
        &self,
        intent: &crate::QuotaIntent,
        requested_now: i64,
        retry_after_seconds: i64,
    ) -> Result<(), A2AError> {
        let tenant = intent.tenant_scope.to_string();
        let account = intent.account_id.to_string();
        let decision_key = intent.binding_digest().to_owned();
        let bucket_digest = content_digest(
            format!(
                "{}\0{}\0{}",
                intent.policy_digest(),
                intent.operation().as_str(),
                intent.binding_digest()
            )
            .as_bytes(),
        );
        let reason_digest = content_digest(b"quota-exhausted");
        let content = content_digest(
            format!(
                "{}\0{}\0{}\0{}",
                intent.policy_digest(),
                bucket_digest,
                reason_digest,
                retry_after_seconds
            )
            .as_bytes(),
        );
        self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let tenant = tenant.clone();
            let decision_key = decision_key.clone();
            let content = content.clone();
            let policy_digest = intent.policy_digest().to_owned();
            let bucket_digest = bucket_digest.clone();
            let reason_digest = reason_digest.clone();
            Box::pin(async move {
                let now = store.effective_now(tx, requested_now).await?;
                let insert = store.q("INSERT INTO __S__.quota_denial_audits(tenant_scope,decision_key,content_digest,policy_digest,bucket_digest,reason_digest,retry_after_seconds,denied_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_scope,decision_key) DO NOTHING");
                tx.execute(&insert, &[&tenant,&decision_key,&content,&policy_digest,&bucket_digest,&reason_digest,&retry_after_seconds,&now]).await
                    .map_err(|error| Self::transaction_body_error(&error, crate::quota::quota_authority_unavailable()))?;
                let lookup = store.q("SELECT content_digest,policy_digest,bucket_digest,reason_digest,retry_after_seconds FROM __S__.quota_denial_audits WHERE tenant_scope=$1 AND decision_key=$2");
                let row = tx.query_one(&lookup, &[&tenant,&decision_key]).await
                    .map_err(|error| Self::transaction_body_error(&error, crate::quota::quota_authority_unavailable()))?;
                if row.get::<_, String>(0) != content
                    || row.get::<_, String>(1) != policy_digest
                    || row.get::<_, String>(2) != bucket_digest
                    || row.get::<_, String>(3) != reason_digest
                    || row.get::<_, i64>(4) != retry_after_seconds
                {
                    return Err(crate::quota::quota_authority_unavailable());
                }
                Ok(())
            })
        }).await
    }

    async fn finalize_quota_result<T>(
        &self,
        intent: Option<&crate::QuotaIntent>,
        requested_now: i64,
        result: Result<T, A2AError>,
    ) -> Result<T, A2AError> {
        match result {
            Err(error) if error.code == -32_010 => {
                let Some(intent) = intent else {
                    return Err(crate::quota::quota_authority_unavailable());
                };
                self.append_quota_denial_audit(intent, requested_now, 1)
                    .await
                    .map_err(|_| crate::quota::quota_authority_unavailable())?;
                if let Some(telemetry) = &self.telemetry {
                    telemetry.quota_decision("quota_exceeded", intent.operation().as_str());
                }
                Err(error)
            }
            Ok(value) => {
                if let (Some(telemetry), Some(intent)) = (&self.telemetry, intent) {
                    telemetry.quota_decision("ok", intent.operation().as_str());
                }
                Ok(value)
            }
            Err(error) => {
                if let (Some(telemetry), Some(intent)) = (&self.telemetry, intent) {
                    telemetry.quota_decision("unavailable", intent.operation().as_str());
                }
                Err(error)
            }
        }
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

async fn reconcile_callback_policy(
    client: &mut tokio_postgres::Client,
    schema: &str,
    configured: Option<&crate::push::PushPolicy>,
) -> Result<Option<Arc<crate::CallbackPolicySnapshot>>, PostgresStoreError> {
    client
        .batch_execute("SELECT set_config('smesh.internal_global','callback-worker-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let enabled = configured.filter(|p| p.enabled());
    let count: i64 = client
        .query_one(
            &format!("SELECT count(*) FROM {schema}.callback_policy_snapshots"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);

    let Some(policy) = enabled else {
        return if count == 0 {
            Ok(None)
        } else {
            Err(PostgresStoreError::InvalidSchema)
        };
    };
    let revision =
        i64::try_from(policy.policy_revision()).map_err(|_| PostgresStoreError::InvalidConfig)?;
    let latest = client.query_opt(&format!("SELECT policy_id,policy_revision,policy_digest,max_configs_per_task,max_configs_per_tenant,max_pending,max_payload_bytes,max_attempts,max_delivery_age_ms FROM {schema}.callback_policy_snapshots ORDER BY policy_revision DESC LIMIT 1"), &[])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = latest {
        let old_revision: i64 = row.get(1);
        if row.get::<_, &str>(0) != policy.policy_id()
            || old_revision > revision
            || (old_revision == revision
                && (row.get::<_, &str>(2) != policy.policy_digest()
                    || row.get::<_, i32>(3) != i32::from(policy.max_configs_per_task())
                    || row.get::<_, i64>(4) != i64::from(policy.max_configs_per_tenant())
                    || row.get::<_, i64>(5) != i64::from(policy.max_pending())
                    || row.get::<_, i32>(6) != 262_144
                    || row.get::<_, i32>(7) != i32::from(policy.max_attempts())
                    || row.get::<_, i64>(8)
                        != i64::try_from(policy.max_delivery_age_ms()).unwrap_or(-1)))
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let exists: bool = client.query_one(&format!("SELECT EXISTS(SELECT 1 FROM {schema}.callback_policy_snapshots WHERE policy_id=$1 AND policy_revision=$2)"), &[&policy.policy_id(),&revision])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?.get(0);

    if !exists {
        let tx = client
            .transaction()
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.batch_execute("SELECT set_config('smesh.internal_global','callback-worker-v1',true)")
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&CALLBACK_POLICY_FENCE_LOCK],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let locked_latest = tx.query_opt(&format!("SELECT policy_id,policy_revision,policy_digest,max_configs_per_task,max_configs_per_tenant,max_pending,max_payload_bytes,max_attempts,max_delivery_age_ms FROM {schema}.callback_policy_snapshots ORDER BY policy_revision DESC LIMIT 1"), &[])
            .await.map_err(|_| PostgresStoreError::InvalidSchema)?;
        let install = if let Some(row) = locked_latest {
            let locked_revision: i64 = row.get(1);
            if row.get::<_, &str>(0) != policy.policy_id() || locked_revision > revision {
                return Err(PostgresStoreError::InvalidSchema);
            }
            if locked_revision == revision {
                if row.get::<_, &str>(2) != policy.policy_digest()
                    || row.get::<_, i32>(3) != i32::from(policy.max_configs_per_task())
                    || row.get::<_, i64>(4) != i64::from(policy.max_configs_per_tenant())
                    || row.get::<_, i64>(5) != i64::from(policy.max_pending())
                    || row.get::<_, i32>(6) != 262_144
                    || row.get::<_, i32>(7) != i32::from(policy.max_attempts())
                    || row.get::<_, i64>(8)
                        != i64::try_from(policy.max_delivery_age_ms()).unwrap_or(-1)
                {
                    return Err(PostgresStoreError::InvalidSchema);
                }
                false
            } else {
                true
            }
        } else {
            true
        };
        if install {
            tx.execute(&format!("INSERT INTO {schema}.callback_policy_snapshots VALUES($1,$2,$3,$4,$5,$6,262144,$7,$8,{schema}.db_millis())"), &[&policy.policy_id(),&revision,&policy.policy_digest(),&i32::from(policy.max_configs_per_task()),&i64::from(policy.max_configs_per_tenant()),&i64::from(policy.max_pending()),&i32::from(policy.max_attempts()),&i64::try_from(policy.max_delivery_age_ms()).map_err(|_|PostgresStoreError::InvalidConfig)?])
            .await.map_err(|_| PostgresStoreError::Initialization)?;
            for enrollment in policy.enrollments() {
                let url = enrollment.url().as_str();
                let url_digest = content_digest(url.as_bytes());
                let secret = enrollment.secret_file().to_string_lossy().into_owned();
                let ca = enrollment
                    .ca_file()
                    .map(|p| p.to_string_lossy().into_owned());
                let cert = enrollment
                    .mtls_files()
                    .map(|v| v.0.to_string_lossy().into_owned());
                let key = enrollment
                    .mtls_files()
                    .map(|v| v.1.to_string_lossy().into_owned());
                tx.execute(&format!("INSERT INTO {schema}.callback_enrollments VALUES($1,$2,$3,$4,$2,$5,$6,$7,$8,$9,$10,$11)"), &[&policy.policy_id(),&revision,&enrollment.tenant(),&enrollment.endpoint_id(),&url,&url_digest,&enrollment.key_generation(),&secret,&ca,&cert,&key])
                .await.map_err(|_| PostgresStoreError::Initialization)?;
            }
            // A higher policy revision may remove or replace enrollments. Reconcile
            // before startup can advertise readiness. Live leases are never revoked:
            // they make startup fail until database-time expiry; all other retained
            // work is atomically canceled and its config revoked.
            let removed_predicate = format!(
                "NOT EXISTS(SELECT 1 FROM {schema}.callback_enrollments n WHERE n.policy_id=$1 AND n.policy_revision=$2 AND n.tenant_scope=c.tenant_scope AND n.enrollment_id=c.enrollment_id AND n.enrollment_generation=c.enrollment_generation AND n.canonical_url=c.canonical_url)"
            );
            let active_removed_lease = tx
            .query_one(
                &format!("SELECT EXISTS(SELECT 1 FROM {schema}.callback_configs c JOIN {schema}.callback_deliveries d USING(tenant_scope,task_id,config_id) WHERE {removed_predicate} AND d.state='leased' AND d.lease_until>{schema}.db_millis())"),
                &[&policy.policy_id(), &revision],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
            .get::<_, bool>(0);
            if active_removed_lease {
                return Err(PostgresStoreError::Initialization);
            }
            tx.execute(
            &format!("UPDATE {schema}.callback_deliveries d SET state='canceled',lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at={schema}.db_millis() FROM {schema}.callback_configs c WHERE d.tenant_scope=c.tenant_scope AND d.task_id=c.task_id AND d.config_id=c.config_id AND {removed_predicate} AND (d.state IN ('pending','retry') OR (d.state='leased' AND d.lease_until<={schema}.db_millis()))"),
            &[&policy.policy_id(), &revision],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
            tx.execute(
            &format!("UPDATE {schema}.callback_configs c SET state='revoked',updated_at={schema}.db_millis() WHERE {removed_predicate} AND c.state IN ('active','draining','terminal_closed')"),
            &[&policy.policy_id(), &revision],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        }
        tx.commit()
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
    }
    client
        .batch_execute("SELECT set_config('smesh.internal_global','callback-worker-v1',false)")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let enrollment_count: i64 = client.query_one(&format!("SELECT count(*) FROM {schema}.callback_enrollments WHERE policy_id=$1 AND policy_revision=$2"), &[&policy.policy_id(),&revision])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?.get(0);

    client
        .batch_execute("SELECT set_config('smesh.internal_global','',false)")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if enrollment_count
        != i64::try_from(policy.enrollments().len())
            .map_err(|_| PostgresStoreError::InvalidConfig)?
    {
        return Err(PostgresStoreError::InvalidSchema);
    }
    crate::CallbackPolicySnapshot::new_with_tenant_cap(
        policy.policy_id(),
        policy.policy_revision(),
        policy.policy_digest(),
        policy.max_configs_per_task(),
        policy.max_configs_per_tenant(),
        policy.max_pending(),
        262_144,
        policy.max_attempts(),
        policy.max_delivery_age_ms(),
    )
    .map(Arc::new)
    .map(Some)
    .map_err(|_| PostgresStoreError::InvalidSchema)
}

async fn reconcile_quota_policy(
    client: &mut tokio_postgres::Client,
    schema: &str,
    configured: Option<&crate::QuotaPolicy>,
    plan: Option<&crate::QuotaReconciliationPlan>,
) -> Result<(), PostgresStoreError> {
    let Some(configured) = configured else {
        return Ok(());
    };
    // ALLOWLIST: policy reconciliation is startup-only, advisory-fenced, and atomically audited.
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    tx.batch_execute("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='15s'; SELECT set_config('smesh.internal_global','reconcile-v1',true); SELECT pg_advisory_xact_lock(6001136200064)")
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    let rows = tx.query(
        &format!("SELECT DISTINCT ON (tenant_scope) tenant_scope,policy_id,policy_revision,policy_digest,canonical_json FROM {schema}.quota_policy_versions ORDER BY tenant_scope,policy_revision DESC"),
        &[],
    ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in rows {
        let tenant: String = row.get(0);
        let policy_id: String = row.get(1);
        let revision: i64 = row.get(2);
        let digest: String = row.get(3);
        let canonical: String = row.get(4);
        let configured_revision =
            i64::try_from(configured.revision()).map_err(|_| PostgresStoreError::InvalidSchema)?;
        if policy_id != configured.policy_id() || configured_revision < revision {
            return Err(PostgresStoreError::InvalidSchema);
        }
        if configured_revision == revision {
            if digest != configured.digest() {
                return Err(PostgresStoreError::InvalidSchema);
            }
            continue;
        }
        let old = crate::QuotaPolicy::from_json(canonical.as_bytes())
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let now: i64 = tx
            .query_one(&format!("SELECT {schema}.db_millis()"), &[])
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .get(0);
        let lowered = configured.lowered_limits_from(&old);
        if !lowered.is_empty() {
            let Some(plan) = plan else {
                return Err(PostgresStoreError::ReconciliationRequired);
            };
            if plan.effective_at > now
                || lowered.iter().any(|(scope, dimension)| {
                    !plan.authorizes(&tenant, &digest, configured.digest(), *scope, *dimension)
                })
            {
                return Err(PostgresStoreError::ReconciliationRequired);
            }
        }
        let buckets = tx.query(
            &format!("SELECT scope_kind,scope_id,operation,dimension,algorithm,window_start,window_millis,used_units,updated_at,available_tokens,last_refill_at,refill_remainder FROM {schema}.quota_buckets WHERE tenant_scope=$1 AND policy_digest=$2 ORDER BY scope_kind,scope_id,operation,dimension,window_start FOR UPDATE"),
            &[&tenant, &digest],
        ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
        for bucket in buckets {
            let scope_text: String = bucket.get(0);
            let dimension_text: String = bucket.get(3);
            let scope = match scope_text.as_str() {
                "tenant" => crate::QuotaScopeKind::Tenant,
                "account" => crate::QuotaScopeKind::Account,
                "principal" => crate::QuotaScopeKind::Principal,
                _ => return Err(PostgresStoreError::InvalidSchema),
            };
            let dimension = quota_dimension_from_str(&dimension_text)
                .ok_or(PostgresStoreError::InvalidSchema)?;
            let operation: String = bucket.get(2);
            if matches!(
                dimension,
                crate::QuotaDimension::ConcurrentActiveWork
                    | crate::QuotaDimension::ConcurrentStreams
                    | crate::QuotaDimension::ConcurrentSubscriptions
            ) || (matches!(
                dimension,
                crate::QuotaDimension::OutputBytes | crate::QuotaDimension::EventCount
            ) && matches!(operation.as_str(), "taskCreate" | "taskContinue"))
            {
                continue;
            }
            let capacity = i64::try_from(configured.limit(dimension, scope))
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            let algorithm: String = bucket.get(4);
            let old_available: Option<i64> = bucket.get(9);
            let available = old_available.map(|value| value.min(capacity));
            let used: i64 = if algorithm == "tokenBucket" {
                capacity - available.ok_or(PostgresStoreError::InvalidSchema)?
            } else {
                bucket.get(7)
            };
            if used > capacity {
                return Err(PostgresStoreError::ReconciliationRequired);
            }
            tx.execute(
                &format!("INSERT INTO {schema}.quota_buckets(tenant_scope,policy_digest,scope_kind,scope_id,operation,dimension,algorithm,window_start,window_millis,capacity,used_units,available_tokens,last_refill_at,refill_numerator,refill_period_millis,refill_remainder,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint,$10,$11,$12,$13,CASE WHEN $7::text='tokenBucket' THEN $10::bigint END,CASE WHEN $7::text='tokenBucket' THEN $9::bigint END,$14,$15) ON CONFLICT DO NOTHING"),
                &[&tenant,&configured.digest(),&scope_text,&bucket.get::<_,String>(1),&bucket.get::<_,String>(2),&dimension_text,&algorithm,&bucket.get::<_,i64>(5),&bucket.get::<_,Option<i64>>(6),&capacity,&used,&available,&bucket.get::<_,Option<i64>>(10),&bucket.get::<_,Option<i64>>(11),&bucket.get::<_,i64>(8)],
            ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
        }
        for (scope, dimension) in &lowered {
            let limit = i64::try_from(configured.limit(*dimension, *scope))
                .map_err(|_| PostgresStoreError::InvalidSchema)?;
            if *dimension == crate::QuotaDimension::RetainedAuthorityBytes {
                let kind = match scope {
                    crate::QuotaScopeKind::Tenant => "tenant",
                    crate::QuotaScopeKind::Account => "account",
                    crate::QuotaScopeKind::Principal => "principal",
                };
                let over: bool = tx.query_one(
                    &format!("SELECT EXISTS(SELECT 1 FROM {schema}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind=$2 AND retained_bytes>$3)"),
                    &[&tenant,&kind,&limit],
                ).await.map_err(|_| PostgresStoreError::InvalidSchema)?.get(0);
                if over {
                    return Err(PostgresStoreError::ReconciliationRequired);
                }
            }
        }
        tx.execute(
            &format!("UPDATE {schema}.quota_policy_versions SET lifecycle='draining',retired_at=$3 WHERE tenant_scope=$1 AND policy_digest=$2 AND lifecycle='active'"),
            &[&tenant,&digest,&now],
        ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
        tx.execute(
            &format!("INSERT INTO {schema}.quota_policy_versions(tenant_scope,policy_id,policy_revision,policy_digest,canonical_json,created_at) VALUES($1,$2,$3,$4,$5,$6)"),
            &[&tenant,&configured.policy_id(),&configured_revision,&configured.digest(),&configured.canonical_json(),&now],
        ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;

        if !lowered.is_empty() {
            let plan = plan.expect("lowered policy checked above");
            let targets = serde_json::to_string(
                &lowered
                    .iter()
                    .map(|(scope, dimension)| (scope.as_str(), dimension.as_str()))
                    .collect::<Vec<_>>(),
            )
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
            let actor_digest = content_digest(plan.actor.as_bytes());
            let reason_digest = content_digest(plan.reason.as_bytes());
            let id = content_digest(format!("quota-reconciliation-v1\0{tenant}\0{digest}\0{}\0{actor_digest}\0{reason_digest}\0{}\0{targets}",configured.digest(),plan.effective_at).as_bytes());
            tx.execute(
                &format!("INSERT INTO {schema}.quota_policy_reconciliation_audits(tenant_scope,reconciliation_id,old_policy_revision,old_policy_digest,new_policy_revision,new_policy_digest,actor_digest,reason_digest,action,targets_json,effective_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'drain',$9,$10,$11) ON CONFLICT(tenant_scope,old_policy_digest,new_policy_digest) DO NOTHING"),
                &[&tenant,&id,&revision,&digest,&configured_revision,&configured.digest(),&actor_digest,&reason_digest,&targets,&plan.effective_at,&now],
            ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
        }
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::Initialization)
}

fn quota_dimension_from_str(value: &str) -> Option<crate::QuotaDimension> {
    Some(match value {
        "requestCount" => crate::QuotaDimension::RequestCount,
        "concurrentActiveWork" => crate::QuotaDimension::ConcurrentActiveWork,
        "inputBytes" => crate::QuotaDimension::InputBytes,
        "outputBytes" => crate::QuotaDimension::OutputBytes,
        "eventCount" => crate::QuotaDimension::EventCount,
        "concurrentStreams" => crate::QuotaDimension::ConcurrentStreams,
        "concurrentSubscriptions" => crate::QuotaDimension::ConcurrentSubscriptions,
        "reconnectCount" => crate::QuotaDimension::ReconnectCount,
        "retainedAuthorityBytes" => crate::QuotaDimension::RetainedAuthorityBytes,
        _ => return None,
    })
}

async fn validate_runtime_login(
    client: &tokio_postgres::Client,
    schema: &str,
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
    let generated_role = format!("{schema}_runtime");
    let generated_exists: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)",
            &[&generated_role],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    let migrator_user: String = client
        .query_one("SELECT current_user", &[])
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    let memberships = client
        .query(
            "SELECT member.rolname,parent.rolname,am.admin_option,am.inherit_option,am.set_option
             FROM pg_auth_members am
             JOIN pg_roles member ON member.oid=am.member
             JOIN pg_roles parent ON parent.oid=am.roleid
             WHERE member.rolname=$1 OR parent.rolname=$1
             ORDER BY member.rolname,parent.rolname",
            &[&generated_role],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    if !generated_exists {
        if !memberships.is_empty() {
            return Err(PostgresStoreError::InvalidSchema);
        }
        return Ok(());
    }
    if memberships.len() != 2
        || !memberships.iter().any(|membership| {
            membership.get::<_, &str>(0) == runtime_user
                && membership.get::<_, &str>(1) == generated_role
                && !membership.get::<_, bool>(2)
                && !membership.get::<_, bool>(3)
                && membership.get::<_, bool>(4)
        })
        || !memberships.iter().any(|membership| {
            membership.get::<_, &str>(0) == migrator_user
                && membership.get::<_, &str>(1) == generated_role
                && membership.get::<_, bool>(2)
                && !membership.get::<_, bool>(3)
                && !membership.get::<_, bool>(4)
        })
    {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let sibling_memberships = client
        .query(
            "SELECT parent.rolname,am.admin_option,am.inherit_option,am.set_option,
                    parent.rolsuper,parent.rolinherit,parent.rolcreaterole,parent.rolcreatedb,
                    parent.rolcanlogin,parent.rolreplication,parent.rolbypassrls,
                    EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname=left(parent.rolname,length(parent.rolname)-8)),
                    EXISTS(SELECT 1 FROM pg_namespace n
                           JOIN pg_auth_members owner_edge ON owner_edge.member=n.nspowner
                           WHERE n.nspname=left(parent.rolname,length(parent.rolname)-8)
                             AND owner_edge.roleid=parent.oid
                             AND owner_edge.admin_option AND NOT owner_edge.inherit_option
                             AND NOT owner_edge.set_option)
             FROM pg_auth_members am
             JOIN pg_roles member ON member.oid=am.member
             JOIN pg_roles parent ON parent.oid=am.roleid
             WHERE member.rolname=$1 AND parent.rolname<>$2
             ORDER BY parent.rolname",
            &[&runtime_user, &generated_role],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    if sibling_memberships.iter().any(|membership| {
        let role = membership.get::<_, &str>(0);
        !role.ends_with("_runtime")
            || membership.get::<_, bool>(1)
            || membership.get::<_, bool>(2)
            || !membership.get::<_, bool>(3)
            || membership.get::<_, bool>(4)
            || membership.get::<_, bool>(5)
            || membership.get::<_, bool>(6)
            || membership.get::<_, bool>(7)
            || membership.get::<_, bool>(8)
            || membership.get::<_, bool>(9)
            || membership.get::<_, bool>(10)
            || !membership.get::<_, bool>(11)
            || !membership.get::<_, bool>(12)
    }) {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let walk = client
        .query(
            "WITH RECURSIVE membership_walk(root_oid,role_oid,path,cycle,depth) AS (
               SELECT r.oid,r.oid,ARRAY[r.oid],false,0 FROM pg_roles r WHERE r.rolname=$1
               UNION ALL
               SELECT w.root_oid,am.roleid,w.path||am.roleid,am.roleid=ANY(w.path),w.depth+1
                 FROM membership_walk w JOIN pg_auth_members am ON am.member=w.role_oid
                WHERE NOT w.cycle AND w.depth<64
             )
             SELECT root.rolname,role.rolname,w.cycle,w.depth,
                    role.rolsuper,role.rolinherit,role.rolcreaterole,role.rolcreatedb,
                    role.rolcanlogin,role.rolreplication,role.rolbypassrls
               FROM membership_walk w JOIN pg_roles root ON root.oid=w.root_oid
               JOIN pg_roles role ON role.oid=w.role_oid ORDER BY root.rolname,w.depth,role.rolname",
            &[&generated_role],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    for entry in walk {
        let role: &str = entry.get(1);
        let cycle: bool = entry.get(2);
        let depth: i32 = entry.get(3);
        if cycle || depth > 0 {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let privileged = entry.get::<_, bool>(4)
            || entry.get::<_, bool>(6)
            || entry.get::<_, bool>(7)
            || entry.get::<_, bool>(9)
            || entry.get::<_, bool>(10);
        let inappropriate_login = role != runtime_user && entry.get::<_, bool>(8);
        let inappropriate_inherit = entry.get::<_, bool>(5);
        if privileged || inappropriate_login || inappropriate_inherit {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    Ok(())
}

async fn callback_retained_oracle_total(
    tx: &tokio_postgres::Transaction<'_>,
    schema: &str,
    tenant: &str,
    scope_kind: &str,
    scope_id: &str,
) -> Result<i64, PostgresStoreError> {
    let (base, artifact, callback, argument): (&str, &str, &str, Option<&str>) = match scope_kind {
        "tenant" => (
            "retained_authority_oracle",
            "artifact_retained_oracle",
            "callback_retained_oracle",
            None,
        ),
        "account" => (
            "retained_authority_account_oracle",
            "artifact_retained_account_oracle",
            "callback_retained_account_oracle",
            Some(scope_id),
        ),
        "principal" => (
            "retained_authority_oracle",
            "artifact_retained_oracle",
            "callback_retained_oracle",
            Some(scope_id),
        ),
        _ => return Err(PostgresStoreError::InvalidSchema),
    };
    tx.batch_execute("SET LOCAL smesh.internal_global='diag-v1'")
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    let base: i64 = tx
        .query_one(
            &format!("SELECT {schema}.{base}($1,$2)"),
            &[&tenant, &argument],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    tx.batch_execute("SET LOCAL smesh.internal_global='claim-v1'")
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    let artifact: i64 = tx
        .query_one(
            &format!("SELECT {schema}.{artifact}($1,$2)"),
            &[&tenant, &argument],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    tx.batch_execute("SET LOCAL smesh.internal_global='callback-worker-v1'")
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    let callback: i64 = tx
        .query_one(
            &format!("SELECT {schema}.{callback}($1,$2)"),
            &[&tenant, &argument],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?
        .get(0);
    base.checked_add(artifact)
        .and_then(|value| value.checked_add(callback))
        .ok_or(PostgresStoreError::InvalidSchema)
}

async fn reconcile_callback_retained_usage(
    tx: &tokio_postgres::Transaction<'_>,
    schema: &str,
) -> Result<(), PostgresStoreError> {
    let tenants = tx
        .query(
            &format!("SELECT * FROM {schema}.authority_tenants_bounded()"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    for row in tenants {
        let tenant: String = row.get(0);
        tx.query_one(
            "SELECT set_config('smesh.tenant_scope',$1,true)",
            &[&tenant],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let mut accounts = BTreeSet::new();
        let mut principals = BTreeSet::new();
        tx.batch_execute("SET LOCAL smesh.internal_global='diag-v1'")
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        for scope in tx
            .query(
                &format!("SELECT * FROM {schema}.authority_retained_scopes_bounded($1,'account')"),
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
        {
            accounts.insert(scope.get::<_, String>(0));
        }
        for scope in tx
            .query(
                &format!(
                    "SELECT * FROM {schema}.authority_retained_scopes_bounded($1,'principal')"
                ),
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
        {
            principals.insert(scope.get::<_, String>(0));
        }
        tx.batch_execute("SET LOCAL smesh.internal_global='callback-worker-v1'")
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        for scope in tx
            .query(
                &format!("SELECT * FROM {schema}.callback_retained_scopes_bounded($1,'account')"),
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
        {
            accounts.insert(scope.get::<_, String>(0));
        }
        for scope in tx
            .query(
                &format!("SELECT * FROM {schema}.callback_retained_scopes_bounded($1,'principal')"),
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
        {
            principals.insert(scope.get::<_, String>(0));
        }
        for row in tx
            .query(
                &format!("SELECT scope_kind,scope_id FROM {schema}.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind IN ('account','principal')"),
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::Initialization)?
        {
            match row.get::<_, &str>(0) {
                "account" => {
                    accounts.insert(row.get::<_, String>(1));
                }
                "principal" => {
                    principals.insert(row.get::<_, String>(1));
                }
                _ => return Err(PostgresStoreError::InvalidSchema),
            }
        }
        let upsert = format!(
            "INSERT INTO {schema}.retained_authority_usage(tenant_scope,scope_kind,scope_id,retained_bytes,updated_at) VALUES($1,$2,$3,$4,{schema}.db_millis()) ON CONFLICT(tenant_scope,scope_kind,scope_id) DO UPDATE SET retained_bytes=EXCLUDED.retained_bytes,updated_at=EXCLUDED.updated_at"
        );
        let tenant_total =
            callback_retained_oracle_total(tx, schema, &tenant, "tenant", &tenant).await?;
        tx.execute(&upsert, &[&tenant, &"tenant", &tenant, &tenant_total])
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        for account in accounts {
            let total =
                callback_retained_oracle_total(tx, schema, &tenant, "account", &account).await?;
            tx.execute(&upsert, &[&tenant, &"account", &account, &total])
                .await
                .map_err(|_| PostgresStoreError::Initialization)?;
        }
        for principal in principals {
            let total =
                callback_retained_oracle_total(tx, schema, &tenant, "principal", &principal)
                    .await?;
            tx.execute(&upsert, &[&tenant, &"principal", &principal, &total])
                .await
                .map_err(|_| PostgresStoreError::Initialization)?;
        }
    }
    tx.batch_execute("SET LOCAL smesh.internal_global=''; SET LOCAL smesh.tenant_scope='' ")
        .await
        .map_err(|_| PostgresStoreError::Initialization)
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
        tx.batch_execute(&format!(
            "GRANT {role} TO {runtime_user} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE"
        ))
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
    let distributed_quota_checksum = content_digest(DISTRIBUTED_QUOTA_MIGRATION_SQL.as_bytes());
    let distributed_quota_row = tx
        .query_opt(
            &format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=4"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = distributed_quota_row {
        if row.get::<_, i64>(0) != LOGICAL_SCHEMA_VERSION
            || row.get::<_, String>(1) != distributed_quota_checksum
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let sql = DISTRIBUTED_QUOTA_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(4,6,$1,$2,{schema}.db_millis())"
            ),
            &[
                &DISTRIBUTED_QUOTA_MIGRATION_NAME,
                &distributed_quota_checksum,
            ],
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
    let artifact_checksum = content_digest(ARTIFACT_MIGRATION_SQL.as_bytes());
    let artifact_row = tx
        .query_opt(
            &format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=5"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = artifact_row {
        if row.get::<_, i64>(0) != LOGICAL_SCHEMA_VERSION
            || row.get::<_, String>(1) != artifact_checksum
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let sql = ARTIFACT_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(5,6,$1,$2,{schema}.db_millis())"
            ),
            &[&ARTIFACT_MIGRATION_NAME, &artifact_checksum],
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
    let audit_checksum = content_digest(AUDIT_PROJECTION_MIGRATION_SQL.as_bytes());
    let audit_row = tx.query_opt(&format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=6"), &[])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = audit_row {
        if row.get::<_, i64>(0) != LOGICAL_SCHEMA_VERSION
            || row.get::<_, String>(1) != audit_checksum
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let sql = AUDIT_PROJECTION_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(6,6,$1,$2,{schema}.db_millis())"
            ),
            &[&AUDIT_PROJECTION_MIGRATION_NAME, &audit_checksum],
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
    let callback_checksum = content_digest(CALLBACK_MIGRATION_SQL.as_bytes());
    let callback_row = tx.query_opt(&format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=7"), &[])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = callback_row {
        if row.get::<_, i64>(0) != 7 || row.get::<_, String>(1) != callback_checksum {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let sql = CALLBACK_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(7,7,$1,$2,{schema}.db_millis())"
            ),
            &[&CALLBACK_MIGRATION_NAME, &callback_checksum],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let catalog = catalog_digest(&tx, schema).await?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata DISABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(&format!("UPDATE {schema}.store_metadata SET schema_version=7,catalog_hash=$1 WHERE singleton=1"), &[&catalog])
            .await.map_err(|_| PostgresStoreError::Initialization)?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata ENABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    }
    let callback_fence_checksum = content_digest(CALLBACK_POLICY_FENCE_MIGRATION_SQL.as_bytes());
    let callback_fence_row = tx.query_opt(&format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=8"), &[])
        .await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = callback_fence_row {
        if row.get::<_, i64>(0) != 8 || row.get::<_, String>(1) != callback_fence_checksum {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let metadata = tx
            .query_one(
                &format!("SELECT schema_version,catalog_hash FROM {schema}.store_metadata WHERE singleton=1"),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let sealed_catalog: String = metadata.get(1);
        if metadata.get::<_, i64>(0) != 7 || sealed_catalog != catalog_digest(&tx, schema).await? {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let sql = CALLBACK_POLICY_FENCE_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"));
        tx.batch_execute(&sql)
            .await
            .map_err(|_| PostgresStoreError::Initialization)?;
        reconcile_callback_retained_usage(&tx, schema).await?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(8,8,$1,$2,{schema}.db_millis())"
            ),
            &[
                &CALLBACK_POLICY_FENCE_MIGRATION_NAME,
                &callback_fence_checksum,
            ],
        )
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        let catalog = catalog_digest(&tx, schema).await?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata DISABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
        tx.execute(&format!("UPDATE {schema}.store_metadata SET schema_version=8,catalog_hash=$1 WHERE singleton=1"), &[&catalog])
            .await.map_err(|_| PostgresStoreError::Initialization)?;
        tx.batch_execute(&format!(
            "ALTER TABLE {schema}.store_metadata ENABLE TRIGGER store_metadata_immutable"
        ))
        .await
        .map_err(|_| PostgresStoreError::Initialization)?;
    }
    let authorization_retention_checksum =
        content_digest(AUTHORIZATION_RETENTION_MIGRATION_SQL.as_bytes());
    let authorization_retention_row = tx
        .query_opt(
            &format!("SELECT logical_schema_version,checksum FROM {schema}.schema_migrations WHERE revision=9"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    if let Some(row) = authorization_retention_row {
        if row.get::<_, i64>(0) != CURRENT_SCHEMA_VERSION
            || row.get::<_, String>(1) != authorization_retention_checksum
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    } else {
        let metadata = tx
            .query_one(
                &format!("SELECT schema_version,catalog_hash FROM {schema}.store_metadata WHERE singleton=1"),
                &[],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let sealed_catalog: String = metadata.get(1);
        if metadata.get::<_, i64>(0) != 8 || sealed_catalog != catalog_digest(&tx, schema).await? {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let sql = AUTHORIZATION_RETENTION_MIGRATION_SQL
            .replace("__SCHEMA__", schema)
            .replace("__ROLE__", &format!("{schema}_runtime"))
            .replace("__MIGRATOR__", &migrator_user.replace('\'', "''"));
        tx.batch_execute(&sql)
            .await
            .inspect_err(|error| {
                eprintln!("smesh.postgres.migration_failed revision=9 error={error:?}");
            })
            .map_err(|_| PostgresStoreError::Initialization)?;
        reconcile_callback_retained_usage(&tx, schema).await?;
        tx.execute(
            &format!(
                "INSERT INTO {schema}.schema_migrations VALUES(9,9,$1,$2,{schema}.db_millis())"
            ),
            &[
                &AUTHORIZATION_RETENTION_MIGRATION_NAME,
                &authorization_retention_checksum,
            ],
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
            &format!("UPDATE {schema}.store_metadata SET schema_version=9,catalog_hash=$1 WHERE singleton=1"),
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

async fn validate_artifact_semantics<C>(client: &C, schema: &str) -> Result<(), PostgresStoreError>
where
    C: tokio_postgres::GenericClient + Sync,
{
    // manifest canonical seal: canonical bytes, digest, producer, classification and policy binding.
    let manifests = client
        .query(
            &format!("SELECT m.artifact_id,m.manifest_digest,m.canonical_json,m.owner_account_id,m.task_id,m.context_id,m.message_id,m.dispatch_id,m.media_type,m.plaintext_length,m.classification,m.encryption_domain,m.policy_id,m.policy_revision,m.policy_digest,m.created_at,m.retain_until,o.content_digest,o.key_generation,m.tenant_scope FROM {schema}.artifact_manifests m JOIN {schema}.content_objects o USING(tenant_scope,object_id)"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in manifests {
        let canonical: String = row.get(2);
        let value: serde_json::Value =
            serde_json::from_str(&canonical).map_err(|_| PostgresStoreError::InvalidSchema)?;
        let producer = value
            .get("producer")
            .ok_or(PostgresStoreError::InvalidSchema)?;
        let policy = value
            .get("policy")
            .ok_or(PostgresStoreError::InvalidSchema)?;
        let mut sealed = b"smesh-artifact-manifest/v1\0".to_vec();
        sealed.extend_from_slice(canonical.as_bytes());
        if content_digest(&sealed) != row.get::<_, String>(1)
            || value.get("schema").and_then(serde_json::Value::as_str)
                != Some("smesh-artifact-manifest/v1")
            || value.get("artifactId").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(0))
            || value.get("mediaType").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(8))
            || value
                .get("plaintextLength")
                .and_then(serde_json::Value::as_i64)
                != Some(row.get(9))
            || value
                .get("classification")
                .and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(10))
            || value
                .get("encryptionDomain")
                .and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(11))
            || value
                .get("contentDigest")
                .and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(17))
            || producer.get("owner").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(3))
            || producer.get("tenant").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(19))
            || producer.get("task").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(4))
            || producer.get("context").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(5))
            || producer.get("message").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(6))
            || producer.get("dispatch").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(7))
            || policy.get("policyId").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(12))
            || policy.get("revision").and_then(serde_json::Value::as_i64) != Some(row.get(13))
            || policy.get("digest").and_then(serde_json::Value::as_str)
                != Some(row.get::<_, &str>(14))
            || policy.get("createdAt").and_then(serde_json::Value::as_i64) != Some(row.get(15))
            || policy
                .get("retainUntil")
                .and_then(serde_json::Value::as_i64)
                != Some(row.get(16))
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let chunks = value
            .get("chunks")
            .and_then(serde_json::Value::as_array)
            .ok_or(PostgresStoreError::InvalidSchema)?;
        let artifact_id: &str = row.get(0);
        let tenant_scope: &str = row.get(19);
        let chunk_rows = client
            .query(
                &format!("SELECT ordinal,byte_offset,plaintext_length,content_digest FROM {schema}.artifact_chunks WHERE tenant_scope=$1 AND artifact_id=$2 ORDER BY ordinal"),
                &[&tenant_scope, &artifact_id],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        if chunks.len() != chunk_rows.len()
            || chunks.iter().zip(&chunk_rows).any(|(chunk, stored)| {
                chunk.get("ordinal").and_then(serde_json::Value::as_i64)
                    != Some(i64::from(stored.get::<_, i32>(0)))
                    || chunk.get("offset").and_then(serde_json::Value::as_i64)
                        != Some(stored.get(1))
                    || chunk.get("length").and_then(serde_json::Value::as_i64)
                        != Some(stored.get(2))
                    || chunk.get("digest").and_then(serde_json::Value::as_str)
                        != Some(stored.get::<_, &str>(3))
            })
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
        let provenance = value
            .get("derivedFrom")
            .and_then(serde_json::Value::as_array)
            .ok_or(PostgresStoreError::InvalidSchema)?;
        let provenance_rows = client
            .query(
                &format!("SELECT parent_artifact_id,relation FROM {schema}.provenance_edges WHERE tenant_scope=$1 AND child_artifact_id=$2 ORDER BY ordinal"),
                &[&tenant_scope, &artifact_id],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?;
        if provenance.len() != provenance_rows.len()
            || provenance
                .iter()
                .zip(&provenance_rows)
                .any(|(edge, stored)| {
                    edge.get("artifactId").and_then(serde_json::Value::as_str)
                        != Some(stored.get::<_, &str>(0))
                        || edge.get("relation").and_then(serde_json::Value::as_str)
                            != Some(stored.get::<_, &str>(1))
                })
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    // chunk topology; reference count; locator grammar; object lifecycle; upload lease;
    // read lease; backup lease; retention hold; tombstone generation.
    let invalid: i64 = client.query_one(&format!(r"SELECT
      (SELECT count(*) FROM (
        SELECT m.tenant_scope,m.artifact_id,m.plaintext_length,
          count(c.*) chunks,COALESCE(sum(c.plaintext_length),0) bytes,
          bool_and(c.ordinal=row_number_placeholder.expected_ordinal AND c.byte_offset=row_number_placeholder.expected_offset AND c.plaintext_length BETWEEN 1 AND 4194304) topology
        FROM {schema}.artifact_manifests m
        LEFT JOIN {schema}.artifact_chunks c USING(tenant_scope,artifact_id)
        LEFT JOIN LATERAL (SELECT count(*)::integer AS expected_ordinal,COALESCE(sum(p.plaintext_length),0) AS expected_offset FROM {schema}.artifact_chunks p WHERE p.tenant_scope=c.tenant_scope AND p.artifact_id=c.artifact_id AND p.ordinal<c.ordinal) row_number_placeholder ON true
        GROUP BY m.tenant_scope,m.artifact_id,m.plaintext_length
      ) x WHERE bytes<>plaintext_length OR (plaintext_length=0 AND chunks<>0) OR (plaintext_length>0 AND (chunks=0 OR topology IS NOT TRUE)))
      +(SELECT count(*) FROM {schema}.content_objects o WHERE o.reference_count<>(SELECT count(*) FROM {schema}.artifact_references r JOIN {schema}.artifact_manifests m USING(tenant_scope,artifact_id) WHERE m.tenant_scope=o.tenant_scope AND m.object_id=o.object_id AND r.state='active'))
      +(SELECT count(*) FROM {schema}.content_objects o WHERE backend_locator!~'^objects/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$' OR encryption_domain NOT LIKE tenant_scope||'/%' OR (state='available' AND available_at IS NULL) OR (state='staged' AND available_at IS NOT NULL) OR (state IN ('tombstoned','deleting','deleted') AND tombstone_generation=0))
      +(SELECT count(*) FROM {schema}.content_objects o JOIN {schema}.artifact_manifests m USING(tenant_scope,object_id) WHERE o.plaintext_length<>m.plaintext_length OR o.classification<>m.classification OR o.encryption_domain<>m.encryption_domain)
      +(SELECT count(*) FROM {schema}.upload_intents u JOIN {schema}.content_objects o USING(tenant_scope,object_id) WHERE u.artifact_id NOT IN (SELECT artifact_id FROM {schema}.artifact_manifests m WHERE m.tenant_scope=u.tenant_scope AND m.object_id=u.object_id) OR u.stage_locator!~'^stage/[A-Za-z0-9_-]{{32}}[.]tmp$' OR u.final_locator<>o.backend_locator OR u.ciphertext_digest<>o.ciphertext_digest OR u.ciphertext_length<>o.ciphertext_length OR (u.state='promoting')<>(u.lease_token IS NOT NULL AND u.lease_until IS NOT NULL))
      +(SELECT count(*) FROM {schema}.artifact_read_leases WHERE lease_token='' OR lease_epoch<=0 OR lease_until<=created_at)
      +(SELECT count(*) FROM {schema}.artifact_backup_leases WHERE lease_owner='' OR lease_token='' OR lease_epoch<=0 OR lease_until<=created_at)
      +(SELECT count(*) FROM {schema}.artifact_retention_holds WHERE actor_digest='' OR reason_digest='' OR (expires_at IS NOT NULL AND expires_at<=created_at) OR (state='released')<>(released_at IS NOT NULL))
      +(SELECT count(*) FROM {schema}.artifact_tombstones t LEFT JOIN {schema}.content_objects o USING(tenant_scope,object_id) WHERE o.object_id IS NULL OR t.tombstone_generation<=0 OR t.tombstone_generation>o.tombstone_generation)
      +(SELECT count(*) FROM {schema}.artifact_gc_jobs j JOIN {schema}.content_objects o USING(tenant_scope,object_id) WHERE j.tombstone_generation<>o.tombstone_generation OR (j.state='leased')<>(j.lease_owner IS NOT NULL AND j.lease_token IS NOT NULL AND j.lease_until IS NOT NULL))"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?.get(0);
    if invalid != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
    // provenance acyclic and cross-domain/classification monotonicity.
    let invalid_provenance: i64 = client.query_one(&format!(r"WITH RECURSIVE walk(tenant_scope,start_id,node,path,cycle) AS (
      SELECT p.tenant_scope,p.child_artifact_id,p.parent_artifact_id,ARRAY[p.child_artifact_id,p.parent_artifact_id],false FROM {schema}.provenance_edges p
      UNION ALL SELECT w.tenant_scope,w.start_id,p.parent_artifact_id,w.path||p.parent_artifact_id,p.parent_artifact_id=ANY(w.path)
      FROM walk w JOIN {schema}.provenance_edges p ON p.tenant_scope=w.tenant_scope AND p.child_artifact_id=w.node WHERE NOT w.cycle AND cardinality(w.path)<=33)
      SELECT (SELECT count(*) FROM walk WHERE cycle)
       +(SELECT count(*) FROM {schema}.provenance_edges p JOIN {schema}.artifact_manifests c ON c.tenant_scope=p.tenant_scope AND c.artifact_id=p.child_artifact_id JOIN {schema}.artifact_manifests a ON a.tenant_scope=p.tenant_scope AND a.artifact_id=p.parent_artifact_id WHERE c.encryption_domain<>a.encryption_domain OR CASE c.classification WHEN 'public' THEN 0 WHEN 'internal' THEN 1 WHEN 'confidential' THEN 2 ELSE 3 END < CASE a.classification WHEN 'public' THEN 0 WHEN 'internal' THEN 1 WHEN 'confidential' THEN 2 ELSE 3 END)"),&[]).await.map_err(|_|PostgresStoreError::InvalidSchema)?.get(0);
    if invalid_provenance != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
    Ok(())
}

async fn validate_semantics<C>(
    client: &C,
    schema: &str,
    cursor_key: &[u8; 32],
) -> Result<(), PostgresStoreError>
where
    C: tokio_postgres::GenericClient + Sync,
{
    validate_artifact_semantics(client, schema).await?;
    let evidence_gaps: i64 = client.query_one(
        &format!("SELECT (SELECT count(*) FROM {schema}.quota_intents i LEFT JOIN {schema}.quota_policy_versions p ON p.tenant_scope=i.tenant_scope AND p.policy_id=i.policy_id AND p.policy_revision=i.policy_revision WHERE p.policy_id IS NULL OR p.policy_digest<>i.policy_digest) + (SELECT count(*) FROM {schema}.quota_receipts r LEFT JOIN {schema}.quota_intents i USING(tenant_scope,binding_digest) WHERE i.binding_digest IS NULL) + (SELECT count(*) FROM {schema}.quota_allocations a LEFT JOIN {schema}.quota_intents i USING(tenant_scope,binding_digest) WHERE i.binding_digest IS NULL) + (SELECT count(*) FROM {schema}.quota_leases l LEFT JOIN {schema}.quota_intents i USING(tenant_scope,binding_digest) WHERE i.binding_digest IS NULL)"),
        &[],
    ).await.map_err(|_| PostgresStoreError::InvalidSchema)?.get(0);
    if evidence_gaps != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let reconciliation_rows = client.query(
        &format!("SELECT tenant_scope,reconciliation_id,old_policy_digest,new_policy_digest,actor_digest,reason_digest,targets_json,effective_at FROM {schema}.quota_policy_reconciliation_audits ORDER BY tenant_scope,reconciliation_id"),
        &[],
    ).await.map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in reconciliation_rows {
        let tenant: String = row.get(0);
        let id: String = row.get(1);
        let old: String = row.get(2);
        let new: String = row.get(3);
        let actor: String = row.get(4);
        let reason: String = row.get(5);
        let targets: String = row.get(6);
        let effective: i64 = row.get(7);
        if serde_json::from_str::<Vec<(String,String)>>(&targets).is_err()
            || id != content_digest(format!("quota-reconciliation-v1\0{tenant}\0{old}\0{new}\0{actor}\0{reason}\0{effective}\0{targets}").as_bytes())
        {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    let invalid_quota_leases: i64 = client
        .query_one(
            &format!("SELECT count(*)::bigint FROM {schema}.quota_leases l JOIN {schema}.quota_intents i ON i.tenant_scope=l.tenant_scope AND i.binding_digest=l.binding_digest WHERE l.account_id<>i.account_id OR l.principal_scope<>i.principal_scope OR l.operation<>i.operation OR l.policy_digest<>i.policy_digest OR NOT EXISTS (SELECT 1 FROM {schema}.quota_receipts r WHERE r.tenant_scope=l.tenant_scope AND r.binding_digest=l.binding_digest AND r.dimension=CASE l.lease_kind WHEN 'messageStream' THEN 'concurrentStreams' ELSE 'concurrentSubscriptions' END)"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if invalid_quota_leases != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
    let invalid_execution_reservations: i64 = client
        .query_one(
            &format!("SELECT count(*)::bigint FROM {schema}.quota_execution_reservations q JOIN {schema}.quota_intents i USING(tenant_scope,binding_digest) JOIN {schema}.outbox o ON o.tenant_scope=q.tenant_scope AND o.dispatch_id=q.dispatch_id AND o.task_id=q.task_id WHERE q.policy_id<>i.policy_id OR q.policy_revision<>i.policy_revision OR q.policy_digest<>i.policy_digest OR q.account_id<>i.account_id OR q.principal_scope<>i.principal_scope OR q.operation<>i.operation OR o.quota_binding_digest<>q.binding_digest OR o.quota_reservation_id<>q.reservation_id OR o.quota_reservation_version<>q.reservation_version OR o.reserved_output_bytes<>q.reserved_output_bytes OR o.reserved_event_count<>q.reserved_event_count OR (SELECT count(*) FROM {schema}.quota_receipts r WHERE r.tenant_scope=q.tenant_scope AND r.binding_digest=q.binding_digest AND r.dimension IN ('outputBytes','eventCount'))<>6 OR (SELECT min(units) FROM {schema}.quota_receipts r WHERE r.tenant_scope=q.tenant_scope AND r.binding_digest=q.binding_digest AND r.dimension='outputBytes')<>q.reserved_output_bytes OR (SELECT min(units) FROM {schema}.quota_receipts r WHERE r.tenant_scope=q.tenant_scope AND r.binding_digest=q.binding_digest AND r.dimension='eventCount')<>q.reserved_event_count OR (q.state='settled' AND (q.actual_output_bytes>q.reserved_output_bytes OR q.actual_event_count>q.reserved_event_count)) OR EXISTS(SELECT 1 FROM {schema}.receiver_inbox r WHERE r.tenant_scope=q.tenant_scope AND r.dispatch_id=q.dispatch_id AND (r.quota_binding_digest<>q.binding_digest OR r.quota_reservation_id<>q.reservation_id OR r.quota_reservation_version<>q.reservation_version OR r.reserved_output_bytes<>q.reserved_output_bytes OR r.reserved_event_count<>q.reserved_event_count OR (r.state='completed' AND (r.measured_output_bytes>q.reserved_output_bytes OR r.measured_event_count>q.reserved_event_count))))"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if invalid_execution_reservations != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
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

async fn validate_callback_semantics(
    client: &mut tokio_postgres::Client,
    schema: &str,
) -> Result<(), PostgresStoreError> {
    // read-only callback semantic validation needs a transaction-local forced-RLS marker
    let tx = client
        .transaction()
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    tx.batch_execute("SET LOCAL smesh.internal_global='callback-worker-v1'")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let policies = tx
        .query(
            &format!("SELECT policy_id,policy_revision,policy_digest,max_configs_per_task,max_configs_per_tenant,max_pending,max_payload_bytes,max_attempts,max_delivery_age_ms FROM {schema}.callback_policy_snapshots"),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in policies {
        crate::CallbackPolicySnapshot::new_with_tenant_cap(
            row.get::<_, String>(0),
            u64::try_from(row.get::<_, i64>(1)).map_err(|_| PostgresStoreError::InvalidSchema)?,
            row.get::<_, String>(2),
            u16::try_from(row.get::<_, i32>(3)).map_err(|_| PostgresStoreError::InvalidSchema)?,
            u32::try_from(row.get::<_, i64>(4)).map_err(|_| PostgresStoreError::InvalidSchema)?,
            u32::try_from(row.get::<_, i64>(5)).map_err(|_| PostgresStoreError::InvalidSchema)?,
            u32::try_from(row.get::<_, i32>(6)).map_err(|_| PostgresStoreError::InvalidSchema)?,
            u16::try_from(row.get::<_, i32>(7)).map_err(|_| PostgresStoreError::InvalidSchema)?,
            u64::try_from(row.get::<_, i64>(8)).map_err(|_| PostgresStoreError::InvalidSchema)?,
        )
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    }
    let callback_tenants = tx
        .query(
            &format!(
                "SELECT DISTINCT tenant_scope FROM {schema}.callback_configs ORDER BY tenant_scope"
            ),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    for row in callback_tenants {
        let tenant: String = row.get(0);
        tx.execute(
            "SELECT set_config('smesh.tenant_scope',$1,true)",
            &[&tenant],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
        let invalid_task_owner: i64 = tx
            .query_one(
                &format!(
                    "SELECT
                     (SELECT count(*) FROM {schema}.callback_configs c
                        LEFT JOIN {schema}.tasks t ON t.tenant_scope=c.tenant_scope AND t.task_id=c.task_id
                       WHERE c.tenant_scope=$1 AND (t.task_id IS NULL OR c.owner_account_id<>t.owner_account_id))
                     +(SELECT count(*) FROM {schema}.callback_events e
                        LEFT JOIN {schema}.tasks t ON t.tenant_scope=e.tenant_scope AND t.task_id=e.task_id
                       WHERE e.tenant_scope=$1 AND t.task_id IS NULL)"
                ),
                &[&tenant],
            )
            .await
            .map_err(|_| PostgresStoreError::InvalidSchema)?
            .get(0);
        if invalid_task_owner != 0 {
            return Err(PostgresStoreError::InvalidSchema);
        }
    }
    tx.batch_execute("SET LOCAL smesh.tenant_scope=''")
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    let invalid: i64 = tx
        .query_one(
            &format!(
                "SELECT
                 (SELECT count(*) FROM {schema}.callback_enrollments e
                    LEFT JOIN {schema}.callback_policy_snapshots p ON p.policy_id=e.policy_id AND p.policy_revision=e.policy_revision
                   WHERE p.policy_id IS NULL OR p.policy_digest IS NULL OR e.enrollment_generation<>e.policy_revision
                      OR e.url_digest<>'sha256:'||encode(sha256(convert_to(e.canonical_url,'UTF8')),'hex'))
                 +(SELECT count(*) FROM {schema}.callback_configs c
                    LEFT JOIN {schema}.callback_enrollments e ON e.tenant_scope=c.tenant_scope AND e.enrollment_id=c.enrollment_id AND e.enrollment_generation=c.enrollment_generation
                   WHERE e.enrollment_id IS NULL OR c.canonical_url<>e.canonical_url OR c.url_digest<>e.url_digest)
                 +(SELECT count(*) FROM {schema}.callback_events e
                   WHERE e.payload_digest<>'sha256:'||encode(sha256(e.payload),'hex')
                      OR e.created_at<=0 OR e.expires_at<e.created_at)
                 +(SELECT count(*) FROM {schema}.callback_deliveries d
                    LEFT JOIN {schema}.callback_events e ON e.tenant_scope=d.tenant_scope AND e.event_id=d.event_id
                    LEFT JOIN {schema}.callback_configs c ON c.tenant_scope=d.tenant_scope AND c.task_id=d.task_id AND c.config_id=d.config_id
                   WHERE e.event_id IS NULL OR c.config_id IS NULL OR e.task_id<>d.task_id
                      OR d.attempt_count<0 OR d.attempt_count>32 OR d.lease_epoch<0
                      OR ((d.state='leased')<>(d.lease_owner IS NOT NULL AND d.lease_token IS NOT NULL AND d.lease_until IS NOT NULL))
                      OR d.updated_at<d.created_at)
                 +(SELECT count(*) FROM {schema}.callback_attempts a
                    LEFT JOIN {schema}.callback_deliveries d ON d.tenant_scope=a.tenant_scope AND d.event_id=a.event_id AND d.config_id=a.config_id
                   WHERE d.event_id IS NULL OR a.attempt_no<1 OR a.attempt_no>d.attempt_count
                      OR a.lease_epoch<1 OR a.lease_epoch>d.lease_epoch OR a.finished_at<a.started_at
                      OR a.outcome NOT IN ('delivered','retry','dead','canceled'))
                 +(SELECT count(*) FROM (SELECT c.tenant_scope FROM {schema}.callback_configs c WHERE c.state<>'revoked' GROUP BY c.tenant_scope HAVING count(*)>(SELECT p.max_configs_per_tenant FROM {schema}.callback_policy_snapshots p ORDER BY p.policy_revision DESC LIMIT 1)) over_tenant)
                 +(SELECT count(*) FROM (SELECT c.tenant_scope,c.task_id FROM {schema}.callback_configs c WHERE c.state<>'revoked' GROUP BY c.tenant_scope,c.task_id HAVING count(*)>(SELECT p.max_configs_per_task FROM {schema}.callback_policy_snapshots p ORDER BY p.policy_revision DESC LIMIT 1)) over_task)
                 +(SELECT count(*) FROM {schema}.callback_audits a
                   WHERE a.occurred_at<=0 OR NOT (
                    (a.event_kind='callback_policy_reconciled' AND a.source_kind='callback_enrollments' AND EXISTS(SELECT 1 FROM {schema}.callback_enrollments e WHERE e.tenant_scope=a.tenant_scope AND a.source_pk_digest={schema}.callback_audit_digest(a.event_kind,e.tenant_scope,'',e.enrollment_id,'',e.enrollment_generation,0)))
                    OR (a.event_kind IN ('callback_config_created','callback_config_deleted') AND a.source_kind='callback_configs' AND EXISTS(SELECT 1 FROM {schema}.callback_configs c WHERE c.tenant_scope=a.tenant_scope AND a.source_pk_digest={schema}.callback_audit_digest(a.event_kind,c.tenant_scope,c.task_id,c.config_id,'',c.enrollment_generation,0)))
                    OR (a.event_kind='callback_event_enqueued' AND a.source_kind='callback_events' AND EXISTS(SELECT 1 FROM {schema}.callback_events e WHERE e.tenant_scope=a.tenant_scope AND a.source_pk_digest={schema}.callback_audit_digest(a.event_kind,e.tenant_scope,e.task_id,'',e.event_id,e.causative_revision,0)))
                    OR (a.event_kind='callback_delivery_attempted' AND a.source_kind='callback_deliveries' AND EXISTS(SELECT 1 FROM {schema}.callback_deliveries d WHERE d.tenant_scope=a.tenant_scope AND a.source_pk_digest={schema}.callback_audit_digest(a.event_kind,d.tenant_scope,d.task_id,d.config_id,d.event_id,0,d.attempt_count)))
                    OR (a.event_kind='callback_delivery_attempted' AND a.source_kind='callback_deliveries' AND EXISTS(SELECT 1 FROM {schema}.callback_attempts x JOIN {schema}.callback_deliveries d ON d.tenant_scope=x.tenant_scope AND d.event_id=x.event_id AND d.config_id=x.config_id WHERE x.tenant_scope=a.tenant_scope AND a.source_pk_digest={schema}.callback_audit_digest(a.event_kind,d.tenant_scope,d.task_id,d.config_id,d.event_id,0,x.attempt_no)))
                    OR (a.event_kind IN ('callback_delivered','callback_retry_scheduled','callback_dead') AND a.source_kind='callback_deliveries' AND EXISTS(SELECT 1 FROM {schema}.callback_attempts x JOIN {schema}.callback_deliveries d ON d.tenant_scope=x.tenant_scope AND d.event_id=x.event_id AND d.config_id=x.config_id WHERE x.tenant_scope=a.tenant_scope AND x.outcome=CASE a.event_kind WHEN 'callback_delivered' THEN 'delivered' WHEN 'callback_retry_scheduled' THEN 'retry' ELSE 'dead' END AND a.source_pk_digest={schema}.callback_audit_digest(a.event_kind,d.tenant_scope,d.task_id,d.config_id,d.event_id,0,x.attempt_no)))
                   ))
                 +(SELECT count(*) FROM (
                    WITH expected(tenant_scope,event_kind,source_kind,source_pk_digest) AS (
                     SELECT tenant_scope,'callback_policy_reconciled','callback_enrollments',{schema}.callback_audit_digest('callback_policy_reconciled',tenant_scope,'',enrollment_id,'',enrollment_generation,0) FROM {schema}.callback_enrollments
                     UNION SELECT tenant_scope,'callback_config_created','callback_configs',{schema}.callback_audit_digest('callback_config_created',tenant_scope,task_id,config_id,'',enrollment_generation,0) FROM {schema}.callback_configs
                     UNION SELECT tenant_scope,'callback_config_deleted','callback_configs',{schema}.callback_audit_digest('callback_config_deleted',tenant_scope,task_id,config_id,'',enrollment_generation,0) FROM {schema}.callback_configs WHERE state IN ('draining','revoked')
                     UNION SELECT tenant_scope,'callback_event_enqueued','callback_events',{schema}.callback_audit_digest('callback_event_enqueued',tenant_scope,task_id,'',event_id,causative_revision,0) FROM {schema}.callback_events
                     UNION SELECT d.tenant_scope,'callback_delivery_attempted','callback_deliveries',{schema}.callback_audit_digest('callback_delivery_attempted',d.tenant_scope,d.task_id,d.config_id,d.event_id,0,n.attempt_no) FROM {schema}.callback_deliveries d CROSS JOIN LATERAL generate_series(1,d.attempt_count) n(attempt_no)
                     UNION SELECT a.tenant_scope,CASE a.outcome WHEN 'delivered' THEN 'callback_delivered' WHEN 'retry' THEN 'callback_retry_scheduled' WHEN 'dead' THEN 'callback_dead' END,'callback_deliveries',{schema}.callback_audit_digest(CASE a.outcome WHEN 'delivered' THEN 'callback_delivered' WHEN 'retry' THEN 'callback_retry_scheduled' WHEN 'dead' THEN 'callback_dead' END,a.tenant_scope,d.task_id,a.config_id,a.event_id,0,a.attempt_no) FROM {schema}.callback_attempts a JOIN {schema}.callback_deliveries d USING(tenant_scope,event_id,config_id) WHERE a.outcome IN ('delivered','retry','dead')
                     UNION SELECT tenant_scope,CASE state WHEN 'delivered' THEN 'callback_delivered' WHEN 'retry' THEN 'callback_retry_scheduled' WHEN 'dead' THEN 'callback_dead' END,'callback_deliveries',{schema}.callback_audit_digest(CASE state WHEN 'delivered' THEN 'callback_delivered' WHEN 'retry' THEN 'callback_retry_scheduled' WHEN 'dead' THEN 'callback_dead' END,tenant_scope,task_id,config_id,event_id,0,attempt_count) FROM {schema}.callback_deliveries WHERE state IN ('delivered','retry','dead')
                    ), actual AS (SELECT tenant_scope,event_kind,source_kind,source_pk_digest FROM {schema}.callback_audits)
                    (SELECT * FROM expected EXCEPT SELECT * FROM actual)
                    UNION ALL (SELECT * FROM actual EXCEPT SELECT * FROM expected)
                   ) audit_difference)
                 +(SELECT count(*) FROM (SELECT tenant_scope,event_kind,source_pk_digest FROM {schema}.callback_audits GROUP BY tenant_scope,event_kind,source_pk_digest HAVING count(*)<>1) duplicates)"
            ),
            &[],
        )
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?
        .get(0);
    if invalid != 0 {
        return Err(PostgresStoreError::InvalidSchema);
    }
    tx.commit()
        .await
        .map_err(|_| PostgresStoreError::InvalidSchema)?;
    Ok(())
}

async fn validate_catalog(
    client: &mut tokio_postgres::Client,
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
            "artifact_inline_migration_required",
            "artifact_restore_incomplete",
            "artifact_stage_locator_live",
            "audit_projection_session_valid",
            "authority_diagnostics_bounded",
            "authority_retained_scopes_bounded",
            "authority_tenants_bounded",
            "callback_worker_session_valid",
            "cancel_callback_config_deliveries",
            "cancellation_requested_bounded",
            "claim_artifact_gc",
            "claim_artifact_reencryption",
            "claim_artifact_upload",
            "claim_audit_projection",
            "claim_callback_deliveries",
            "claim_outbox_bounded",
            "cleanup_audit_projection",
            "cleanup_authorization_decisions",
            "commit_audit_projection",
            "enqueue_audit_projection",
            "enqueue_callback_audit_projection",
            "enqueue_terminal_callbacks",
            "ensure_outbox_tenant_scheduler",
            "fail_audit_projection",
            "finish_callback_delivery",
            "gc_quota_authority_bounded",
            "mark_authorization_projection_requirement",
            "record_callback_audit",
            "register_audit_projection_session",
            "register_callback_worker_session",
            "renew_callback_delivery",
        ]
        || definer_rows.iter().any(|row| {
            if row.get::<_, &str>(1) != expected_owner {
                return true;
            }
            let name: &str = row.get(0);
            row.get::<_, Option<Vec<String>>>(2).is_none_or(|settings| {
                if matches!(
                    name,
                    "claim_artifact_upload"
                        | "claim_artifact_gc"
                        | "claim_artifact_reencryption"
                        | "artifact_stage_locator_live"
                        | "artifact_inline_migration_required"
                        | "artifact_restore_incomplete"
                ) {
                    settings != ["search_path=pg_catalog", "row_security=on"]
                } else {
                    settings != ["search_path=pg_catalog"]
                }
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
        (
            4_i64,
            DISTRIBUTED_QUOTA_MIGRATION_NAME,
            content_digest(DISTRIBUTED_QUOTA_MIGRATION_SQL.as_bytes()),
        ),
        (
            5_i64,
            ARTIFACT_MIGRATION_NAME,
            content_digest(ARTIFACT_MIGRATION_SQL.as_bytes()),
        ),
        (
            6_i64,
            AUDIT_PROJECTION_MIGRATION_NAME,
            content_digest(AUDIT_PROJECTION_MIGRATION_SQL.as_bytes()),
        ),
        (
            7_i64,
            CALLBACK_MIGRATION_NAME,
            content_digest(CALLBACK_MIGRATION_SQL.as_bytes()),
        ),
        (
            8_i64,
            CALLBACK_POLICY_FENCE_MIGRATION_NAME,
            content_digest(CALLBACK_POLICY_FENCE_MIGRATION_SQL.as_bytes()),
        ),
        (
            9_i64,
            AUTHORIZATION_RETENTION_MIGRATION_NAME,
            content_digest(AUTHORIZATION_RETENTION_MIGRATION_SQL.as_bytes()),
        ),
    ];
    if migration_rows.len() != expected_migrations.len()
        || migration_rows
            .iter()
            .zip(expected_migrations.iter())
            .any(|(row, expected)| {
                row.get::<_, i64>(0) != expected.0
                    || row.get::<_, i64>(1)
                        != match expected.0 {
                            7 => 7,
                            8 => 8,
                            9 => CURRENT_SCHEMA_VERSION,
                            _ => LOGICAL_SCHEMA_VERSION,
                        }
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
    if row.get::<_, i64>(0) != CURRENT_SCHEMA_VERSION
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
    validate_callback_semantics(client, schema).await?;
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

async fn enqueue_postgres_terminal_callbacks(
    store: &PostgresTaskStore,
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &str,
    task: &Task,
    revision: i64,
    now: i64,
) -> Result<(), A2AError> {
    if store.callback_policy.is_none() || !task.status.state.is_terminal() {
        return Ok(());
    }
    let terminal = StreamResponse::StatusUpdate(TaskStatusUpdateEvent {
        task_id: task.id.clone(),
        context_id: task.context_id.clone(),
        status: task.status.clone(),
        metadata: None,
    });
    let payload = serde_json::to_vec(&terminal)
        .map_err(|_| A2AError::internal("callback terminal payload encoding failed"))?;
    let digest = content_digest(&payload);
    let event_id = format!(
        "callback-event-{}",
        &content_digest(format!("{tenant}\0{}\0{revision}\0{digest}", task.id).as_bytes())[7..39]
    );
    let egress = i64::try_from(payload.len())
        .map_err(|_| A2AError::internal("callback public egress size overflow"))?;
    let test_fault = if store.trust_injected_time {
        POSTGRES_CALLBACK_TERMINAL_TEST_FAULT
            .lock()
            .map_err(|_| A2AError::internal("callback terminal fault lock failed"))?
            .take()
    } else {
        None
    };
    if let Some(fault) = test_fault {
        tx.query_one(
            "SELECT set_config('smesh.test_callback_terminal_fault',$1,true)",
            &[&fault.as_str()],
        )
        .await
        .map_err(|error| {
            PostgresTaskStore::transaction_body_error(
                &error,
                A2AError::internal("callback terminal fault setup failed"),
            )
        })?;
    }
    let q = store.q("SELECT __S__.enqueue_terminal_callbacks($1,$2,$3,$4,$5,$6,$7,$8)");
    tx.query_one(
        &q,
        &[
            &tenant, &task.id, &revision, &event_id, &payload, &digest, &egress, &now,
        ],
    )
    .await
    .map(|_| ())
    .map_err(|error| {
        PostgresTaskStore::transaction_body_error(
            &error,
            A2AError::internal("callback terminal enqueue failed"),
        )
    })
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
    enqueue_postgres_terminal_callbacks(store, tx, tenant, &task, next_revision, now).await?;
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
pub(crate) fn snapshot_metadata_digest(
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

#[async_trait]
impl crate::AuditProjectionAuthority for PostgresTaskStore {
    fn audit_projection_capabilities(&self) -> crate::AuditProjectionCapabilities {
        crate::AuditProjectionCapabilities {
            enabled: self.audit_projection_enabled,
            starts_at_enable: true,
        }
    }

    async fn claim_audit_projection(
        &self,
        owner: &str,
        lease_duration_ms: i64,
        limit: usize,
    ) -> Result<Vec<crate::AuditProjectionLease>, A2AError> {
        if !self.audit_projection_enabled
            || !crate::durable_authority::valid_bounded_identity(owner)
            || !(1..=300_000).contains(&lease_duration_ms)
            || !(1..=1_000).contains(&limit)
        {
            return Err(A2AError::invalid_request("invalid audit projection claim"));
        }
        let token = content_digest(&rand::random::<[u8; 32]>());
        let client = self.connection().await?;
        let rows = client
            .query(
                &self.q("SELECT * FROM __S__.claim_audit_projection($1,$2,$3,$4)"),
                &[
                    &owner,
                    &token,
                    &lease_duration_ms,
                    &i32::try_from(limit).unwrap_or(1000),
                ],
            )
            .await
            .map_err(|_| A2AError::internal("audit projection claim failed"))?;
        rows.into_iter()
            .map(|r| {
                let tenant: String = r.get(0);
                let source: String = r.get(2);
                let kind: String = r.get(4);
                crate::AuditProjectionLease::new(
                    content_digest(tenant.as_bytes()),
                    r.get::<_, String>(1),
                    crate::AuditProjectionSource::parse(&source)
                        .ok_or_else(|| A2AError::internal("invalid audit projection source"))?,
                    r.get::<_, String>(3),
                    crate::AuditProjectionEventKind::parse(&kind)
                        .ok_or_else(|| A2AError::internal("invalid audit projection kind"))?,
                    r.get(5),
                    owner,
                    &token,
                    u64::try_from(r.get::<_, i64>(6)).unwrap_or(0),
                    r.get(7),
                    u32::try_from(r.get::<_, i32>(8)).unwrap_or(0),
                )
            })
            .collect()
    }

    async fn commit_audit_projection(
        &self,
        lease: &crate::AuditProjectionLease,
    ) -> Result<bool, A2AError> {
        let client = self.connection().await?;
        client
            .query_one(
                &self.q("SELECT __S__.commit_audit_projection($1,$2,$3,$4)"),
                &[
                    &lease.event_id(),
                    &lease.lease_owner(),
                    &lease.lease_token(),
                    &i64::try_from(lease.lease_epoch()).unwrap_or(-1),
                ],
            )
            .await
            .map(|r| r.get(0))
            .map_err(|_| A2AError::internal("audit projection commit failed"))
    }
    async fn fail_audit_projection(
        &self,
        lease: &crate::AuditProjectionLease,
        error_digest: &str,
        retry_delay_ms: i64,
    ) -> Result<crate::AuditProjectionState, A2AError> {
        let client = self.connection().await?;
        let state: String = client
            .query_one(
                &self.q("SELECT __S__.fail_audit_projection($1,$2,$3,$4,$5,$6)"),
                &[
                    &lease.event_id(),
                    &lease.lease_owner(),
                    &lease.lease_token(),
                    &i64::try_from(lease.lease_epoch()).unwrap_or(-1),
                    &error_digest,
                    &retry_delay_ms,
                ],
            )
            .await
            .map_err(|_| A2AError::internal("audit projection failure commit failed"))?
            .get(0);
        Ok(match state.as_str() {
            "pending" => crate::AuditProjectionState::Pending,
            "dead" => crate::AuditProjectionState::Dead,
            _ => crate::AuditProjectionState::Leased,
        })
    }
    async fn cleanup_audit_projection(
        &self,
        retention_ms: i64,
        limit: usize,
    ) -> Result<u64, A2AError> {
        if !(1..=1000).contains(&limit) {
            return Err(A2AError::invalid_request(
                "invalid audit projection cleanup",
            ));
        }
        let client = self.connection().await?;
        let n: i64 = client
            .query_one(
                &self.q("SELECT __S__.cleanup_audit_projection($1,$2)"),
                &[&retention_ms, &i32::try_from(limit).unwrap_or(1000)],
            )
            .await
            .map_err(|_| A2AError::internal("audit projection cleanup failed"))?
            .get(0);
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

impl AuthorityIdentity for PostgresTaskStore {
    fn callback_authority(&self) -> Option<&dyn crate::CallbackAuthority> {
        self.callback_policy
            .as_ref()
            .map(|_| self as &dyn crate::CallbackAuthority)
    }

    fn audit_projection_authority(&self) -> Option<&dyn crate::AuditProjectionAuthority> {
        self.audit_projection_enabled.then_some(self)
    }

    fn artifact_authority(&self) -> Option<&dyn crate::ArtifactAuthority> {
        Some(self)
    }

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

    fn quota_policy_snapshot(&self) -> Option<Arc<crate::QuotaPolicy>> {
        self.quota_policy.clone()
    }
}

fn postgres_callback_config(
    row: &Row,
    tenant: &str,
    task: &str,
) -> Result<crate::CallbackConfig, A2AError> {
    let state = match row.get::<_, &str>(5) {
        "active" => crate::CallbackConfigState::Active,
        "draining" => crate::CallbackConfigState::Draining,
        "revoked" => crate::CallbackConfigState::Revoked,
        "terminal_closed" => crate::CallbackConfigState::TerminalClosed,
        _ => return Err(A2AError::internal("callback config state corrupt")),
    };
    crate::CallbackConfig::new(
        tenant,
        task,
        crate::CallbackConfigId::new(row.get::<_, String>(0))?,
        row.get::<_, String>(1),
        u64::try_from(row.get::<_, i64>(2))
            .map_err(|_| A2AError::internal("callback enrollment corrupt"))?,
        row.get::<_, String>(3),
        row.get::<_, String>(4),
        state,
        row.get::<_, i64>(6),
    )
}
fn postgres_callback_token(
    key: &[u8; 32],
    tenant: &str,
    task: &str,
    created: i64,
    id: &str,
) -> Result<String, A2AError> {
    let payload = format!("1\u{1f}{tenant}\u{1f}{task}\u{1f}{created}\u{1f}{id}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| A2AError::internal("callback token failed"))?;
    mac.update(b"smesh-callback-page-v1\0");
    mac.update(payload.as_bytes());
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}
fn parse_postgres_callback_token(
    key: &[u8; 32],
    token: &str,
    tenant: &str,
    task: &str,
) -> Result<(i64, String), A2AError> {
    let (p, m) = token
        .split_once('.')
        .ok_or_else(|| A2AError::invalid_request("invalid callback page token"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| A2AError::invalid_request("invalid callback page token"))?;
    let supplied = URL_SAFE_NO_PAD
        .decode(m)
        .map_err(|_| A2AError::invalid_request("invalid callback page token"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| A2AError::internal("callback token failed"))?;
    mac.update(b"smesh-callback-page-v1\0");
    mac.update(&payload);
    if mac.verify_slice(&supplied).is_err() {
        return Err(A2AError::invalid_request("invalid callback page token"));
    }
    let text = std::str::from_utf8(&payload)
        .map_err(|_| A2AError::invalid_request("invalid callback page token"))?;
    let mut p = text.split('\u{1f}');
    if p.next() != Some("1") || p.next() != Some(tenant) || p.next() != Some(task) {
        return Err(A2AError::invalid_request("invalid callback page token"));
    }
    let at = p
        .next()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| A2AError::invalid_request("invalid callback page token"))?;
    let id = p
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| A2AError::invalid_request("invalid callback page token"))?
        .to_owned();
    if p.next().is_some() {
        return Err(A2AError::invalid_request("invalid callback page token"));
    }
    Ok((at, id))
}

#[async_trait]
impl crate::CallbackAuthority for PostgresTaskStore {
    async fn callback_database_time(&self) -> Result<i64, A2AError> {
        self.run_retryable_transaction("", None, |store, tx| {
            Box::pin(async move {
                tx.query_one(&store.q("SELECT __S__.db_millis()"), &[])
                    .await
                    .map(|row| row.get(0))
                    .map_err(|_| A2AError::internal("callback DB clock failed"))
            })
        })
        .await
    }
    fn callback_capabilities(&self) -> crate::CallbackCapabilities {
        crate::CallbackCapabilities::postgres_production()
    }
    fn callback_readiness(&self) -> crate::CallbackReadiness {
        if self.callback_policy.is_some() {
            crate::CallbackReadiness::Ready
        } else {
            crate::CallbackReadiness::Disabled
        }
    }
    fn callback_policy_snapshot(&self) -> Option<Arc<crate::CallbackPolicySnapshot>> {
        self.callback_policy.clone()
    }
    async fn resolve_callback_enrollment(
        &self,
        scope: &OwnedTaskScope,
        exact_url: &str,
    ) -> Result<Option<crate::CallbackEnrollmentBinding>, A2AError> {
        let policy = self
            .callback_policy
            .clone()
            .ok_or_else(A2AError::push_notification_not_supported)?;
        let tenant = scope.tenant_scope.clone();
        let url = exact_url.to_owned();
        let policy_id = policy.policy_id().to_owned();
        let policy_revision = i64::try_from(policy.policy_revision())
            .map_err(|_| A2AError::internal("callback policy corrupt"))?;
        self.run_retryable_transaction(&tenant,None,|store,tx|{let tenant=tenant.clone();let url=url.clone();let policy_id=policy_id.clone();Box::pin(async move{let q=store.q("SELECT enrollment_id,enrollment_generation,url_digest FROM __S__.callback_enrollments WHERE tenant_scope=$1 AND canonical_url=$2 AND policy_id=$3 AND policy_revision=$4 AND policy_revision=(SELECT max(policy_revision) FROM __S__.callback_policy_snapshots) ORDER BY enrollment_generation DESC LIMIT 1");let row=tx.query_opt(&q,&[&tenant,&url,&policy_id,&policy_revision]).await.map_err(|_|A2AError::internal("callback enrollment lookup failed"))?;row.map(|r|crate::CallbackEnrollmentBinding::new(r.get::<_,String>(0),u64::try_from(r.get::<_,i64>(1)).map_err(|_|A2AError::internal("callback enrollment corrupt"))?,url,r.get::<_,String>(2))).transpose()})}).await
    }
    async fn create_callback_config(
        &self,
        command: crate::ConfigCreateCommand,
    ) -> Result<crate::CallbackConfig, A2AError> {
        let policy = self
            .callback_policy
            .clone()
            .ok_or_else(A2AError::push_notification_not_supported)?;
        let tenant = command.scope().tenant_scope.clone();
        let owner = command.scope().owner_account_id.clone();
        let principal = command.scope().principal_scope.clone();
        let own = command.scope().visibility == VisibilityScope::Own;
        let task = command.task_id().to_owned();
        let id = command.config_id().map_or_else(
            || {
                format!(
                    "callback-{}",
                    &content_digest(&rand::random::<[u8; 32]>())[7..39]
                )
            },
            |v| v.as_str().to_owned(),
        );
        let enrollment = command.enrollment_id().to_owned();
        let generation = i64::try_from(command.enrollment_generation())
            .map_err(|_| A2AError::invalid_request("invalid callback enrollment generation"))?;
        let url = command.canonical_url().to_owned();
        let digest = command.url_digest().to_owned();
        let created = command.created_at();
        let authorization_audit = command.authorization_audit().cloned();
        let policy_id = policy.policy_id().to_owned();
        let policy_revision = i64::try_from(policy.policy_revision())
            .map_err(|_| A2AError::internal("callback policy corrupt"))?;
        self.run_retryable_transaction(&tenant,Some(&owner),|store,tx|{let tenant=tenant.clone();let owner=owner.clone();let principal=principal.clone();let task=task.clone();let id=id.clone();let enrollment=enrollment.clone();let url=url.clone();let digest=digest.clone();let policy=policy.clone();let policy_id=policy_id.clone();let authorization_audit=authorization_audit.clone();Box::pin(async move{tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&CALLBACK_POLICY_FENCE_LOCK]).await.map_err(|_|A2AError::internal("callback policy fence failed"))?;let visible=store.q("SELECT EXISTS(SELECT 1 FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 AND (NOT $3 OR owner_account_id=$4) AND state NOT IN ('\"TASK_STATE_COMPLETED\"','\"TASK_STATE_FAILED\"','\"TASK_STATE_CANCELED\"','\"TASK_STATE_REJECTED\"'))");if !tx.query_one(&visible,&[&tenant,&task,&own,&owner]).await.map_err(|_|A2AError::internal("callback parent lookup failed"))?.get::<_,bool>(0){return Err(A2AError::task_not_found("resource"));}let enrolled=store.q(ACTIVE_CALLBACK_ENROLLMENT_EXISTS_SQL);if !tx.query_one(&enrolled,&[&tenant,&enrollment,&generation,&url,&digest,&policy_id,&policy_revision]).await.map_err(|_|A2AError::internal("callback enrollment lookup failed"))?.get::<_,bool>(0){return Err(A2AError::invalid_request("callback enrollment is not authorized"));}let lookup=store.q("SELECT config_id,enrollment_id,enrollment_generation,canonical_url,url_digest,state,created_at FROM __S__.callback_configs WHERE tenant_scope=$1 AND task_id=$2 AND config_id=$3");if let Some(row)=tx.query_opt(&lookup,&[&tenant,&task,&id]).await.map_err(|_|A2AError::internal("callback idempotency lookup failed"))?{if row.get::<_,&str>(1)!=enrollment||row.get::<_,i64>(2)!=generation||row.get::<_,&str>(3)!=url||row.get::<_,&str>(4)!=digest{return Err(A2AError::invalid_request("callback config id is already bound to different semantics"));}let config=postgres_callback_config(&row,&tenant,&task)?;if let Some(audit)=authorization_audit.clone(){store.insert_audit(tx,audit).await?;}return Ok(config);}let scheduler_lock=store.q("SELECT pg_advisory_xact_lock(hashtextextended($1,17))");tx.query_one(&scheduler_lock,&[&tenant]).await.map_err(|_|A2AError::internal("callback tenant capacity lock failed"))?;let tenant_count=store.q("SELECT count(*) FROM __S__.callback_configs WHERE tenant_scope=$1 AND state<>'revoked'");if tx.query_one(&tenant_count,&[&tenant]).await.map_err(|_|A2AError::internal("callback tenant config count failed"))?.get::<_,i64>(0)>=i64::from(policy.max_configs_per_tenant()){return Err(A2AError::invalid_params("callback tenant config capacity reached"));}let count=store.q("SELECT count(*) FROM __S__.callback_configs WHERE tenant_scope=$1 AND task_id=$2 AND state<>'revoked'");if tx.query_one(&count,&[&tenant,&task]).await.map_err(|_|A2AError::internal("callback config count failed"))?.get::<_,i64>(0)>=i64::from(policy.max_configs_per_task()){return Err(A2AError::invalid_request("callback config capacity reached"));}let insert=store.q("INSERT INTO __S__.callback_configs(tenant_scope,task_id,config_id,owner_account_id,principal_scope,enrollment_id,enrollment_generation,canonical_url,url_digest,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$10) RETURNING config_id,enrollment_id,enrollment_generation,canonical_url,url_digest,state,created_at");let row=tx.query_one(&insert,&[&tenant,&task,&id,&owner,&principal,&enrollment,&generation,&url,&digest,&created]).await.map_err(|_|A2AError::internal("callback config insert failed"))?;let config=postgres_callback_config(&row,&tenant,&task)?;if let Some(audit)=authorization_audit{store.insert_audit(tx,audit).await?;}Ok(config)})}).await
    }
    async fn get_callback_config(
        &self,
        command: crate::ConfigGetCommand,
    ) -> Result<Option<crate::CallbackConfig>, A2AError> {
        if self.callback_policy.is_none() {
            return Err(A2AError::push_notification_not_supported());
        }
        let tenant = command.scope().tenant_scope.clone();
        let owner = command.scope().owner_account_id.clone();
        let own = command.scope().visibility == VisibilityScope::Own;
        let task = command.task_id().to_owned();
        let id = command.config_id().as_str().to_owned();
        self.run_retryable_transaction(&tenant,Some(&owner),|store,tx|{let tenant=tenant.clone();let owner=owner.clone();let task=task.clone();let id=id.clone();Box::pin(async move{let q=store.q("SELECT c.config_id,c.enrollment_id,c.enrollment_generation,c.canonical_url,c.url_digest,c.state,c.created_at FROM __S__.callback_configs c JOIN __S__.tasks t USING(tenant_scope,task_id) WHERE c.tenant_scope=$1 AND c.task_id=$2 AND c.config_id=$3 AND c.state<>'revoked' AND (NOT $4 OR t.owner_account_id=$5)");tx.query_opt(&q,&[&tenant,&task,&id,&own,&owner]).await.map_err(|_|A2AError::internal("callback config lookup failed"))?.map(|r|postgres_callback_config(&r,&tenant,&task)).transpose()})}).await
    }
    async fn list_callback_configs(
        &self,
        command: crate::ConfigListCommand,
    ) -> Result<crate::CallbackConfigPage, A2AError> {
        if self.callback_policy.is_none() {
            return Err(A2AError::push_notification_not_supported());
        }
        let tenant = command.scope().tenant_scope.clone();
        let owner = command.scope().owner_account_id.clone();
        let own = command.scope().visibility == VisibilityScope::Own;
        let task = command.task_id().to_owned();
        let limit = usize::from(command.page_size().get());
        let after = command
            .page_token()
            .map(|v| parse_postgres_callback_token(&self.cursor_key, v, &tenant, &task))
            .transpose()?
            .unwrap_or((0, String::new()));
        let key = *self.cursor_key;
        self.run_retryable_transaction(&tenant,Some(&owner),|store,tx|{let tenant=tenant.clone();let owner=owner.clone();let task=task.clone();let after=after.clone();Box::pin(async move{let q=store.q("SELECT c.config_id,c.enrollment_id,c.enrollment_generation,c.canonical_url,c.url_digest,c.state,c.created_at FROM __S__.callback_configs c JOIN __S__.tasks t USING(tenant_scope,task_id) WHERE c.tenant_scope=$1 AND c.task_id=$2 AND c.state<>'revoked' AND (NOT $3 OR t.owner_account_id=$4) AND (c.created_at>$5 OR (c.created_at=$5 AND c.config_id>$6)) ORDER BY c.created_at,c.config_id LIMIT $7");let rows=tx.query(&q,&[&tenant,&task,&own,&owner,&after.0,&after.1,&i64::try_from(limit+1).unwrap_or(101)]).await.map_err(|_|A2AError::internal("callback config list failed"))?;let more=rows.len()>limit;let mut values=Vec::new();for row in rows.iter().take(limit){values.push(postgres_callback_config(row,&tenant,&task)?);}let next=if more{let last=values.last().expect("bounded page");Some(postgres_callback_token(&key,&tenant,&task,last.created_at(),last.config_id().as_str())?)}else{None};crate::CallbackConfigPage::new(values,next)})}).await
    }
    async fn delete_callback_config(
        &self,
        command: crate::ConfigDeleteCommand,
    ) -> Result<crate::CallbackDeleteOutcome, A2AError> {
        if self.callback_policy.is_none() {
            return Err(A2AError::push_notification_not_supported());
        }
        let tenant = command.scope().tenant_scope.clone();
        let owner = command.scope().owner_account_id.clone();
        let own = command.scope().visibility == VisibilityScope::Own;
        let task = command.task_id().to_owned();
        let id = command.config_id().as_str().to_owned();
        let requested = command.requested_at();
        let authorization_audit = command.authorization_audit().cloned();
        self.run_retryable_transaction(&tenant,Some(&owner),|store,tx|{let tenant=tenant.clone();let owner=owner.clone();let task=task.clone();let id=id.clone();let authorization_audit=authorization_audit.clone();Box::pin(async move{let parent=store.q("SELECT EXISTS(SELECT 1 FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 AND (NOT $3 OR owner_account_id=$4))");if !tx.query_one(&parent,&[&tenant,&task,&own,&owner]).await.map_err(|_|A2AError::internal("callback parent lookup failed"))?.get::<_,bool>(0){return Err(A2AError::task_not_found("resource"));}let lookup=store.q("SELECT state FROM __S__.callback_configs WHERE tenant_scope=$1 AND task_id=$2 AND config_id=$3 FOR UPDATE");let Some(row)=tx.query_opt(&lookup,&[&tenant,&task,&id]).await.map_err(|_|A2AError::internal("callback delete lookup failed"))? else{if let Some(audit)=authorization_audit.clone(){store.insert_audit(tx,audit).await?;}return Ok(crate::CallbackDeleteOutcome::AlreadyAbsent)};if row.get::<_,&str>(0)=="revoked"{if let Some(audit)=authorization_audit.clone(){store.insert_audit(tx,audit).await?;}return Ok(crate::CallbackDeleteOutcome::AlreadyAbsent);}let cancel=store.q("SELECT __S__.cancel_callback_config_deliveries($1,$2,$3)");tx.query_one(&cancel,&[&tenant,&task,&id]).await.map_err(|_|A2AError::internal("callback cancellation failed"))?;let leased=store.q("SELECT EXISTS(SELECT 1 FROM __S__.callback_deliveries WHERE tenant_scope=$1 AND task_id=$2 AND config_id=$3 AND state='leased' AND lease_until>__S__.db_millis())");let draining=tx.query_one(&leased,&[&tenant,&task,&id]).await.map_err(|_|A2AError::internal("callback lease lookup failed"))?.get::<_,bool>(0);let update=store.q("UPDATE __S__.callback_configs SET state=$4,updated_at=$5 WHERE tenant_scope=$1 AND task_id=$2 AND config_id=$3");tx.execute(&update,&[&tenant,&task,&id,&if draining{"draining"}else{"revoked"},&requested]).await.map_err(|_|A2AError::internal("callback revoke failed"))?;if let Some(audit)=authorization_audit{store.insert_audit(tx,audit).await?;}Ok(if draining{crate::CallbackDeleteOutcome::Draining}else{crate::CallbackDeleteOutcome::Revoked})})}).await
    }
    async fn claim_callback_deliveries(
        &self,
        command: crate::DeliveryClaimCommand,
    ) -> Result<Vec<crate::CallbackLease>, A2AError> {
        let policy = self
            .callback_policy
            .clone()
            .ok_or_else(A2AError::push_notification_not_supported)?;
        let owner = command.owner().to_owned();
        let duration = command.lease_duration().get();
        let limit = i32::from(command.batch_limit());
        let attempts = i32::from(policy.max_attempts());
        let token = format!(
            "lease-{}",
            &content_digest(&rand::random::<[u8; 32]>())[7..39]
        );
        self.run_retryable_transaction("", None, |store, tx| {
            let owner = owner.clone();
            let token = token.clone();
            Box::pin(async move {
                let q = store.q("SELECT * FROM __S__.claim_callback_deliveries($1,$2,$3,$4,$5)");
                let rows = tx
                    .query(&q, &[&owner, &token, &duration, &limit, &attempts])
                    .await
                    .map_err(|error| {
                        Self::transaction_body_error(
                            &error,
                            A2AError::internal("callback claim failed"),
                        )
                    })?;
                rows.into_iter()
                    .map(|r| {
                        let tenant: String = r.get(0);
                        let event: String = r.get(1);
                        let fence = crate::DeliveryFence::new(
                            tenant,
                            event,
                            r.get::<_, String>(3),
                            &owner,
                            &token,
                            u64::try_from(r.get::<_, i64>(10))
                                .map_err(|_| A2AError::internal("callback fence corrupt"))?,
                        )?;
                        crate::CallbackLease::new_authoritative(
                            fence,
                            r.get::<_, String>(2),
                            r.get::<_, String>(3),
                            r.get::<_, String>(4),
                            r.get::<_, String>(5),
                            u64::try_from(r.get::<_, i64>(6))
                                .map_err(|_| A2AError::internal("callback enrollment corrupt"))?,
                            r.get::<_, Vec<u8>>(7),
                            r.get::<_, String>(8),
                            u16::try_from(r.get::<_, i32>(9))
                                .map_err(|_| A2AError::internal("callback attempt corrupt"))?,
                            r.get::<_, i64>(14),
                            r.get::<_, i64>(15),
                            r.get::<_, i64>(11),
                            r.get::<_, String>(12),
                            r.get::<_, String>(13),
                        )
                    })
                    .collect()
            })
        })
        .await
    }
    async fn renew_callback_delivery(
        &self,
        fence: &crate::DeliveryFence,
        duration: crate::LeaseDurationMillis,
    ) -> Result<Option<i64>, A2AError> {
        let f = fence.clone();
        self.run_retryable_transaction(f.tenant_scope(), None, |store, tx| {
            let f = f.clone();
            Box::pin(async move {
                let q = store.q("SELECT __S__.renew_callback_delivery($1,$2,$3,$4,$5,$6,$7)");
                tx.query_one(
                    &q,
                    &[
                        &f.tenant_scope(),
                        &f.event_id(),
                        &f.config_id(),
                        &f.lease_owner(),
                        &f.lease_token(),
                        &i64::try_from(f.lease_epoch()).unwrap_or(-1),
                        &duration.get(),
                    ],
                )
                .await
                .map(|r| r.get(0))
                .map_err(|error| {
                    Self::transaction_body_error(
                        &error,
                        A2AError::internal("callback renewal failed"),
                    )
                })
            })
        })
        .await
    }
    async fn commit_callback_delivery(
        &self,
        fence: &crate::DeliveryFence,
    ) -> Result<bool, A2AError> {
        self.finish_postgres_callback(fence, "delivered", None, None, None)
            .await
            .map(|s| s == crate::CallbackDeliveryState::Delivered)
    }
    async fn fail_callback_delivery(
        &self,
        command: crate::CallbackFailCommand,
    ) -> Result<crate::CallbackDeliveryState, A2AError> {
        let next = match command.disposition() {
            crate::CallbackDeliveryDisposition::Retry => "retry",
            crate::CallbackDeliveryDisposition::Dead => "dead",
        };
        let category = format!("{:?}", command.category()).to_ascii_lowercase();
        self.finish_postgres_callback(
            command.fence(),
            next,
            Some(category),
            Some(command.error_digest().to_owned()),
            command.retry_at(),
        )
        .await
    }
    async fn revoke_callback_delivery(
        &self,
        fence: &crate::DeliveryFence,
    ) -> Result<crate::CallbackDeliveryState, A2AError> {
        self.finish_postgres_callback(fence, "canceled", None, None, None)
            .await
    }
}

async fn run_authorization_retention_operator(
    client: &mut tokio_postgres::Client,
    config: &PostgresStoreConfig,
    tenant_scope: &str,
    retention_ms: i64,
    limit: usize,
) -> Result<AuthorizationAuditCleanup, A2AError> {
    // ALLOWLIST: operator-only bounded authorization retention transaction.
    validate_catalog(client, &config.schema)
        .await
        .map_err(|_| A2AError::internal("authorization retention catalog invalid"))?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| A2AError::internal("authorization retention transaction failed"))?;
    tx.batch_execute("SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='5s'")
        .await
        .map_err(|_| A2AError::internal("authorization retention transaction failed"))?;
    let row = tx
        .query_one(
            &format!(
                "SELECT * FROM {}.cleanup_authorization_decisions($1,$2,$3)",
                config.schema
            ),
            &[
                &tenant_scope,
                &retention_ms,
                &i32::try_from(limit).unwrap_or(1_000),
            ],
        )
        .await
        .map_err(|_| A2AError::internal("authorization retention cleanup failed"))?;
    let result = AuthorizationAuditCleanup {
        deleted: u64::try_from(row.get::<_, i64>(0)).unwrap_or(0),
        projection_blocked: u64::try_from(row.get::<_, i64>(1)).unwrap_or(0),
        has_more: row.get(2),
        oldest_remaining: row.get(3),
        cutoff: row.get(4),
    };
    tx.commit()
        .await
        .map_err(|_| A2AError::internal("authorization retention commit failed"))?;
    Ok(result)
}

impl PostgresTaskStore {
    /// Deletes one bounded tenant batch through the migrator-only operator boundary.
    ///
    /// This is an operator boundary, not a method on a shared runtime store. A
    /// projection-required decision is removed only with terminal projection
    /// evidence, and both rows are deleted in the same transaction.
    pub async fn cleanup_authorization_decisions(
        config: &PostgresStoreConfig,
        tenant_scope: &str,
        retention_ms: i64,
        limit: usize,
    ) -> Result<AuthorizationAuditCleanup, A2AError> {
        if !crate::durable_authority::valid_bounded_identity(tenant_scope)
            || !(0..=315_576_000_000).contains(&retention_ms)
            || !(1..=1_000).contains(&limit)
        {
            return Err(A2AError::invalid_request(
                "invalid authorization retention cleanup",
            ));
        }
        let insecure = validate_tls(config)
            .map_err(|_| A2AError::internal("authorization retention configuration invalid"))?;
        let pg = tokio_postgres::Config::from_str(&config.migrator_url)
            .map_err(|_| A2AError::internal("authorization retention configuration invalid"))?;
        if insecure {
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(NoTls))
                    .await
                    .map_err(|_| {
                        A2AError::internal("authorization retention connection timed out")
                    })?
                    .map_err(|_| A2AError::internal("authorization retention connection failed"))?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let result = run_authorization_retention_operator(
                &mut client,
                config,
                tenant_scope,
                retention_ms,
                limit,
            )
            .await;
            driver.abort();
            result
        } else {
            let connector = native_tls_connector()
                .map_err(|_| A2AError::internal("authorization retention TLS invalid"))?;
            let (mut client, connection) =
                tokio::time::timeout(config.connect_timeout, pg.connect(connector))
                    .await
                    .map_err(|_| {
                        A2AError::internal("authorization retention connection timed out")
                    })?
                    .map_err(|_| A2AError::internal("authorization retention connection failed"))?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let result = run_authorization_retention_operator(
                &mut client,
                config,
                tenant_scope,
                retention_ms,
                limit,
            )
            .await;
            driver.abort();
            result
        }
    }

    async fn finish_postgres_callback(
        &self,
        fence: &crate::DeliveryFence,
        next: &'static str,
        category: Option<String>,
        evidence: Option<String>,
        retry: Option<i64>,
    ) -> Result<crate::CallbackDeliveryState, A2AError> {
        let f = fence.clone();
        self.run_retryable_transaction(f.tenant_scope(), None, |store, tx| {
            let f = f.clone();
            let category = category.clone();
            let evidence = evidence.clone();
            Box::pin(async move {
                let q = store
                    .q("SELECT __S__.finish_callback_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)");
                let state: String = tx
                    .query_one(
                        &q,
                        &[
                            &f.tenant_scope(),
                            &f.event_id(),
                            &f.config_id(),
                            &f.lease_owner(),
                            &f.lease_token(),
                            &i64::try_from(f.lease_epoch()).unwrap_or(-1),
                            &next,
                            &category,
                            &evidence,
                            &retry,
                        ],
                    )
                    .await
                    .map_err(|error| {
                        Self::transaction_body_error(
                            &error,
                            A2AError::invalid_request("stale callback delivery fence"),
                        )
                    })?
                    .get(0);
                match state.as_str() {
                    "delivered" => Ok(crate::CallbackDeliveryState::Delivered),
                    "retry" => Ok(crate::CallbackDeliveryState::Retry),
                    "dead" => Ok(crate::CallbackDeliveryState::Dead),
                    "canceled" => Ok(crate::CallbackDeliveryState::Canceled),
                    _ => Err(A2AError::internal("callback delivery state corrupt")),
                }
            })
        })
        .await
    }
}

#[async_trait]
impl QuotaLeaseAuthority for PostgresTaskStore {
    async fn charge_quota_request(
        &self,
        intent: &crate::QuotaIntent,
        now: i64,
    ) -> Result<(), A2AError> {
        if !self.quota_enforcement
            || intent.operation() == crate::QuotaOperation::PublicEgress
            || intent.charges().iter().any(|charge| {
                matches!(
                    charge.dimension(),
                    crate::QuotaDimension::ConcurrentActiveWork
                        | crate::QuotaDimension::ConcurrentStreams
                        | crate::QuotaDimension::ConcurrentSubscriptions
                        | crate::QuotaDimension::OutputBytes
                        | crate::QuotaDimension::EventCount
                )
            })
        {
            return Err(crate::quota::quota_authority_unavailable());
        }
        let tenant = intent.tenant_scope.to_string();
        let account = intent.account_id.to_string();
        let intent = intent.clone();
        let denial_intent = intent.clone();
        let result = self
            .run_retryable_transaction(&tenant, Some(&account), |store, tx| {
                let tenant = tenant.clone();
                let account = account.clone();
                let intent = intent.clone();
                Box::pin(async move {
                    let now = store.effective_now(tx, now).await?;
                    store
                        .apply_quota_intent(tx, &intent, &tenant, &account, None, now, true, None)
                        .await
                })
            })
            .await;
        self.finalize_quota_result(Some(&denial_intent), now, result)
            .await
    }

    async fn acquire_quota_lease(
        &self,
        intent: &crate::QuotaIntent,
        kind: crate::QuotaLeaseKind,
        resource_digest: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<QuotaLease, A2AError> {
        if !self.quota_enforcement
            || resource_digest.is_empty()
            || resource_digest.len() > 256
            || !(1_000..=300_000).contains(&lease_duration)
            || !intent
                .charges()
                .iter()
                .any(|charge| charge.dimension() == kind.dimension())
        {
            return Err(crate::quota::quota_authority_unavailable());
        }
        let tenant = intent.tenant_scope.to_string();
        let account = intent.account_id.to_string();
        let principal = intent.principal_scope.to_string();
        let intent = intent.clone();
        let denial_intent = intent.clone();
        let resource_digest = resource_digest.to_owned();
        let lease_id = content_digest(&rand::random::<[u8; 32]>());
        let lease_token = content_digest(&rand::random::<[u8; 32]>());
        let result = self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let tenant = tenant.clone();
            let account = account.clone();
            let principal = principal.clone();
            let intent = intent.clone();
            let resource_digest = resource_digest.clone();
            let lease_id = lease_id.clone();
            let lease_token = lease_token.clone();
            Box::pin(async move {
                let now = store.effective_now(tx, now).await?;
                let lease_until = now
                    .checked_add(lease_duration)
                    .ok_or_else(|| A2AError::invalid_request("quota lease time overflow"))?;
                store.reclaim_expired_quota_leases(tx, &tenant, now, 100).await?;
                store
                    .apply_quota_intent(tx, &intent, &tenant, &account, None, now, true, None)
                    .await?;
                let sql = store.q("INSERT INTO __S__.quota_leases(tenant_scope,lease_id,lease_token,lease_epoch,binding_digest,policy_digest,account_id,principal_scope,operation,lease_kind,resource_digest,lease_until,state,created_at,updated_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,'active',$12,$12)");
                tx.execute(
                    &sql,
                    &[&tenant,&lease_id,&lease_token,&intent.binding_digest(),&intent.policy_digest(),&account,&principal,&intent.operation().as_str(),&kind.as_str(),&resource_digest,&lease_until,&now],
                )
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("quota lease insert failed")))?;
                Ok(QuotaLease {
                    tenant_scope: tenant,
                    account_id: account,
                    principal_scope: principal,
                    operation: intent.operation(),
                    kind,
                    resource_digest,
                    lease_id,
                    lease_token,
                    lease_epoch: 1,
                    lease_until,
                })
            })
        }).await;
        self.finalize_quota_result(Some(&denial_intent), now, result)
            .await
    }

    async fn renew_quota_lease(
        &self,
        lease: &QuotaLease,
        now: i64,
        lease_duration: i64,
    ) -> Result<LeaseRenewalOutcome, A2AError> {
        if !(1_000..=300_000).contains(&lease_duration) {
            return Err(A2AError::invalid_request("invalid quota lease duration"));
        }
        let lease = lease.clone();
        self.run_retryable_transaction(&lease.tenant_scope.clone(), Some(&lease.account_id.clone()), |store, tx| {
            let lease = lease.clone();
            Box::pin(async move {
                let now = store.effective_now(tx, now).await?;
                store.reclaim_expired_quota_leases(tx, &lease.tenant_scope, now, 100).await?;
                let until = now.checked_add(lease_duration).ok_or_else(|| A2AError::invalid_request("quota lease time overflow"))?;
                let sql = store.q("UPDATE __S__.quota_leases SET lease_until=$6,updated_at=$5 WHERE tenant_scope=$1 AND lease_id=$2 AND lease_token=$3 AND lease_epoch=$4 AND state='active' AND lease_until>$5 RETURNING lease_until");
                let row = tx.query_opt(&sql, &[&lease.tenant_scope,&lease.lease_id,&lease.lease_token,&i64::try_from(lease.lease_epoch).unwrap_or(i64::MAX),&now,&until]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("quota lease renewal failed")))?;
                Ok(row.map_or(LeaseRenewalOutcome::Stale, |_| LeaseRenewalOutcome::Applied { lease_until: until }))
            })
        }).await
    }

    async fn release_quota_lease(
        &self,
        lease: &QuotaLease,
        requested_now: i64,
    ) -> Result<bool, A2AError> {
        let lease = lease.clone();
        self.run_retryable_transaction(&lease.tenant_scope.clone(), Some(&lease.account_id.clone()), |store, tx| {
            let lease = lease.clone();
            Box::pin(async move {
                let now = store.effective_now(tx, requested_now).await?;
                store.reclaim_expired_quota_leases(tx, &lease.tenant_scope, now, 100).await?;
                let sql = store.q("UPDATE __S__.quota_leases SET state='released',updated_at=$5 WHERE tenant_scope=$1 AND lease_id=$2 AND lease_token=$3 AND lease_epoch=$4 AND state='active' AND lease_until>$5 RETURNING binding_digest");
                let Some(row) = tx.query_opt(&sql, &[&lease.tenant_scope,&lease.lease_id,&lease.lease_token,&i64::try_from(lease.lease_epoch).unwrap_or(i64::MAX),&now]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("quota lease release failed")))? else { return Ok(false); };
                let binding: String = row.get(0);
                let release = store.q("WITH released AS (
                  SELECT i.policy_digest,i.operation,r.scope_kind,r.scope_id,r.dimension,r.window_start,sum(r.units)::bigint units
                    FROM __S__.quota_receipts r JOIN __S__.quota_intents i ON i.tenant_scope=r.tenant_scope AND i.binding_digest=r.binding_digest
                   WHERE r.tenant_scope=$1 AND r.binding_digest=$2 AND r.dimension IN ('concurrentStreams','concurrentSubscriptions')
                   GROUP BY i.policy_digest,i.operation,r.scope_kind,r.scope_id,r.dimension,r.window_start
                ) UPDATE __S__.quota_buckets b SET used_units=GREATEST(b.used_units-released.units,0),updated_at=$3 FROM released
                   WHERE b.tenant_scope=$1 AND b.policy_digest=released.policy_digest AND b.operation=released.operation
                    AND b.scope_kind=released.scope_kind AND b.scope_id=released.scope_id AND b.dimension=released.dimension AND b.window_start=released.window_start");
                tx.execute(&release, &[&lease.tenant_scope,&binding,&now]).await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("quota lease capacity release failed")))?;
                Ok(true)
            })
        }).await
    }

    async fn charge_quota_egress(
        &self,
        intent: &crate::QuotaIntent,
        now: i64,
    ) -> Result<(), A2AError> {
        if !self.quota_enforcement || intent.operation() != crate::QuotaOperation::PublicEgress {
            return Err(crate::quota::quota_authority_unavailable());
        }
        let tenant = intent.tenant_scope.to_string();
        let account = intent.account_id.to_string();
        let intent = intent.clone();
        let denial_intent = intent.clone();
        let result = self
            .run_retryable_transaction(&tenant, Some(&account), |store, tx| {
                let tenant = tenant.clone();
                let account = account.clone();
                let intent = intent.clone();
                Box::pin(async move {
                    let now = store.effective_now(tx, now).await?;
                    store
                        .apply_quota_intent(tx, &intent, &tenant, &account, None, now, true, None)
                        .await
                })
            })
            .await;
        self.finalize_quota_result(Some(&denial_intent), now, result)
            .await
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
            Box::pin(async move { store.insert_audit(tx, audit).await })
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
        let (command, quota_reservation, quota_intent, callback_intent) =
            mutation.into_authority_parts();
        let callback_intent = callback_intent.map(|mut intent| {
            if intent.config_id.is_none() {
                intent.config_id = Some(
                    crate::CallbackConfigId::new(format!(
                        "callback-{}",
                        &content_digest(&rand::random::<[u8; 32]>())[7..39]
                    ))
                    .expect("generated callback id is valid"),
                );
            }
            intent
        });
        if callback_intent.is_some() && self.callback_policy.is_none() {
            return Err(A2AError::push_notification_not_supported());
        }
        if self.quota_enforcement && quota_intent.is_none() {
            return Err(crate::quota::quota_authority_unavailable());
        }
        if quota_intent.as_ref().is_some_and(|intent| {
            intent.operation()
                != if command.streaming {
                    crate::QuotaOperation::SendStream
                } else {
                    crate::QuotaOperation::TaskCreate
                }
        }) {
            return Err(A2AError::invalid_request("quota intent operation mismatch"));
        }
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
        let requested_now = audit.decided_at();
        let denial_intent = quota_intent.clone();
        let result = self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
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
            let quota_intent = quota_intent.clone();
            let callback_intent = callback_intent.clone();
            Box::pin(async move {
        let quota_now = store.effective_now(tx, command.now).await?;
        if store.quota_policy.is_none() {
            tx.query_one("SELECT pg_advisory_xact_lock(6001136200063)", &[])
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("admission capacity lock failed")))?;
        }
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
            if let Some(intent) = quota_intent.as_ref() {
                store.apply_quota_intent(tx, intent, &tenant, &owner, Some(&stored_task_id), quota_now, false, Some(&command.request)).await?;
                store.bind_execution_reservation(tx, intent, &stored_task_id, &message_id, &dispatch_id, quota_now, false).await?;
            }
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
        let execution_reservation = if let Some(intent) = quota_intent.as_ref() {
            store.apply_quota_intent(tx, intent, &tenant, &owner, Some(&command.task.id), quota_now, true, Some(&command.request)).await?;
            Some(store.bind_execution_reservation(tx, intent, &command.task.id, &message_id, &dispatch_id, quota_now, true).await?)
        } else {
            None
        };
        let event=store.q("INSERT INTO __S__.task_events(tenant_scope,task_id,event_seq,task_revision,event_kind,from_state,to_state,event_json,created_at) VALUES($1,$2,1,1,'admitted',NULL,$3,$4,$5)");
        tx.execute(
            &event,
            &[&tenant, &command.task.id, &state, &task_json, &command.now],
        )
        .await
        .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("atomic event append failed")))?;
        if let Some(intent)=callback_intent.as_ref(){
            tx.query_one("SELECT pg_advisory_xact_lock($1)",&[&CALLBACK_POLICY_FENCE_LOCK]).await.map_err(|error|Self::transaction_body_error(&error,A2AError::internal("inline callback policy fence failed")))?;
            let generation=i64::try_from(intent.enrollment.enrollment_generation()).map_err(|_|A2AError::invalid_request("invalid callback enrollment generation"))?;
            let policy=store.callback_policy.as_ref().ok_or_else(A2AError::push_notification_not_supported)?;
            let policy_revision=i64::try_from(policy.policy_revision()).map_err(|_|A2AError::internal("callback policy corrupt"))?;
            let enrolled=store.q(ACTIVE_CALLBACK_ENROLLMENT_EXISTS_SQL);
            if !tx.query_one(&enrolled,&[&tenant,&intent.enrollment.enrollment_id(),&generation,&intent.enrollment.canonical_url(),&intent.enrollment.url_digest(),&policy.policy_id(),&policy_revision]).await.map_err(|error|Self::transaction_body_error(&error,A2AError::internal("inline callback enrollment lookup failed")))?.get::<_,bool>(0){return Err(A2AError::invalid_params("callback enrollment is not authorized"));}
            let max=store.callback_policy.as_ref().map_or(0,|p|p.max_configs_per_task());let tenant_max=store.callback_policy.as_ref().map_or(0,|p|p.max_configs_per_tenant());let scheduler_lock=store.q("SELECT pg_advisory_xact_lock(hashtextextended($1,17))");tx.query_one(&scheduler_lock,&[&tenant]).await.map_err(|error|Self::transaction_body_error(&error,A2AError::internal("inline callback tenant capacity lock failed")))?;let tenant_count=store.q("SELECT count(*) FROM __S__.callback_configs WHERE tenant_scope=$1 AND state<>'revoked'");if tx.query_one(&tenant_count,&[&tenant]).await.map_err(|error|Self::transaction_body_error(&error,A2AError::internal("inline callback tenant count failed")))?.get::<_,i64>(0)>=i64::from(tenant_max){return Err(A2AError::invalid_params("callback tenant config capacity reached"));}
            let count=store.q("SELECT count(*) FROM __S__.callback_configs WHERE tenant_scope=$1 AND task_id=$2 AND state<>'revoked'");
            if tx.query_one(&count,&[&tenant,&command.task.id]).await.map_err(|error|Self::transaction_body_error(&error,A2AError::internal("inline callback count failed")))?.get::<_,i64>(0)>=i64::from(max){return Err(A2AError::invalid_params("callback config capacity reached"));}
            let config_id=intent.config_id.as_ref().expect("callback intent id assigned before retry").as_str().to_owned();
            let principal=quota_intent.as_ref().map(crate::QuotaIntent::principal_scope).ok_or_else(crate::quota::quota_authority_unavailable)?;
            let insert=store.q("INSERT INTO __S__.callback_configs(tenant_scope,task_id,config_id,owner_account_id,principal_scope,enrollment_id,enrollment_generation,canonical_url,url_digest,state,causative_message_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$11)");
            tx.execute(&insert,&[&tenant,&command.task.id,&config_id,&owner,&principal,&intent.enrollment.enrollment_id(),&generation,&intent.enrollment.canonical_url(),&intent.enrollment.url_digest(),&command.request.message.message_id,&command.now]).await.map_err(|error|Self::transaction_body_error(&error,A2AError::internal("inline callback config insert failed")))?;
        }
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
        let reservation_id = execution_reservation.as_ref().map(|(id, _)| id.as_str());
        let quota_binding = quota_intent.as_ref().map(crate::QuotaIntent::binding_digest);
        let reservation_version = execution_reservation.as_ref().map(|_| 1_i64);
        let reserved_output = execution_reservation.as_ref().map(|(_, budget)| i64::try_from(budget.max_output_bytes()).unwrap_or(i64::MAX));
        let reserved_events = execution_reservation.as_ref().map(|(_, budget)| i64::try_from(budget.max_event_count()).unwrap_or(i64::MAX));
        let outbox=store.q("INSERT INTO __S__.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version,quota_binding_digest,quota_reservation_id,quota_reservation_version,reserved_output_bytes,reserved_event_count) VALUES($1,$2,$3,$4,1,$5,$6,'pending',$7,$8,$8,$8,2,$9,$10,$11,$12,$13)");
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
                &quota_binding,
                &reservation_id,
                &reservation_version,
                &reserved_output,
                &reserved_events,
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
                Ok(AdmissionOutcome::Admitted(AdmissionRecord {
                    task_id: command.task.id,
                    revision: 1,
                    dispatch_id,
                }))
            })
        })
        .await;
        self.finalize_quota_result(denial_intent.as_ref(), requested_now, result)
            .await
    }

    async fn authorize_and_continue_mutation(
        &self,
        scope: &OwnedTaskScope,
        mutation: AuthorizedMutation<SendMessageAdmission>,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError> {
        let (command, quota_reservation, quota_intent, _callback_intent) =
            mutation.into_authority_parts();
        if self.quota_enforcement && quota_intent.is_none() {
            return Err(crate::quota::quota_authority_unavailable());
        }
        if quota_intent
            .as_ref()
            .is_some_and(|intent| intent.operation() != crate::QuotaOperation::TaskContinue)
        {
            return Err(A2AError::invalid_request("quota intent operation mismatch"));
        }
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
        let requested_now = audit.decided_at();
        let denial_intent = quota_intent.clone();
        let result = self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
            let command = command.clone();
            let audit = audit.clone();
            let tenant = tenant.clone();
            let owner = owner.clone();
            let message_id = message_id.clone();
            let digest = digest.clone();
            let dispatch_id = dispatch_id.clone();
            let request_json = request_json.clone();
            let quota_reservation = quota_reservation.clone();
            let quota_intent = quota_intent.clone();
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
            if let Some(intent) = quota_intent.as_ref() {
                store.apply_quota_intent(tx, intent, &tenant, &owner, Some(&command.task.id), quota_now, false, Some(&command.request)).await?;
                store.bind_execution_reservation(tx, intent, &command.task.id, &message_id, &dispatch_id, quota_now, false).await?;
            }
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
        let execution_reservation = if let Some(intent) = quota_intent.as_ref() {
            store.apply_quota_intent(tx, intent, &tenant, &owner, Some(&command.task.id), quota_now, true, Some(&command.request)).await?;
            Some(store.bind_execution_reservation(tx, intent, &command.task.id, &message_id, &dispatch_id, quota_now, true).await?)
        } else {
            None
        };
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
        let reservation_id = execution_reservation.as_ref().map(|(id, _)| id.as_str());
        let quota_binding = quota_intent.as_ref().map(crate::QuotaIntent::binding_digest);
        let reservation_version = execution_reservation.as_ref().map(|_| 1_i64);
        let reserved_output = execution_reservation.as_ref().map(|(_, budget)| i64::try_from(budget.max_output_bytes()).unwrap_or(i64::MAX));
        let reserved_events = execution_reservation.as_ref().map(|(_, budget)| i64::try_from(budget.max_event_count()).unwrap_or(i64::MAX));
        let outbox=store.q("INSERT INTO __S__.outbox(dispatch_id,tenant_scope,task_id,message_id,causative_revision,payload_json,payload_digest,state,max_attempts,available_at,created_at,updated_at,dispatch_identity_version,quota_binding_digest,quota_reservation_id,quota_reservation_version,reserved_output_bytes,reserved_event_count) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9,$9,$9,2,$10,$11,$12,$13,$14)");
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
                &quota_binding,
                &reservation_id,
                &reservation_version,
                &reserved_output,
                &reserved_events,
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
                Ok(AdmissionOutcome::Admitted(AdmissionRecord {
                    task_id: task.id,
                    revision: u64::try_from(next)
                        .map_err(|_| A2AError::internal("task revision corrupt"))?,
                    dispatch_id,
                }))
            })
        })
        .await;
        self.finalize_quota_result(denial_intent.as_ref(), requested_now, result)
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

    async fn get_authorized_with_quota(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        audit: AuthorizationAuditInput,
        quota_intent: Option<&crate::QuotaIntent>,
    ) -> Result<Option<Task>, A2AError> {
        if self.quota_enforcement && quota_intent.is_none() {
            return Err(crate::quota::quota_authority_unavailable());
        }
        if quota_intent.is_some_and(|intent| {
            intent.operation() != crate::QuotaOperation::TaskGet
                || intent.semantic_id.as_ref() != audit.decision_id()
        }) {
            return Err(A2AError::invalid_request("quota intent operation mismatch"));
        }
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
        {
            return Err(A2AError::invalid_request("authorized read scope mismatch"));
        }
        let tenant = scope.tenant_scope().to_owned();
        let account = scope.owner_account_id().to_owned();
        let own = scope.visibility() == VisibilityScope::Own;
        let task_id = task_id.to_owned();
        let requested_now = audit.decided_at();
        let quota_intent = quota_intent.cloned();
        let denial_intent = quota_intent.clone();
        let result = self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
            let tenant = tenant.clone();
            let account = account.clone();
            let task_id = task_id.clone();
            let audit = audit.clone();
            let quota_intent = quota_intent.clone();
            Box::pin(async move {
                if let Some(intent) = quota_intent.as_ref() {
                    let now = store.effective_now(tx, audit.decided_at()).await?;
                    store
                        .apply_quota_intent(tx, intent, &tenant, &account, None, now, true, None)
                        .await?;
                }
                let sql = store.q("SELECT task_json FROM __S__.tasks WHERE tenant_scope=$1 AND task_id=$2 AND ($3::boolean=false OR owner_account_id=$4)");
                let result = tx
                    .query_opt(&sql, &[&tenant, &task_id, &own, &account])
                    .await
                    .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("authorized task lookup failed")))?
                    .map(|row| task_from_row(&row))
                    .transpose()?;
                let decision = if result.is_some() {
                    audit.decided(AuthorizationDecisionEffect::Allow, "visible_resource", None)
                } else {
                    audit.decided(AuthorizationDecisionEffect::Deny, "resource_unavailable", None)
                };
                store.insert_audit(tx, decision).await?;
                Ok(result)
            })
        })
        .await;
        self.finalize_quota_result(denial_intent.as_ref(), requested_now, result)
            .await
    }

    async fn list_authorized(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        cursor_scope_digest: &str,
    ) -> Result<ListTasksResponse, A2AError> {
        self.list_authorized_with_quota(scope, request, audit, cursor_scope_digest, None)
            .await
    }

    async fn list_authorized_with_quota(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        cursor_scope_digest: &str,
        quota_intent: Option<&crate::QuotaIntent>,
    ) -> Result<ListTasksResponse, A2AError> {
        if self.quota_enforcement && quota_intent.is_none() {
            return Err(crate::quota::quota_authority_unavailable());
        }
        if quota_intent.is_some_and(|intent| {
            intent.operation() != crate::QuotaOperation::TaskList
                || intent.semantic_id.as_ref() != audit.decision_id()
        }) {
            return Err(A2AError::invalid_request("quota intent operation mismatch"));
        }
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
        self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
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
                let delete = store
                    .q("DELETE FROM __S__.list_snapshots WHERE tenant_scope=$1 AND expires_at<=$2");
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
        let requested_now = audit.decided_at();
        let quota_intent = quota_intent.cloned();
        let denial_intent = quota_intent.clone();
        let result = self.run_retryable_transaction(&tenant, Some(&owner), |store, tx| {
            let tenant = tenant.clone();
            let owner = owner.clone();
            let request = request.clone();
            let audit = audit.clone();
            let query_digest = query_digest.clone();
            let cursor_scope_digest = cursor_scope_digest.clone();
            let quota_intent = quota_intent.clone();
            Box::pin(async move {
        let quota_now = store.effective_now(tx, audit.decided_at()).await?;
        let now: i64 = tx
            .query_one(&store.q("SELECT __S__.db_millis()"), &[])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("task snapshot clock failed")))?
            .get(0);
        if let Some(intent) = quota_intent.as_ref() {
            store
                .apply_quota_intent(tx, intent, &tenant, &owner, None, quota_now, true, None)
                .await?;
        }
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
                let tenant_counter_lock=store.q("SELECT retained_bytes FROM __S__.retained_authority_usage WHERE tenant_scope=$1 AND scope_kind='tenant' AND scope_id=$1 FOR UPDATE");
                tx.query_one(&tenant_counter_lock, &[&tenant])
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
                Ok(response)
            })
        })
        .await;
        self.finalize_quota_result(denial_intent.as_ref(), requested_now, result)
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
    async fn telemetry_correlation_for_outbox(
        &self,
        lease: &OutboxLease,
    ) -> Result<Option<crate::TelemetryCorrelation>, A2AError> {
        let mut connection = self.connection().await?;
        // ALLOWLIST: read-only indexed scoped telemetry correlation lookup.
        let tx = connection
            .transaction()
            .await
            .map_err(|_| A2AError::internal("durable telemetry correlation lookup failed"))?;
        self.set_tenant(&tx, &lease.tenant_scope, None).await?;
        let sql = self.q("SELECT o.message_id,o.task_id,t.context_id FROM __S__.outbox o JOIN __S__.tasks t ON t.tenant_scope=o.tenant_scope AND t.task_id=o.task_id WHERE o.tenant_scope=$1 AND o.dispatch_id=$2");
        let row = tx
            .query_opt(&sql, &[&lease.tenant_scope, &lease.dispatch_id])
            .await
            .map_err(|_| A2AError::internal("durable telemetry correlation lookup failed"))?;
        tx.commit()
            .await
            .map_err(|_| A2AError::internal("durable telemetry correlation lookup failed"))?;
        row.map(|row| crate::TelemetryCorrelation::new(row.get(0), row.get(1), row.get(2)))
            .transpose()
    }

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
        let sql=store.q("SELECT tenant_scope,outbox_id,dispatch_id,task_id,attempt_no,max_attempts,payload_json,quota_binding_digest,quota_reservation_id,quota_reservation_version,reserved_output_bytes,reserved_event_count,quota_policy_id,quota_policy_revision,quota_policy_digest FROM __S__.claim_outbox_bounded($1,$2,$3,$4)");
        let row = tx
            .query_opt(&sql, &[&now, &lease_owner, &token, &until])
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("outbox claim failed")))?;
        let Some(row) = row else {
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
        let reservation_parts = (
            row.get::<_, Option<String>>(7),
            row.get::<_, Option<String>>(8),
            row.get::<_, Option<i64>>(9),
            row.get::<_, Option<i64>>(10),
            row.get::<_, Option<i64>>(11),
            row.get::<_, Option<String>>(12),
            row.get::<_, Option<i64>>(13),
            row.get::<_, Option<String>>(14),
        );
        let execution_reservation = match reservation_parts {
            (None, None, None, None, None, None, None, None) => None,
            (Some(binding_digest), Some(reservation_id), Some(version), Some(output), Some(events), Some(policy_id), Some(policy_revision), Some(policy_digest)) => {
                Some(ExecutionReservation {
                    reservation_id,
                    reservation_version: u64::try_from(version).map_err(|_| A2AError::internal("execution reservation version is corrupt"))?,
                    binding_digest,
                    policy_id,
                    policy_revision: u64::try_from(policy_revision).map_err(|_| A2AError::internal("execution reservation policy revision is corrupt"))?,
                    policy_digest,
                    budget: crate::ExecutionBudget::new(
                        u64::try_from(output).map_err(|_| A2AError::internal("execution output budget is corrupt"))?,
                        u64::try_from(events).map_err(|_| A2AError::internal("execution event budget is corrupt"))?,
                    ).map_err(|_| A2AError::internal("execution reservation budget is corrupt"))?,
                })
            }
            _ => return Err(A2AError::internal("execution reservation binding is incomplete")),
        };
        if store.quota_enforcement && execution_reservation.is_none() {
            return Err(A2AError::internal("claimable outbox has no execution reservation"));
        }

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
                        execution_reservation: execution_reservation.clone(),
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
                return Ok(None);
        }

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
            execution_reservation,
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
                let reservation_id = lease.execution_reservation.as_ref().map(|value| value.reservation_id.as_str());
                let binding = lease.execution_reservation.as_ref().map(|value| value.binding_digest.as_str());
                let reservation_version = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.reservation_version).unwrap_or(i64::MAX));
                let reserved_output = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_output_bytes()).unwrap_or(i64::MAX));
                let reserved_events = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_event_count()).unwrap_or(i64::MAX));
                let sql = store.q("UPDATE __S__.outbox SET lease_until=$1,updated_at=$2 WHERE tenant_scope=$3 AND outbox_id=$4 AND dispatch_id=$5 AND task_id=$6 AND state='leased' AND lease_owner=$7 AND lease_token=$8 AND attempt_count=$9 AND max_attempts=$10 AND lease_until=$11 AND lease_until>$2 AND quota_reservation_id IS NOT DISTINCT FROM $12 AND quota_binding_digest IS NOT DISTINCT FROM $13 AND quota_reservation_version IS NOT DISTINCT FROM $14 AND reserved_output_bytes IS NOT DISTINCT FROM $15 AND reserved_event_count IS NOT DISTINCT FROM $16");
                let changed = tx.execute(&sql, &[&until, &now, &lease.tenant_scope, &lease.outbox_id, &lease.dispatch_id, &lease.task_id, &lease.lease_owner, &lease.lease_token, &i64::from(lease.attempt_no), &i64::from(lease.max_attempts), &lease.lease_until, &reservation_id, &binding, &reservation_version, &reserved_output, &reserved_events]).await
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
        store
            .settle_execution_reservation(tx, &lease, "receiver-completed", now)
            .await?;
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
        enqueue_postgres_terminal_callbacks(store,tx,&lease.tenant_scope,&task,revision,now).await?;
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
        if self.quota_enforcement && envelope.execution_reservation.is_none() {
            return Err(A2AError::invalid_params(
                "durable receiver envelope has no execution reservation",
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
        let ownership_sql=store.q("SELECT o.attempt_count,o.lease_token,o.quota_binding_digest,o.quota_reservation_id,o.quota_reservation_version,o.reserved_output_bytes,o.reserved_event_count,q.policy_id,q.policy_revision,q.policy_digest FROM __S__.outbox o LEFT JOIN __S__.quota_execution_reservations q ON q.tenant_scope=o.tenant_scope AND q.reservation_id=o.quota_reservation_id WHERE o.tenant_scope=$1 AND o.dispatch_id=$2 AND o.task_id=$3 AND o.payload_digest=$4 AND o.payload_json=$5 AND o.state='leased' AND o.lease_token IS NOT NULL FOR UPDATE OF o");
        let Some(sender) = tx.query_opt(&ownership_sql, &[&envelope.tenant_scope, &envelope.dispatch_id, &envelope.request.task_id, &envelope.payload_digest, &payload]).await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver outbox ownership lookup failed")))?
        else {
            return Err(A2AError::invalid_params("invalid durable receiver envelope"));
        };
        let sender_attempt: i64 = sender.get(0);
        let sender_token: String = sender.get(1);
        let sender_reservation = match (
            sender.get::<_, Option<String>>(2), sender.get::<_, Option<String>>(3),
            sender.get::<_, Option<i64>>(4), sender.get::<_, Option<i64>>(5),
            sender.get::<_, Option<i64>>(6), sender.get::<_, Option<String>>(7),
            sender.get::<_, Option<i64>>(8), sender.get::<_, Option<String>>(9),
        ) {
            (None, None, None, None, None, None, None, None) => None,
            (Some(binding_digest), Some(reservation_id), Some(version), Some(output), Some(events), Some(policy_id), Some(policy_revision), Some(policy_digest)) => Some(ExecutionReservation {
                reservation_id,
                reservation_version: u64::try_from(version).map_err(|_| A2AError::internal("execution reservation version is corrupt"))?,
                binding_digest,
                policy_id,
                policy_revision: u64::try_from(policy_revision).map_err(|_| A2AError::internal("execution reservation policy revision is corrupt"))?,
                policy_digest,
                budget: crate::ExecutionBudget::new(
                    u64::try_from(output).map_err(|_| A2AError::internal("execution output budget is corrupt"))?,
                    u64::try_from(events).map_err(|_| A2AError::internal("execution event budget is corrupt"))?,
                ).map_err(|_| A2AError::internal("execution reservation budget is corrupt"))?,
            }),
            _ => return Err(A2AError::internal("execution reservation binding is incomplete")),
        };
        if sender_reservation != envelope.execution_reservation {
            return Err(A2AError::invalid_params("invalid durable receiver execution reservation"));
        }
        let lookup=store.q("SELECT payload_digest,state,lease_until,lease_epoch,completion_kind,termination_json,frame_count,transcript_digest,quota_binding_digest,quota_reservation_id,quota_reservation_version,reserved_output_bytes,reserved_event_count,measured_output_bytes,measured_event_count FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND dispatch_id=$2 FOR UPDATE");
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
            let stored_reservation = (
                row.get::<_, Option<String>>(8),
                row.get::<_, Option<String>>(9),
                row.get::<_, Option<i64>>(10),
                row.get::<_, Option<i64>>(11),
                row.get::<_, Option<i64>>(12),
            );
            let expected_reservation = envelope.execution_reservation.as_ref().map(|reservation| (
                reservation.binding_digest.clone(),
                reservation.reservation_id.clone(),
                i64::try_from(reservation.reservation_version).unwrap_or(i64::MAX),
                i64::try_from(reservation.budget.max_output_bytes()).unwrap_or(i64::MAX),
                i64::try_from(reservation.budget.max_event_count()).unwrap_or(i64::MAX),
            ));
            if stored_reservation != expected_reservation.map_or((None, None, None, None, None), |value| (Some(value.0), Some(value.1), Some(value.2), Some(value.3), Some(value.4))) {
                return Err(A2AError::invalid_request("dispatch identity is already bound to another execution reservation"));
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
                let measured_bytes = events.iter().try_fold(0_i64, |total, event| {
                    let bytes = i64::try_from(serde_json::to_vec(event).map_err(|_| A2AError::internal("receiver replay measurement is corrupt"))?.len())
                        .map_err(|_| A2AError::internal("receiver replay measurement is corrupt"))?;
                    total.checked_add(bytes).ok_or_else(|| A2AError::internal("receiver replay measurement is corrupt"))
                })?;
                if row.get::<_, Option<i64>>(13) != Some(measured_bytes)
                    || row.get::<_, Option<i64>>(14) != i64::try_from(events.len()).ok()
                {
                    return Err(A2AError::internal("receiver replay measurement is corrupt"));
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
            if tx.execute(
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
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver reclaim failed")))?
                != 1
            {
                return Err(A2AError::internal("receiver reclaim failed"));
            }
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
                execution_reservation: envelope.execution_reservation.clone(),
            }));
        }
        let quota_binding = envelope.execution_reservation.as_ref().map(|value| value.binding_digest.as_str());
        let reservation_id = envelope.execution_reservation.as_ref().map(|value| value.reservation_id.as_str());
        let reservation_version = envelope.execution_reservation.as_ref().map(|value| i64::try_from(value.reservation_version).unwrap_or(i64::MAX));
        let reserved_output = envelope.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_output_bytes()).unwrap_or(i64::MAX));
        let reserved_events = envelope.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_event_count()).unwrap_or(i64::MAX));
        let insert=store.q("INSERT INTO __S__.receiver_inbox(tenant_scope,dispatch_id,payload_digest,payload_json,task_id,context_id,state,lease_epoch,lease_owner,lease_token,lease_until,accepted_at,updated_at,sender_attempt_no,sender_lease_token,quota_binding_digest,quota_reservation_id,quota_reservation_version,reserved_output_bytes,reserved_event_count) VALUES($1,$2,$3,$4,$5,$6,'processing',1,$7,$8,$9,$10,$10,$11,$12,$13,$14,$15,$16,$17)");
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
                &quota_binding,
                &reservation_id,
                &reservation_version,
                &reserved_output,
                &reserved_events,
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
            execution_reservation: envelope.execution_reservation,
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
                let reservation_id = lease.execution_reservation.as_ref().map(|value| value.reservation_id.as_str());
                let binding = lease.execution_reservation.as_ref().map(|value| value.binding_digest.as_str());
                let reservation_version = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.reservation_version).unwrap_or(i64::MAX));
                let reserved_output = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_output_bytes()).unwrap_or(i64::MAX));
                let reserved_events = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_event_count()).unwrap_or(i64::MAX));
                let sql = store.q("UPDATE __S__.receiver_inbox SET lease_until=$1,updated_at=$2 WHERE tenant_scope=$3 AND task_id=$4 AND dispatch_id=$5 AND payload_digest=$6 AND sender_attempt_no=$7 AND sender_lease_token=$8 AND state='processing' AND lease_owner=$9 AND lease_token=$10 AND lease_epoch=$11 AND lease_until=$12 AND lease_until>$2 AND quota_reservation_id IS NOT DISTINCT FROM $13 AND quota_binding_digest IS NOT DISTINCT FROM $14 AND quota_reservation_version IS NOT DISTINCT FROM $15 AND reserved_output_bytes IS NOT DISTINCT FROM $16 AND reserved_event_count IS NOT DISTINCT FROM $17");
                let changed = tx.execute(&sql, &[&until, &now, &lease.tenant_scope, &lease.task_id, &lease.dispatch_id, &lease.payload_digest, &i64::from(lease.sender_attempt_no), &lease.sender_lease_token, &lease.lease_owner, &lease.lease_token, &epoch, &lease.lease_until, &reservation_id, &binding, &reservation_version, &reserved_output, &reserved_events]).await
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
    #[allow(clippy::single_match_else)]
    async fn prepare_receiver_artifacts(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        _now: i64,
    ) -> Result<(Vec<MeshEvent>, Vec<crate::ArtifactStageRegistration>), A2AError> {
        if !events
            .iter()
            .any(|event| matches!(event, MeshEvent::Artifact { .. }))
        {
            return Ok((events.to_vec(), Vec::new()));
        }
        let Some(blobs) = self.artifact_store.as_ref() else {
            return Ok((events.to_vec(), Vec::new()));
        };
        let key_generation = blobs.active_key_generation();
        let tenant = lease.tenant_scope.clone();
        let task = lease.task_id.clone();
        let dispatch = lease.dispatch_id.clone();
        let (owner, context, revision, message, db_now) = self.run_retryable_transaction(&tenant, None, |store, tx| {
            let tenant=tenant.clone(); let task=task.clone(); let dispatch=dispatch.clone();
            Box::pin(async move {
                let q=store.q("SELECT t.owner_account_id,t.context_id,t.revision,o.message_id,__S__.db_millis() FROM __S__.tasks t JOIN __S__.outbox o ON o.tenant_scope=t.tenant_scope AND o.task_id=t.task_id AND o.dispatch_id=$3 WHERE t.tenant_scope=$1 AND t.task_id=$2");
                let row=tx.query_one(&q,&[&tenant,&task,&dispatch]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact producer lookup failed")))?;
                Ok((row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,i64>(2),row.get::<_,String>(3),row.get::<_,i64>(4)))
            })
        }).await?;
        let mut prepared = Vec::with_capacity(events.len());
        let mut staged_artifacts = Vec::new();
        for (ordinal, event) in events.iter().enumerate() {
            let (name, media_type, bytes) = match event {
                MeshEvent::Artifact {
                    name,
                    media_type,
                    content,
                } => match crate::bridge::internal_artifact_payload(content) {
                    Some(crate::bridge::InternalArtifactPayload::Binary { bytes }) => {
                        use base64::Engine as _;
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(bytes)
                            .map_err(|_| A2AError::internal("artifact payload is corrupt"))?;
                        (name.clone(), media_type.clone(), bytes)
                    }
                    Some(crate::bridge::InternalArtifactPayload::Published { .. }) => {
                        prepared.push(event.clone());
                        continue;
                    }
                    None => (
                        name.clone(),
                        media_type.clone(),
                        content.as_bytes().to_vec(),
                    ),
                },
                _ => {
                    prepared.push(event.clone());
                    continue;
                }
            };
            if bytes.len() as u64 > self.artifact_runtime_limits.max_artifact_bytes {
                return Err(A2AError::invalid_request(
                    "artifact payload exceeds configured limit",
                ));
            }
            let semantic = content_digest(
                format!(
                    "{}\0{}\0{}",
                    lease.dispatch_id,
                    ordinal,
                    content_digest(&bytes)
                )
                .as_bytes(),
            );
            let artifact_id = format!("artifact-{}", &semantic[7..39]);
            let upload_id = format!("upload-{}", &semantic[39..71]);
            let object_id = content_digest(
                format!(
                    "{}\0{}\0confidential\0{}",
                    lease.tenant_scope,
                    owner,
                    content_digest(&bytes)
                )
                .as_bytes(),
            );
            let domain =
                crate::EncryptionDomain::new(format!("{}/confidential", lease.tenant_scope))
                    .map_err(|_| A2AError::invalid_params("invalid artifact encryption domain"))?;
            let producer = crate::ArtifactProducer::new(
                &lease.tenant_scope,
                &owner,
                &lease.task_id,
                &context,
                &message,
                &lease.dispatch_id,
            )
            .map_err(|_| A2AError::invalid_params("invalid artifact producer"))?;
            let retain_until = db_now
                .checked_add(self.artifact_runtime_limits.retention_millis)
                .ok_or_else(|| A2AError::invalid_params("artifact retention overflow"))?;
            let policy_digest = crate::ContentDigestV1::of(b"smesh-artifact-default/v1");
            let policy = crate::ArtifactPolicySnapshot::new(
                "artifact-default",
                1,
                policy_digest,
                db_now,
                retain_until,
            )
            .map_err(|_| A2AError::invalid_params("invalid artifact policy"))?;
            let manifest = crate::ArtifactManifestV1::new(
                &artifact_id,
                name,
                Some("Durably replayable SMESH output".to_owned()),
                media_type.clone(),
                crate::ArtifactClassification::Confidential,
                domain,
                key_generation.clone(),
                producer,
                vec![],
                policy,
                db_now,
                &bytes,
            )
            .map_err(|_| A2AError::invalid_params("invalid artifact payload"))?;
            let registration = crate::ArtifactStageRegistration {
                tenant_scope: lease.tenant_scope.clone(),
                account_id: owner.clone(),
                owner_account_id: owner.clone(),
                task_id: lease.task_id.clone(),
                context_id: context.clone(),
                message_id: message.clone(),
                dispatch_id: lease.dispatch_id.clone(),
                upload_id,
                artifact_id: artifact_id.clone(),
                object_id,
                content_digest: manifest.content_digest().to_string(),
                manifest_digest: manifest.manifest_digest().to_string(),
                ciphertext_digest: String::new(),
                plaintext_length: manifest.plaintext_length(),
                ciphertext_length: 0,
                classification: "confidential".to_owned(),
                encryption_domain: format!("{}/confidential", lease.tenant_scope),
                key_generation: key_generation.clone(),
                canonical_manifest_json: manifest.canonical_json().to_owned(),
                chunks: manifest
                    .chunks()
                    .iter()
                    .map(|chunk| crate::ArtifactChunkRegistration {
                        ordinal: chunk.ordinal(),
                        byte_offset: chunk.offset(),
                        plaintext_length: chunk.length(),
                        content_digest: chunk.digest().to_string(),
                    })
                    .collect(),
                provenance: Vec::new(),
                media_type,
                reference_id: format!("reference-{}", &semantic[7..39]),
                task_revision: u64::try_from(revision)
                    .map_err(|_| A2AError::internal("task revision corrupt"))?,
                policy_id: "artifact-default".to_owned(),
                policy_revision: 1,
                policy_digest: policy_digest.to_string(),
                created_at: db_now,
                stage_locator: String::new(),
                final_locator: String::new(),
                nonce: [0; 12],
                retain_until,
                quota_binding_digest: lease
                    .execution_reservation
                    .as_ref()
                    .map(|value| value.binding_digest.clone()),
                receiver_lease_epoch: lease.lease_epoch,
                receiver_lease_token: lease.lease_token.clone(),
            };
            let staged =
                crate::ArtifactAuthority::stage_artifact(self, registration, bytes).await?;
            staged_artifacts.push(staged);
            prepared.push(crate::bridge::published_artifact_event(
                serde_json::to_string(&manifest.to_a2a_projection())
                    .map_err(|_| A2AError::internal("artifact projection failed"))?,
            ));
        }
        Ok((prepared, staged_artifacts))
    }

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
        let (prepared_events, staged_artifacts) =
            self.prepare_receiver_artifacts(lease, events, now).await?;
        let events = prepared_events.as_slice();
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
        let measured_output_bytes = encoded.iter().try_fold(0_u64, |total, frame| {
            total
                .checked_add(u64::try_from(frame.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| A2AError::invalid_params("receiver transcript byte count overflow"))
        })?;
        let measured_event_count = u64::try_from(encoded.len())
            .map_err(|_| A2AError::invalid_params("receiver transcript event count overflow"))?;
        if let Some(reservation) = &lease.execution_reservation {
            if measured_output_bytes > reservation.budget.max_output_bytes()
                || measured_event_count > reservation.budget.max_event_count()
            {
                return Err(A2AError::invalid_params(
                    "receiver transcript exceeds reserved execution budget",
                ));
            }
        } else if self.quota_enforcement {
            return Err(A2AError::invalid_params(
                "receiver lease has no execution reservation",
            ));
        }
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
            let staged_artifacts = staged_artifacts.clone();
            Box::pin(async move {
        let now = store.effective_now(tx, now).await?;
        let reservation_id = lease.execution_reservation.as_ref().map(|value| value.reservation_id.as_str());
        let binding = lease.execution_reservation.as_ref().map(|value| value.binding_digest.as_str());
        let reservation_version = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.reservation_version).unwrap_or(i64::MAX));
        let reserved_output = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_output_bytes()).unwrap_or(i64::MAX));
        let reserved_events = lease.execution_reservation.as_ref().map(|value| i64::try_from(value.budget.max_event_count()).unwrap_or(i64::MAX));
        let fence=store.q("SELECT 1 FROM __S__.receiver_inbox WHERE tenant_scope=$1 AND task_id=$2 AND dispatch_id=$3 AND payload_digest=$4 AND sender_attempt_no=$5 AND sender_lease_token=$6 AND state='processing' AND lease_owner=$7 AND lease_token=$8 AND lease_epoch=$9 AND lease_until=$10 AND lease_until>$11 AND (EXISTS(SELECT 1 FROM __S__.cancellation_intents c WHERE c.tenant_scope=$1 AND c.dispatch_id=$3 AND c.state='requested'))=$12 AND quota_reservation_id IS NOT DISTINCT FROM $13 AND quota_binding_digest IS NOT DISTINCT FROM $14 AND quota_reservation_version IS NOT DISTINCT FROM $15 AND reserved_output_bytes IS NOT DISTINCT FROM $16 AND reserved_event_count IS NOT DISTINCT FROM $17 FOR UPDATE");
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
                    &reservation_id,
                    &binding,
                    &reservation_version,
                    &reserved_output,
                    &reserved_events,
                ],
            )
            .await
            .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver fence lookup failed")))?
            .is_none()
        {
            return Err(A2AError::invalid_request("receiver lease is stale"));
        }
        // Artifact metadata becomes authoritative only inside the fenced receiver
        // completion transaction. Staging is the sole pre-transaction side effect.
        for r in &staged_artifacts {
            if r.tenant_scope != lease.tenant_scope
                || r.task_id != lease.task_id
                || r.dispatch_id != lease.dispatch_id
                || r.receiver_lease_epoch != lease.lease_epoch
                || r.receiver_lease_token != lease.lease_token
                || r.quota_binding_digest.as_deref() != binding
                || r.task_revision == 0
                || r.policy_revision == 0
                || r.created_at > r.retain_until
                || r.ciphertext_length < 16
            {
                return Err(A2AError::invalid_request("artifact receiver binding is stale"));
            }
            let locator_fence = store.q("SELECT pg_advisory_xact_lock(hashtextextended($1,0))");
            tx.execute(&locator_fence,&[&r.stage_locator]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact stage fence failed")))?;
            let claimed = store.q("SELECT EXISTS(SELECT 1 FROM __S__.artifact_orphan_candidates WHERE stage_locator=$1)");
            if tx.query_one(&claimed,&[&r.stage_locator]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact stage ownership lookup failed")))?.get::<_,bool>(0) {
                return Err(A2AError::invalid_request("artifact stage is owned by orphan cleanup"));
            }
            let key = store.q("INSERT INTO __S__.artifact_key_generations(tenant_scope,encryption_domain,key_generation,state,created_at) VALUES($1,$2,$3,'active',$4) ON CONFLICT DO NOTHING");
            tx.execute(&key, &[&r.tenant_scope,&r.encryption_domain,&r.key_generation,&now]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact key registration failed")))?;
            let nonce = r.nonce.to_vec();
            store.publication_fault(ArtifactPublicationTestFault::BeforeContentObject)?;
            let object = store.q("INSERT INTO __S__.content_objects(tenant_scope,owner_account_id,object_id,content_digest,classification,encryption_domain,key_generation,plaintext_length,ciphertext_length,ciphertext_digest,backend_locator,nonce,state,reference_count,retain_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'staged',0,$13,$14) ON CONFLICT DO NOTHING");
            let object_inserted=tx.execute(&object,&[&r.tenant_scope,&r.owner_account_id,&r.object_id,&r.content_digest,&r.classification,&r.encryption_domain,&r.key_generation,&i64::try_from(r.plaintext_length).unwrap_or(i64::MAX),&i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX),&r.ciphertext_digest,&r.final_locator,&nonce,&r.retain_until,&r.created_at]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact object registration failed")))? == 1;
            store.publication_fault(ArtifactPublicationTestFault::AfterContentObject)?;
            let verify = store.q("SELECT owner_account_id,content_digest,classification,encryption_domain,plaintext_length FROM __S__.content_objects WHERE tenant_scope=$1 AND object_id=$2");
            let row=tx.query_one(&verify,&[&r.tenant_scope,&r.object_id]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact object verification failed")))?;
            if row.get::<_,String>(0)!=r.owner_account_id || row.get::<_,String>(1)!=r.content_digest || row.get::<_,String>(2)!=r.classification || row.get::<_,String>(3)!=r.encryption_domain || row.get::<_,i64>(4)!=i64::try_from(r.plaintext_length).unwrap_or(i64::MAX) { return Err(A2AError::invalid_request("artifact registration conflicts with immutable state")); }
            store.publication_fault(ArtifactPublicationTestFault::BeforeManifest)?;
            let manifest=store.q("INSERT INTO __S__.artifact_manifests(tenant_scope,artifact_id,manifest_digest,object_id,schema_version,canonical_json,owner_account_id,task_id,context_id,message_id,dispatch_id,media_type,plaintext_length,classification,encryption_domain,policy_id,policy_revision,policy_digest,created_at,retain_until) VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT DO NOTHING");
            tx.execute(&manifest,&[&r.tenant_scope,&r.artifact_id,&r.manifest_digest,&r.object_id,&r.canonical_manifest_json,&r.owner_account_id,&r.task_id,&r.context_id,&r.message_id,&r.dispatch_id,&r.media_type,&i64::try_from(r.plaintext_length).unwrap_or(i64::MAX),&r.classification,&r.encryption_domain,&r.policy_id,&i64::try_from(r.policy_revision).unwrap_or(i64::MAX),&r.policy_digest,&r.created_at,&r.retain_until]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact manifest registration failed")))?;
            store.publication_fault(ArtifactPublicationTestFault::AfterManifest)?;
            store.publication_fault(ArtifactPublicationTestFault::BeforeChunkBatch)?;
            let chunk_sql=store.q("INSERT INTO __S__.artifact_chunks(tenant_scope,artifact_id,ordinal,byte_offset,plaintext_length,content_digest) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING");
            for chunk in &r.chunks { tx.execute(&chunk_sql,&[&r.tenant_scope,&r.artifact_id,&i32::try_from(chunk.ordinal).unwrap_or(i32::MAX),&i64::try_from(chunk.byte_offset).unwrap_or(i64::MAX),&i64::try_from(chunk.plaintext_length).unwrap_or(i64::MAX),&chunk.content_digest]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact chunk registration failed")))?; }
            store.publication_fault(ArtifactPublicationTestFault::AfterChunkBatch)?;
            store.publication_fault(ArtifactPublicationTestFault::BeforeProvenanceBatch)?;
            let provenance_sql=store.q("INSERT INTO __S__.provenance_edges(tenant_scope,child_artifact_id,ordinal,parent_artifact_id,relation) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING");
            for edge in &r.provenance { tx.execute(&provenance_sql,&[&r.tenant_scope,&r.artifact_id,&i32::try_from(edge.ordinal).unwrap_or(i32::MAX),&edge.parent_artifact_id,&edge.relation]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact provenance registration failed")))?; }
            store.publication_fault(ArtifactPublicationTestFault::AfterProvenanceBatch)?;
            store.publication_fault(ArtifactPublicationTestFault::BeforeReference)?;
            let reference=store.q("INSERT INTO __S__.artifact_references(tenant_scope,reference_id,artifact_id,task_id,context_id,owner_account_id,task_revision,state,retain_until,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9) ON CONFLICT DO NOTHING RETURNING reference_id");
            let reference_inserted=tx.query_opt(&reference,&[&r.tenant_scope,&r.reference_id,&r.artifact_id,&r.task_id,&r.context_id,&r.owner_account_id,&i64::try_from(r.task_revision).unwrap_or(i64::MAX),&r.retain_until,&r.created_at]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact reference registration failed")))?.is_some();
            if reference_inserted { let increment=store.q("UPDATE __S__.content_objects o SET reference_count=o.reference_count+1 WHERE o.tenant_scope=$1 AND o.object_id=$2"); tx.execute(&increment,&[&r.tenant_scope,&r.object_id]).await.map_err(|e|Self::transaction_body_error(&e,A2AError::internal("artifact reference accounting failed")))?; }
            store.publication_fault(ArtifactPublicationTestFault::AfterReference)?;
            store.publication_fault(ArtifactPublicationTestFault::BeforeUploadIntent)?;
            if object_inserted { let upload=store.q("INSERT INTO __S__.upload_intents(tenant_scope,upload_id,artifact_id,object_id,state,stage_locator,final_locator,ciphertext_digest,ciphertext_length,lease_epoch,created_at,updated_at) VALUES($1,$2,$3,$4,'committed',$5,$6,$7,$8,1,$9,$9) ON CONFLICT DO NOTHING");
            tx.execute(&upload,&[&r.tenant_scope,&r.upload_id,&r.artifact_id,&r.object_id,&r.stage_locator,&r.final_locator,&r.ciphertext_digest,&i64::try_from(r.ciphertext_length).unwrap_or(i64::MAX),&now]).await.map_err(|e| Self::transaction_body_error(&e,A2AError::internal("artifact upload registration failed")))?; }
            store.publication_fault(ArtifactPublicationTestFault::AfterUploadIntent)?;
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
        store.publication_fault(ArtifactPublicationTestFault::BeforeReceiverEffect)?;
        if loopback_effect {
            let effect = store.q("INSERT INTO __S__.loopback_effects VALUES($1,$2,'accepted',$3)");
            tx.execute(&effect, &[&lease.tenant_scope, &lease.dispatch_id, &now])
                .await
                .map_err(|error| Self::transaction_body_error(&error, A2AError::internal("receiver effect commit failed")))?;
        }
        store.publication_fault(ArtifactPublicationTestFault::AfterReceiverEffect)?;
        store.publication_fault(ArtifactPublicationTestFault::BeforeReceiverFrames)?;
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
        store.publication_fault(ArtifactPublicationTestFault::AfterReceiverFrames)?;
        let count = i64::try_from(encoded.len())
            .map_err(|_| A2AError::internal("too many receiver frames"))?;
        let digest = content_digest(&transcript);
        store.publication_fault(ArtifactPublicationTestFault::BeforeReceiverCompletion)?;
        let update=store.q("UPDATE __S__.receiver_inbox SET state='completed',completion_kind=$1,termination_json=$2,frame_count=$3,transcript_digest=$4,measured_output_bytes=$5,measured_event_count=$6,completed_at=$7,updated_at=$7,lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE tenant_scope=$8 AND dispatch_id=$9 AND state='processing' AND lease_token=$10 AND lease_epoch=$11");
        if tx
            .execute(
                &update,
                &[
                    &kind,
                    &termination_json,
                    &count,
                    &digest,
                    &i64::try_from(measured_output_bytes).map_err(|_| A2AError::internal("receiver output measurement overflow"))?,
                    &i64::try_from(measured_event_count).map_err(|_| A2AError::internal("receiver event measurement overflow"))?,
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
        store.publication_fault(ArtifactPublicationTestFault::AfterReceiverCompletion)?;
                Ok(())
            })
        })
        .await?;
        crate::artifact_production_checkpoint("receiver_complete_before_sender_delivery_commit");
        Ok(())
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
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
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
        self.cancel_authorized_with_quota(scope, task_id, now, audit, None, None)
            .await
    }

    async fn cancel_authorized_with_quota(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
        quota_reservation: Option<&QuotaReservationInput>,
        quota_intent: Option<&crate::QuotaIntent>,
    ) -> Result<CancellationOutcome, A2AError> {
        if self.quota_enforcement && quota_intent.is_none() {
            return Err(crate::quota::quota_authority_unavailable());
        }
        if quota_intent
            .is_some_and(|intent| intent.operation() != crate::QuotaOperation::TaskCancel)
        {
            return Err(A2AError::invalid_request("quota intent operation mismatch"));
        }
        if audit.tenant_scope() != scope.tenant_scope()
            || audit.actor_account_id() != scope.owner_account_id()
            || audit.effect() != AuthorizationDecisionEffect::Allow
        {
            return Err(A2AError::invalid_request(
                "authorized cancellation scope mismatch",
            ));
        }
        if let Some(intent) = quota_intent {
            self.charge_quota_request(intent, now).await?;
        }
        let tenant = scope.tenant_scope().to_owned();
        let account = scope.owner_account_id().to_owned();
        let own = scope.visibility() == VisibilityScope::Own;
        let task_id = task_id.to_owned();
        let quota_reservation = quota_reservation.cloned();
        let quota_intent = quota_intent.cloned();
        let denial_intent = quota_intent.clone();
        let result = self.run_retryable_transaction(&tenant, Some(&account), |store, tx| {
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
        enqueue_postgres_terminal_callbacks(store,tx,&tenant,&task,next,now).await?;
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
                Ok(CancellationOutcome::Canceled(task))
            })
        })
        .await;
        self.finalize_quota_result(denial_intent.as_ref(), now, result)
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
