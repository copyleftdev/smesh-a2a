//! A2A v1 interoperability gateway for SMESH swarms.

/// Backend-neutral artifact contracts, encrypted POSIX CAS, authorization, and lifecycle.
pub mod artifact;
mod artifact_backup_executor;
mod artifact_checkpoint;
mod artifact_gc;
mod artifact_migration;
mod artifact_migration_executor;
mod artifact_operator_plan;
mod artifact_orphan_scanner;
mod artifact_promoter;
mod artifact_reencryption_executor;
mod artifact_restore_executor;
/// Bearer and mTLS principal verification and request-scoping boundaries.
pub mod auth;
/// Server-owned tenant authorization policy and immutable request context.
pub mod authorization;
mod bridge;
mod callback_authority;
mod callback_worker;
mod card;
mod channel;
mod durable_authority;
mod durable_dispatch;
mod durable_handler;
#[cfg(test)]
mod durable_handler_tests;
mod executor;
mod full_matrix_capture;
mod full_matrix_replay;
mod fuzzing;
mod guard;
mod input;
mod lifeline;
mod lifeline_director;
mod lifeline_teams;
mod lifeline_topology;
mod loopback;
mod outbox_driver;
mod policy;
mod postgres_store;
/// Secure operator-enrolled callback policy, SSRF validation, and signing.
pub mod push;
mod quota;
mod runtime_config;
mod runtime_trace;
mod runtime_worker;
mod server;
mod sqlite_store;
mod store;
mod task_state;
/// Closed, bounded optional OpenTelemetry projection schema and exporter owner.
pub mod telemetry;
/// Bounded pre-persistence trace classification, redaction, and privacy verification.
pub mod trace_privacy;
/// Production exposure policy, TLS material loading, reload, and bounded acceptor.
pub mod transport;

pub use artifact::{
    ARTIFACT_CHUNK_BYTES, ArtifactBackupInventory, ArtifactBackupObject, ArtifactCatalog,
    ArtifactChunkV1, ArtifactClassification, ArtifactKeyRotationPlan, ArtifactKeyring,
    ArtifactManifestV1, ArtifactMigrationPlan, ArtifactPolicySnapshot, ArtifactProducer,
    ArtifactStoreConfig, ArtifactStoreError, ContentDigestV1, DerivedFrom, DerivedRelation,
    EncryptionDomain, InMemoryKeyring, JsonArtifactKeyring, PosixArtifactBlobStore,
    ReloadingArtifactKeyring, RetentionDecision, StageOrphanCleanup, StagedArtifact,
    StoredArtifact,
};
pub use artifact_backup_executor::ArtifactBackupOutcome;
#[doc(hidden)]
pub use artifact_checkpoint::artifact_production_checkpoint;
pub use artifact_gc::{ArtifactGcHandle, ArtifactGcState, spawn_artifact_gc};
pub use artifact_migration::{
    ArtifactMigrationPlanFile, InlineArtifact, InlineArtifactKind, InlineArtifactPart,
    extract_inline_artifacts,
};
pub use artifact_operator_plan::{
    ArtifactBackupPlanFile, ArtifactKeyRotationPlanFile, ArtifactRestorePlanFile, SignatureHook,
};
pub use artifact_orphan_scanner::{
    ArtifactOrphanScannerHandle, ArtifactOrphanScannerState, spawn_artifact_orphan_scanner,
};
pub use artifact_promoter::{
    ArtifactPromoterHandle, ArtifactPromoterState, spawn_artifact_promoter,
    spawn_artifact_promoter_with_telemetry,
};
pub use artifact_reencryption_executor::ArtifactKeyRotationOutcome;
pub use artifact_restore_executor::ArtifactRestoreOutcome;
pub use authorization::{
    AuthorizationContext, AuthorizationError, AuthorizationMiddlewareState, AuthorizationPolicy,
    Operation, TENANT_SELECTOR_HEADER, TenantRole, VisibilityScope, authorize_request,
    current_authorization_context, current_quota_reservation, scope_quota_reservation,
};
pub use bridge::{DispatchError, MeshDispatcher, MeshEvent, MeshRequest};
pub use callback_authority::{
    CallbackAuthority, CallbackBackend, CallbackCapabilities, CallbackConfig, CallbackConfigId,
    CallbackConfigPage, CallbackConfigState, CallbackDeleteOutcome, CallbackDeliveryCategory,
    CallbackDeliveryDisposition, CallbackDeliveryState, CallbackEnrollmentBinding,
    CallbackFailCommand, CallbackLease, CallbackPolicySnapshot, CallbackReadiness,
    CallbackTerminalTestFault, ConfigCreateCommand, ConfigDeleteCommand, ConfigGetCommand,
    ConfigListCommand, ConfigPageSize, DeliveryClaimCommand, DeliveryFence, LeaseDurationMillis,
};
pub use callback_worker::{
    CallbackAttemptSender, CallbackJitter, CallbackQuotaAuthority, CallbackQuotaDecision,
    CallbackWorkerError, CallbackWorkerHandle, ProductionCallbackQuotaAuthority,
    SecureCallbackSender, SystemCallbackJitter, callback_quota_semantic_id,
    callback_request_accounted_bytes,
};
pub use card::{
    LiveAgentCard, build_agent_card, build_agent_card_with_push_readiness,
    build_authenticated_agent_card, build_secured_agent_card, build_secured_agent_card_with_policy,
};
pub use channel::{ChannelDispatcher, DispatchCommand};
pub use durable_authority::{
    AdmissionOutcome, AdmissionRecord, ArtifactAuthority, ArtifactBackupLease,
    ArtifactCapabilities, ArtifactChunkRegistration, ArtifactGcClaim, ArtifactHold,
    ArtifactPromotionClaim, ArtifactProvenanceRegistration, ArtifactReadLease,
    ArtifactReadMetadata, ArtifactRuntimeLimits, ArtifactStageReference, ArtifactStageRegistration,
    AtomicRecordCounts, AttemptDisposition, AuditProjectionAuthority, AuditProjectionCapabilities,
    AuditProjectionEventKind, AuditProjectionLease, AuditProjectionSource, AuditProjectionState,
    AuthorityCapabilities, AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown,
    AuthorizationAuditInput, AuthorizationAuditParts, AuthorizationAuditSink,
    AuthorizationDecisionEffect, AuthorizedMutation, AuthorizedTaskRead, CancellationAuthority,
    CancellationOutcome, ChangeObservation, ChangeObserver, DurableAuthority, ExecutionReservation,
    IntoDurableAuthority, LeaseRenewalOutcome, OutboxAuthority, OutboxLease, OwnedTaskScope,
    PollInterval, QuotaLease, QuotaLeaseAuthority, QuotaReservationInput, ReceiverAdmission,
    ReceiverAuthority, ReceiverLease, SendMessageAdmission, StreamTranscriptBatch,
    SubscriptionCursor, TRUSTED_SINGLE_TENANT_SCOPE, TaskAdmission, TaskEventBatch, TaskLifecycle,
    TelemetryCorrelation, TranscriptAuthority, TransitionOutcome, authorized_message_identity,
    canonical_send_message_digest, canonical_send_message_digest_v2,
};
pub use durable_dispatch::{
    DurableDispatchEnvelope, DurableInterruptionKind, DurableLoopbackEndpoint,
    DurableReceiverResult, DurableReceiverTermination, InjectedClock, SystemClockTicker,
};
pub use executor::{ExecutionLimits, SmeshExecutor};
pub use full_matrix_capture::{
    A2aCaptureAdapter, ArtifactCaptureAdapter, CanonicalCapture, CaptureError, CaptureEvent,
    CaptureFailure, CaptureGapReason, CaptureKind, CaptureParent, CaptureProducer, CaptureReceipt,
    CaptureStream, CapturedContent, FULL_MATRIX_CAPTURE_SCHEMA_VERSION, HumanConsoleCaptureAdapter,
    ProducerIdentity, ProducerKind, SmeshJournalCaptureAdapter, ToolCaptureError,
    ToolMcpCaptureAdapter,
};
pub use full_matrix_replay::{
    CANONICALIZATION, CAUSAL_SOURCE_SCHEMA_VERSION, CausalMerger, CausalSourceEvent,
    FULL_MATRIX_REPLAY_SCHEMA_VERSION, HybridLogicalClock, MergeLimits, MissingParentPolicy,
    ProjectionReceipt, REPLAY_RECEIPT_SCHEMA_VERSION, ReplayError, ReplayReceipt, ReplaySealInput,
    SealedReplay, capture_causal_source_jsonl, merge_and_seal_jsonl,
    reconcile_published_replay_temporary, reconcile_unpublished_replay_temporary,
    verify_replay_receipt, verify_sealed_replay,
};
#[doc(hidden)]
pub use fuzzing::{fuzz_decode_opaque_page_token, fuzz_parse_callback_page_token};
pub use input::{InputError, InputLimits, extract_text};
pub use lifeline::{
    TraceError, TraceEvent, generate_lifeline_trace, verify_trace, write_lifeline_trace,
};
pub use lifeline_director::{
    LIFELINE_DIRECTOR_SCHEMA_VERSION, LifelineDirectorError, LifelineDirectorManifest,
    LifelineDirectorOperation, LifelineDirectorOperationReceipt, LifelineDirectorRun,
    LifelineResponseDirector, ResolvedLifelineGateway,
};
pub use lifeline_teams::{
    LIFELINE_TEAM_DISCLAIMER, LIFELINE_TEAM_SCHEMA_VERSION, LifelineLocalTool, LifelineTeam,
    LifelineTeamError, LifelineTeamManifest, LifelineTeamRole, RunningLifelineTeamTopology,
    RunningLifelineTeams,
};
pub use lifeline_topology::{
    LIFELINE_DISCOVERY_DISCLAIMER, LIFELINE_TOPOLOGY_SCHEMA_VERSION, LifelineAuthentication,
    LifelineEndpoint, LifelineGateway, LifelineGeography, LifelineListener, LifelineLogisticsRoute,
    LifelineSkill, LifelineTopologyError, LifelineTopologyManifest, RunningLifelineTopology,
};
pub use loopback::LoopbackDispatcher;
pub use policy::{
    ArtifactManifest, COMPLETION_POLICY_V1, ClosedAttestation, CompletionEvidence,
    CompletionPolicySpec, CompletionReceipt, CompletionSnapshot, PolicyBlock, PolicyBlockReason,
    PolicyCheckpoint, PolicyDecision, PolicyError, RatificationReceipt, RatificationStatement,
    TrustedAuthority, VersionedCompletionPolicy, artifact_set_digest, completion_evidence_digest,
    content_digest,
};
pub use postgres_store::{
    ArtifactMigrationOutcome, ArtifactPublicationTestFault, AuthorizationAuditCleanup,
    PostgresStoreConfig, PostgresStoreError, PostgresTaskStore, PostgresTransactionTestFault,
};
pub use quota::{
    ExecutionBudget, QuotaAlgorithm, QuotaCharge, QuotaDimension, QuotaExceeded, QuotaIntent,
    QuotaLeaseKind, QuotaOperation, QuotaPolicy, QuotaPolicyError, QuotaReconciliationPlan,
    QuotaReconciliationTarget, QuotaScopeKind, QuotaSubject,
};
pub use runtime_config::{GatewayMode, GatewayModeError, RuntimeModeConfig};
pub use runtime_trace::{
    CorrelatingRuntimeProcessor, RuntimeCancellationOutcome, RuntimeClaimKind, RuntimeEventCapture,
    RuntimeTerminalState, RuntimeTrace, RuntimeTraceDetails, RuntimeTraceError, RuntimeTraceEvent,
    RuntimeTraceKind,
};
pub use runtime_worker::{
    RuntimeAdmissionProcessor, RuntimeEventSink, RuntimeTask, RuntimeTaskProcessor, RuntimeWorker,
    RuntimeWorkerConfig, RuntimeWorkerHandle,
};
pub use server::{
    CompletionPolicyStore, DurableGateway, GatewayConfig,
    build_authenticated_durable_loopback_gateway, build_authenticated_router,
    build_authenticated_router_with_trace, build_authorized_durable_loopback_gateway,
    build_authorized_durable_loopback_gateway_with_telemetry, build_durable_loopback_gateway,
    build_durable_loopback_gateway_with_telemetry, build_router, build_router_with_policy,
    build_router_with_policy_and_trace, build_router_with_sqlite,
    build_router_with_sqlite_and_trace, build_router_with_trace,
};
pub use sqlite_store::{LegacyTenantBinding, SqliteStoreError, SqliteTaskStore};
pub use store::BoundedTaskStore;
#[doc(hidden)]
pub use task_state::task_state_transition_allowed;
pub use trace_privacy::{
    DataClass, PrivacyError, PrivacyPolicy, PublicProjectionReceipt, PublicTraceManifest,
    RedactionAction, RedactionLogEntry, RedactionRule, RestrictedStoragePolicy,
    RestrictedTraceManifest, RunHmacKey, SanitizedTrace, TraceArtifactBinding, TraceArtifactOrigin,
    TraceArtifactProvenance, sanitize_public_trace, sanitize_public_trace_with_receipts,
    scan_public_trace, verify_sanitized_trace,
};
