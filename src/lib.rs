//! A2A v1 interoperability gateway for SMESH swarms.

/// Bearer and mTLS principal verification and request-scoping boundaries.
pub mod auth;
/// Server-owned tenant authorization policy and immutable request context.
pub mod authorization;
mod bridge;
mod card;
mod channel;
mod durable_authority;
mod durable_dispatch;
mod durable_handler;
#[cfg(test)]
mod durable_handler_tests;
mod executor;
mod guard;
mod input;
mod lifeline;
mod loopback;
mod outbox_driver;
mod policy;
mod runtime_config;
mod runtime_trace;
mod runtime_worker;
mod server;
mod sqlite_store;
mod store;
/// Production exposure policy, TLS material loading, reload, and bounded acceptor.
pub mod transport;

pub use authorization::{
    AuthorizationContext, AuthorizationError, AuthorizationMiddlewareState, AuthorizationPolicy,
    Operation, TENANT_SELECTOR_HEADER, TenantRole, VisibilityScope, current_authorization_context,
};
pub use bridge::{DispatchError, MeshDispatcher, MeshEvent, MeshRequest};
pub use card::{
    build_agent_card, build_authenticated_agent_card, build_secured_agent_card,
    build_secured_agent_card_with_policy,
};
pub use channel::{ChannelDispatcher, DispatchCommand};
pub use durable_authority::{
    AdmissionOutcome, AdmissionRecord, AtomicRecordCounts, AttemptDisposition,
    AuthorityDiagnostics, AuthorityIdentity, AuthorityShutdown, AuthorizationAuditInput,
    AuthorizationAuditParts, AuthorizationAuditSink, AuthorizationDecisionEffect,
    AuthorizedTaskRead, CancellationAuthority, CancellationOutcome, ChangeObservation,
    ChangeObserver, DurableAuthority, IntoDurableAuthority, OutboxAuthority, OutboxLease,
    OwnedTaskScope, PollInterval, ReceiverAdmission, ReceiverAuthority, ReceiverLease,
    SendMessageAdmission, StreamTranscriptBatch, SubscriptionCursor, TRUSTED_SINGLE_TENANT_SCOPE,
    TaskAdmission, TaskEventBatch, TaskLifecycle, TranscriptAuthority, TransitionOutcome,
    authorized_message_identity, canonical_send_message_digest, canonical_send_message_digest_v2,
};
pub use durable_dispatch::{
    DurableDispatchEnvelope, DurableInterruptionKind, DurableLoopbackEndpoint,
    DurableReceiverResult, DurableReceiverTermination, InjectedClock, SystemClockTicker,
};
pub use executor::{ExecutionLimits, SmeshExecutor};
pub use input::{InputError, InputLimits, extract_text};
pub use lifeline::{
    TraceError, TraceEvent, generate_lifeline_trace, verify_trace, write_lifeline_trace,
};
pub use loopback::LoopbackDispatcher;
pub use policy::{
    ArtifactManifest, COMPLETION_POLICY_V1, ClosedAttestation, CompletionEvidence,
    CompletionPolicySpec, CompletionReceipt, CompletionSnapshot, PolicyBlock, PolicyBlockReason,
    PolicyCheckpoint, PolicyDecision, PolicyError, RatificationReceipt, RatificationStatement,
    TrustedAuthority, VersionedCompletionPolicy, artifact_set_digest, completion_evidence_digest,
    content_digest,
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
    build_durable_loopback_gateway, build_router, build_router_with_policy,
    build_router_with_policy_and_trace, build_router_with_sqlite,
    build_router_with_sqlite_and_trace, build_router_with_trace,
};
pub use sqlite_store::{LegacyTenantBinding, SqliteStoreError, SqliteTaskStore};
pub use store::BoundedTaskStore;
