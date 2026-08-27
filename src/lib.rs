//! A2A v1 interoperability gateway for SMESH swarms.

mod bridge;
mod card;
mod channel;
mod executor;
mod guard;
mod input;
mod lifeline;
mod loopback;
mod policy;
mod runtime_config;
mod runtime_trace;
mod runtime_worker;
mod server;
mod sqlite_store;
mod store;

pub use bridge::{DispatchError, MeshDispatcher, MeshEvent, MeshRequest};
pub use card::build_agent_card;
pub use channel::{ChannelDispatcher, DispatchCommand};
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
    CompletionPolicyStore, GatewayConfig, build_router, build_router_with_policy,
    build_router_with_policy_and_trace, build_router_with_sqlite,
    build_router_with_sqlite_and_trace, build_router_with_trace,
};
pub use sqlite_store::{SqliteStoreError, SqliteTaskStore};
pub use store::BoundedTaskStore;
