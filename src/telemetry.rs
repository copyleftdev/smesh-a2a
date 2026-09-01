//! Closed, bounded observability schema.
//!
//! Durable authority rows and the bounded recent-window `runtime-trace/3` remain authoritative. Values
//! admitted here are safe only for the optional, lossy OTLP projection.
#![allow(
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_precision_loss,
    clippy::struct_field_names
)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::Instrument as _;

/// Server-owned immutable request correlation. Inbound correlation headers are never authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTelemetryContext {
    request_id: String,
    trace_id: [u8; 16],
    span_id: [u8; 8],
}
impl RequestTelemetryContext {
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    #[must_use]
    pub(crate) const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }
    #[must_use]
    pub(crate) const fn span_id(&self) -> [u8; 8] {
        self.span_id
    }
}

tokio::task_local! {
    static SERVER_REQUEST_TELEMETRY: RequestTelemetryContext;
}

/// Return an immutable clone of the server-owned correlation for the current request.
#[must_use]
pub fn current_request_telemetry_context() -> Option<RequestTelemetryContext> {
    SERVER_REQUEST_TELEMETRY.try_with(Clone::clone).ok()
}

/// Capture the correlation before constructing deferred or spawned work.
#[must_use]
pub fn capture_request_telemetry_context() -> Option<RequestTelemetryContext> {
    current_request_telemetry_context()
}

pub(crate) async fn scope_request_telemetry_context<F>(
    context: Option<RequestTelemetryContext>,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    if let Some(context) = context {
        SERVER_REQUEST_TELEMETRY.scope(context, future).await
    } else {
        future.await
    }
}

/// Install the outer request correlation/redaction boundary.
pub fn instrument_router(router: axum::Router) -> axum::Router {
    instrument_router_with_telemetry(router, None)
}

/// Install request telemetry with an optional bounded exporter handle.
pub fn instrument_router_with_telemetry(
    router: axum::Router,
    telemetry: Option<TelemetryHandle>,
) -> axum::Router {
    router.layer(axum::middleware::from_fn_with_state(
        telemetry,
        request_telemetry_middleware,
    ))
}

async fn request_telemetry_middleware(
    axum::extract::State(telemetry): axum::extract::State<Option<TelemetryHandle>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    for name in ["x-request-id", "traceparent", "tracestate", "baggage"] {
        request.headers_mut().remove(name);
    }
    let trace_id: [u8; 16] = rand::random();
    let span_id: [u8; 8] = rand::random();
    let request_id = format!("{:032x}", u128::from_be_bytes(trace_id));
    let start = now_unix_nanos();
    let context = RequestTelemetryContext {
        request_id: request_id.clone(),
        trace_id,
        span_id,
    };
    request.extensions_mut().insert(context.clone());
    let span = tracing::info_span!("smesh.http.request", smesh.request.id = %request_id);
    let mut response = SERVER_REQUEST_TELEMETRY
        .scope(context, next.run(request).instrument(span))
        .await;
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Some(telemetry) = telemetry {
        let end = now_unix_nanos().max(start);
        let outcome = if response.status().is_success() {
            "ok"
        } else {
            "failed"
        };
        let attributes = vec![
            Attribute::new(AttributeKey::RequestId, &request_id)
                .expect("server request identifier is valid"),
            Attribute::new(AttributeKey::Outcome, outcome)
                .expect("static telemetry outcome is valid"),
            Attribute::new(AttributeKey::Reason, "served").expect("static request reason is valid"),
            Attribute::new(AttributeKey::Operation, "http_request")
                .expect("static request operation is valid"),
        ];
        let _ = telemetry.try_emit(
            TelemetryRecord::log(EventName::RequestCompleted, attributes.clone())
                .expect("static request event is valid"),
        );
        let metric_attributes: Vec<_> = attributes
            .iter()
            .filter(|attribute| attribute.key() != AttributeKey::RequestId.as_str())
            .cloned()
            .collect();
        let _ = telemetry.try_emit(TelemetryRecord::metric(
            MetricPoint::new(MetricName::A2aRequest, 1, metric_attributes.clone())
                .expect("static request metric is valid"),
        ));
        let sli_attributes = vec![
            Attribute::new(AttributeKey::Slo, "edge_availability").expect("static SLO is valid"),
            Attribute::new(
                AttributeKey::Result,
                classify_edge_availability(response.status()),
            )
            .expect("static SLI result is valid"),
        ];
        let _ = telemetry.try_emit(TelemetryRecord::metric(
            MetricPoint::new(MetricName::A2aSliEvent, 1, sli_attributes)
                .expect("static SLI metric is valid"),
        ));
        let elapsed_ms = end.saturating_sub(start).div_ceil(1_000_000);
        let _ = telemetry.try_emit(TelemetryRecord::metric(
            MetricPoint::new(
                MetricName::A2aRequestDuration,
                elapsed_ms,
                metric_attributes,
            )
            .expect("static request metric is valid"),
        ));
        if telemetry.sample_trace() {
            let span = ClosedSpan::new(
                SpanName::HttpRequest,
                trace_id,
                span_id,
                None,
                Vec::new(),
                start,
                end,
                attributes,
            )
            .expect("server generated span identifiers and times are valid");
            let _ = telemetry.try_emit(TelemetryRecord::span(span));
        }
    }
    response
}

/// Closed edge-availability classifier. Caller-caused malformed/authentication
/// failures are outside the eligible population; expected domain responses are
/// successful service outcomes, while server/authority failures are bad.
#[must_use]
pub const fn classify_edge_availability(status: axum::http::StatusCode) -> &'static str {
    match status.as_u16() {
        200..=399 | 403 | 404 | 409 | 429 => "eligible_good",
        500..=599 => "eligible_bad",
        _ => "ineligible",
    }
}

pub const EVENT_SCHEMA: &str = "smesh.telemetry/1";
pub const MAX_METRIC_ATTRIBUTES: usize = 8;
pub const MAX_SERIES_PER_INSTRUMENT: usize = 2_000;
pub const MAX_GLOBAL_SERIES: usize = 10_000;
pub const MAX_CORRELATION_BYTES: usize = 512;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TelemetrySchemaError {
    #[error("unknown telemetry name")]
    UnknownName,
    #[error("unknown telemetry enum value")]
    UnknownEnumValue,
    #[error("telemetry attribute is invalid")]
    InvalidAttribute,
    #[error("metric attribute is forbidden")]
    MetricAttributeForbidden,
    #[error("telemetry record has too many attributes")]
    TooManyAttributes,
}

macro_rules! closed_names {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];
            pub fn parse(value: &str) -> Result<Self, TelemetrySchemaError> {
                match value { $($value => Ok(Self::$variant),)+ _ => Err(TelemetrySchemaError::UnknownName) }
            }
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value,)+ }
            }
        }
    };
}

closed_names!(SpanName {
    HttpRequest => "smesh.http.request",
    AuthVerify => "smesh.auth.verify",
    AuthJwksFetch => "smesh.auth.jwks.fetch",
    AuthorizationResolve => "smesh.authorization.resolve",
    A2aOperation => "smesh.a2a.operation",
    DurableRead => "smesh.durable.read",
    DurableAdmission => "smesh.durable.admission",
    DurableCancel => "smesh.durable.cancel",
    OutboxClaim => "smesh.outbox.claim",
    OutboxAttempt => "smesh.outbox.attempt",
    LeaseRenew => "smesh.lease.renew",
    ReceiverAdmit => "smesh.receiver.admit",
    ReceiverExecute => "smesh.receiver.execute",
    DurableCommit => "smesh.durable.commit",
    RuntimeProcess => "smesh.runtime.process",
    ArtifactOperation => "smesh.artifact.operation",
    QuotaOperation => "smesh.quota.operation",
    WorkerCycle => "smesh.worker.cycle"
});

closed_names!(EventName {
    RequestCompleted => "smesh.request.completed",
    AuthenticationDecided => "smesh.authentication.decided",
    AuthorizationDecided => "smesh.authorization.decided",
    QuotaDecided => "smesh.quota.decided",
    TaskAdmitted => "smesh.task.admitted",
    TaskTransitioned => "smesh.task.transitioned",
    TaskTerminal => "smesh.task.terminal",
    CancellationRequested => "smesh.cancellation.requested",
    CancellationAcknowledged => "smesh.cancellation.acknowledged",
    CancellationStopped => "smesh.cancellation.stopped",
    DispatchClaimed => "smesh.dispatch.claimed",
    DispatchAttempted => "smesh.dispatch.attempted",
    DispatchRetried => "smesh.dispatch.retried",
    DispatchDeadLettered => "smesh.dispatch.dead_lettered",
    ReceiverAdmitted => "smesh.receiver.admitted",
    ReceiverCompleted => "smesh.receiver.completed",
    RuntimeLifecycle => "smesh.runtime.lifecycle",
    RuntimeClaim => "smesh.runtime.claim",
    RuntimeContradiction => "smesh.runtime.contradiction",
    RuntimeTerminal => "smesh.runtime.terminal",
    ArtifactStaged => "smesh.artifact.staged",
    ArtifactRegistered => "smesh.artifact.registered",
    ArtifactPromoted => "smesh.artifact.promoted",
    ArtifactResolved => "smesh.artifact.resolved",
    ArtifactCorruptionDetected => "smesh.artifact.corruption_detected",
    PushConfigChanged => "smesh.push.config.changed",
    PushDelivery => "smesh.push.delivery",
    PushPolicyReconciled => "smesh.push.policy.reconciled",
    LeaseRenewed => "smesh.lease.renewed",
    WorkerState => "smesh.worker.state",
    TelemetryDropped => "smesh.telemetry.dropped",
    AuditProjectorState => "smesh.audit.projector.state"
});

closed_names!(MetricName {
    A2aRequest => "smesh.a2a.request",
    A2aRequestDuration => "smesh.a2a.request.duration",
    A2aSliEvent => "smesh.a2a.sli.event",
    TaskAdmitted => "smesh.a2a.task.admitted",
    TaskSettled => "smesh.a2a.task.settled",
    TaskSettlementDuration => "smesh.a2a.task.settlement.duration",
    DurableOperation => "smesh.a2a.durable.operation",
    OutboxRows => "smesh.a2a.durable.outbox.rows",
    QuotaDecision => "smesh.a2a.quota.decision",
    ArtifactResolve => "smesh.a2a.artifact.resolve",
    ArtifactCorruption => "smesh.a2a.artifact.corruption",
    PushDelivery => "smesh.a2a.push.delivery",
    AuditProjectionLag => "smesh.a2a.audit.projection.lag",
    AuditProjectionFailure => "smesh.a2a.audit.projection.failure",
    TelemetryExport => "smesh.a2a.telemetry.export",
    TelemetryQueue => "smesh.a2a.telemetry.queue",
    TelemetryDropped => "smesh.a2a.telemetry.dropped"
});

closed_names!(AttributeKey {
    RequestId => "smesh.request.id",
    TaskId => "a2a.task.id",
    ContextId => "a2a.context.id",
    MessageId => "a2a.message.id",
    DispatchId => "smesh.dispatch.id",
    SignalHash => "smesh.signal.hash",
    ArtifactId => "smesh.artifact.id",
    AuditDecisionId => "smesh.audit.decision_id",
    EventId => "event.id",
    AuditSource => "smesh.audit.source",
    EventSchema => "event.schema",
    Outcome => "smesh.outcome",
    Reason => "smesh.reason",
    Operation => "smesh.operation",
    Protocol => "smesh.protocol",
    Backend => "smesh.backend",
    TaskState => "smesh.task.state",
    Worker => "smesh.worker.kind",
    LeaseKind => "smesh.lease.kind",
    ScopeKind => "smesh.quota.scope",
    Dimension => "smesh.quota.dimension",
    ArtifactState => "smesh.artifact.state",
    Replica => "smesh.replica",
    Slo => "smesh.slo",
    Result => "smesh.result",
    Signal => "otel.signal",
    DropReason => "smesh.drop.reason"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Rejected,
    Denied,
    NotFound,
    QuotaExceeded,
    Busy,
    Retry,
    Stale,
    Timeout,
    Unavailable,
    Canceled,
    Failed,
}
impl Outcome {
    pub fn parse(value: &str) -> Result<Self, TelemetrySchemaError> {
        match value {
            "ok" => Ok(Self::Ok),
            "rejected" => Ok(Self::Rejected),
            "denied" => Ok(Self::Denied),
            "not_found" => Ok(Self::NotFound),
            "quota_exceeded" => Ok(Self::QuotaExceeded),
            "busy" => Ok(Self::Busy),
            "retry" => Ok(Self::Retry),
            "stale" => Ok(Self::Stale),
            "timeout" => Ok(Self::Timeout),
            "unavailable" => Ok(Self::Unavailable),
            "canceled" => Ok(Self::Canceled),
            "failed" => Ok(Self::Failed),
            _ => Err(TelemetrySchemaError::UnknownEnumValue),
        }
    }
}

/// Typed internal fallback used when a lower layer has no more specific closed
/// telemetry mapping. Raw operation names and error text never cross this seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalTelemetryOperation {
    Durable,
    Dispatch,
    Artifact,
    Runtime,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalTelemetryError {
    Busy,
    Timeout,
    Unavailable,
    Permanent,
}
#[must_use]
pub const fn map_internal_telemetry_fallback(
    operation: InternalTelemetryOperation,
    error: InternalTelemetryError,
) -> (&'static str, &'static str, &'static str) {
    let operation = match operation {
        InternalTelemetryOperation::Durable => "terminal_commit",
        InternalTelemetryOperation::Dispatch => "outbox_attempt",
        InternalTelemetryOperation::Artifact => "artifact_resolve",
        InternalTelemetryOperation::Runtime => "runtime_capture",
    };
    let (outcome, reason) = match error {
        InternalTelemetryError::Busy => ("busy", "busy"),
        InternalTelemetryError::Timeout => ("timeout", "timeout"),
        InternalTelemetryError::Unavailable => ("unavailable", "unavailable"),
        InternalTelemetryError::Permanent => ("failed", "permanent"),
    };
    (operation, outcome, reason)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    Span,
    Log,
    Metric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    QueueFull,
    InvalidAttribute,
    SeriesLimit,
    CircuitOpen,
    Timeout,
    Transport,
    Serialization,
    Shutdown,
}
impl DropReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::InvalidAttribute => "invalid_attribute",
            Self::SeriesLimit => "series_limit",
            Self::CircuitOpen => "circuit_open",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Serialization => "serialization",
            Self::Shutdown => "shutdown",
        }
    }
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribute {
    key: String,
    value: String,
}
impl Attribute {
    pub fn new(key: AttributeKey, value: impl Into<String>) -> Result<Self, TelemetrySchemaError> {
        let value = value.into();
        validate_value(key, &value)?;
        Ok(Self {
            key: key.as_str().to_owned(),
            value,
        })
    }
    #[doc(hidden)]
    #[must_use]
    pub fn new_unchecked_for_test(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

fn validate_value(key: AttributeKey, value: &str) -> Result<(), TelemetrySchemaError> {
    let bounded = !value.is_empty()
        && value.len() <= MAX_CORRELATION_BYTES
        && !value.chars().any(char::is_control);
    let lower = value.to_ascii_lowercase();
    let secret_like = lower.contains("bearer ")
        || lower.contains("password")
        || lower.contains("://")
        || lower.starts_with("error:");
    if !bounded || secret_like {
        return Err(TelemetrySchemaError::InvalidAttribute);
    }

    let closed = |allowed: &[&str]| {
        if allowed.contains(&value) {
            Ok(())
        } else {
            Err(TelemetrySchemaError::UnknownEnumValue)
        }
    };
    match key {
        AttributeKey::Outcome => Outcome::parse(value).map(|_| ()),
        AttributeKey::Reason => closed(&[
            "admitted",
            "attempts_exhausted",
            "busy",
            "claim",
            "claimed",
            "committed",
            "contradiction",
            "cooperative_stop",
            "fatal",
            "durable_ack",
            "encrypted",
            "execute",
            "integrity_verified",
            "invalid_token",
            "lifecycle",
            "lost",
            "missing",
            "other",
            "permanent",
            "published",
            "quarantined",
            "read",
            "ready",
            "renewed",
            "replay",
            "role_denied",
            "served",
            "shutdown",
            "terminal",
            "timeout",
            "unavailable",
            "unexpected_exit",
            "verified",
            "worker_panic",
        ]),
        AttributeKey::Operation => closed(&[
            "artifact_backup_completed",
            "artifact_corruption",
            "artifact_key_changed",
            "artifact_migration_completed",
            "artifact_promote",
            "artifact_register",
            "artifact_restore_completed",
            "artifact_rotation_completed",
            "artifact_resolve",
            "artifact_stage",
            "authorize",
            "authorization_decision",
            "callback_config_created",
            "callback_config_deleted",
            "callback_delivery_attempted",
            "callback_delivered",
            "callback_event_enqueued",
            "callback_dead",
            "callback_policy_reconciled",
            "callback_retry_scheduled",
            "callback_worker",
            "cancel",
            "cancel_task",
            "get",
            "get_task",
            "http_request",
            "lease_acquire",
            "list",
            "list_tasks",
            "outbox_attempt",
            "outbox_claim",
            "outbox_renew",
            "receiver_admit",
            "receiver_execute",
            "runtime_capture",
            "send",
            "send_message",
            "send_streaming_message",
            "subscribe_to_task",
            "quota_denied",
            "quota_overridden",
            "quota_reconciled",
            "task_canceled",
            "task_terminal",
            "task_transition",
            "terminal_commit",
        ]),
        AttributeKey::Protocol => closed(&["a2a", "jsonrpc", "rest", "sse", "other"]),
        AttributeKey::Backend => closed(&["sqlite", "postgres", "runtime", "artifact", "other"]),
        AttributeKey::TaskState => closed(&[
            "submitted",
            "working",
            "input_required",
            "auth_required",
            "completed",
            "failed",
            "canceled",
            "rejected",
            "unknown",
        ]),
        AttributeKey::Worker => closed(&[
            "outbox",
            "receiver",
            "runtime",
            "artifact_promoter",
            "audit_projector",
            "callback",
            "other",
        ]),
        AttributeKey::LeaseKind => closed(&[
            "outbox", "receiver", "runtime", "quota", "artifact", "other",
        ]),
        AttributeKey::ScopeKind => closed(&["tenant", "account", "task", "global", "other"]),
        AttributeKey::Dimension => closed(&[
            "tasks",
            "authority_bytes",
            "artifact_bytes",
            "egress_bytes",
            "other",
        ]),
        AttributeKey::ArtifactState => closed(&[
            "staged",
            "registered",
            "promoted",
            "available",
            "quarantined",
            "deleted",
            "other",
        ]),
        AttributeKey::Slo => closed(&["edge_availability"]),
        AttributeKey::Result => closed(&["eligible_good", "eligible_bad", "ineligible"]),
        AttributeKey::Signal => closed(&["traces", "logs", "metrics"]),
        AttributeKey::DropReason => closed(&[
            "queue_full",
            "invalid_attribute",
            "series_limit",
            "circuit_open",
            "timeout",
            "transport",
            "serialization",
            "shutdown",
        ]),
        AttributeKey::AuditSource => closed(&[
            "authorization_decisions",
            "task_events",
            "cancellation_intents",
            "quota_denial_audits",
            "quota_override_audits",
            "quota_policy_reconciliation_audits",
            "artifact_corruption_audits",
            "artifact_key_audits",
            "artifact_migration_plans",
            "artifact_backup_jobs",
            "artifact_restore_jobs",
            "artifact_key_rotation_plans",
            "callback_policy_snapshots",
            "callback_configs",
            "callback_events",
            "callback_deliveries",
            "callback_attempts",
        ]),
        AttributeKey::RequestId => {
            if value.len() == 32
                && value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                Ok(())
            } else {
                Err(TelemetrySchemaError::InvalidAttribute)
            }
        }
        AttributeKey::SignalHash | AttributeKey::EventId => {
            if value.len() == 71
                && value.starts_with("sha256:")
                && value[7..]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                Ok(())
            } else {
                Err(TelemetrySchemaError::InvalidAttribute)
            }
        }
        AttributeKey::TaskId
        | AttributeKey::ContextId
        | AttributeKey::MessageId
        | AttributeKey::DispatchId
        | AttributeKey::ArtifactId
        | AttributeKey::AuditDecisionId
        | AttributeKey::Replica => {
            if value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            {
                Ok(())
            } else {
                Err(TelemetrySchemaError::InvalidAttribute)
            }
        }
        AttributeKey::EventSchema => closed(&[EVENT_SCHEMA]),
    }
}

fn ensure_unique_attributes(attributes: &[Attribute]) -> Result<(), TelemetrySchemaError> {
    let mut keys = std::collections::BTreeSet::new();
    if attributes
        .iter()
        .all(|attribute| keys.insert(attribute.key()))
    {
        Ok(())
    } else {
        Err(TelemetrySchemaError::InvalidAttribute)
    }
}

fn validate_shape(
    attributes: &[Attribute],
    allowed: &[AttributeKey],
    required: &[AttributeKey],
) -> Result<(), TelemetrySchemaError> {
    ensure_unique_attributes(attributes)?;
    if !required.iter().all(|key| {
        attributes
            .iter()
            .any(|attribute| attribute.key() == key.as_str())
    }) || attributes.iter().any(|attribute| {
        AttributeKey::parse(attribute.key()).map_or(true, |key| !allowed.contains(&key))
    }) {
        Err(TelemetrySchemaError::InvalidAttribute)
    } else {
        Ok(())
    }
}

#[allow(clippy::match_same_arms)] // Deliberate: every closed event has an auditable schema row.
fn validate_log_shape(
    name: EventName,
    attributes: &[Attribute],
) -> Result<(), TelemetrySchemaError> {
    use AttributeKey as K;
    const DECISION: &[K] = &[
        K::RequestId,
        K::AuditDecisionId,
        K::EventId,
        K::AuditSource,
        K::Outcome,
        K::Reason,
        K::Operation,
    ];
    const DURABLE: &[K] = &[
        K::RequestId,
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::EventId,
        K::AuditSource,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::TaskState,
    ];
    const DISPATCH: &[K] = &[
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::TaskState,
        K::LeaseKind,
    ];
    const RUNTIME: &[K] = &[
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::SignalHash,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::TaskState,
    ];
    const ARTIFACT: &[K] = &[
        K::RequestId,
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::ArtifactId,
        K::EventId,
        K::AuditSource,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::ArtifactState,
    ];
    const WORKER: &[K] = &[K::Outcome, K::Reason, K::Operation, K::Worker, K::Replica];
    const DROP: &[K] = &[K::Outcome, K::Reason, K::Signal, K::DropReason];
    const AUDIT: &[K] = &[
        K::EventId,
        K::AuditSource,
        K::Outcome,
        K::Reason,
        K::Operation,
    ];
    const ORO: &[K] = &[K::Outcome, K::Reason, K::Operation];
    const OO: &[K] = &[K::Outcome, K::Operation];
    const REQUEST: &[K] = &[K::RequestId, K::Outcome, K::Reason, K::Operation];
    const TASK_ID_CORRELATION: &[K] = &[K::Outcome, K::Reason, K::Operation, K::TaskId];
    const TASK_CORRELATION: &[K] = &[K::Outcome, K::Reason, K::Operation, K::TaskId, K::ContextId];
    const TASK_MESSAGE_CORRELATION: &[K] = &[
        K::Outcome,
        K::Reason,
        K::Operation,
        K::TaskId,
        K::ContextId,
        K::MessageId,
    ];
    const DISPATCH_CORRELATION: &[K] = &[
        K::Outcome,
        K::Reason,
        K::Operation,
        K::DispatchId,
        K::TaskId,
        K::ContextId,
        K::MessageId,
    ];
    const ARTIFACT_REQUIRED: &[K] = &[K::Outcome, K::Reason, K::Operation, K::ArtifactId];
    let (allowed, required): (&[K], &[K]) = match name {
        EventName::RequestCompleted => (REQUEST, REQUEST),
        EventName::AuthenticationDecided => (DECISION, &[K::RequestId, K::Outcome, K::Reason]),
        EventName::AuthorizationDecided => (
            DECISION,
            &[K::RequestId, K::Outcome, K::Reason, K::Operation],
        ),
        EventName::QuotaDecided => (DECISION, OO),
        EventName::TaskAdmitted => (DURABLE, TASK_MESSAGE_CORRELATION),
        EventName::TaskTransitioned => (DURABLE, ORO),
        EventName::TaskTerminal => (DURABLE, TASK_MESSAGE_CORRELATION),
        EventName::CancellationRequested => (DURABLE, TASK_ID_CORRELATION),
        EventName::CancellationAcknowledged => (DURABLE, TASK_CORRELATION),
        EventName::CancellationStopped => (DURABLE, TASK_CORRELATION),
        EventName::DispatchClaimed => (DISPATCH, DISPATCH_CORRELATION),
        EventName::DispatchAttempted => (DISPATCH, DISPATCH_CORRELATION),
        EventName::DispatchRetried => (DISPATCH, DISPATCH_CORRELATION),
        EventName::DispatchDeadLettered => (DISPATCH, DISPATCH_CORRELATION),
        EventName::ReceiverAdmitted => (DISPATCH, DISPATCH_CORRELATION),
        EventName::ReceiverCompleted => (DISPATCH, DISPATCH_CORRELATION),
        EventName::RuntimeLifecycle => (RUNTIME, ORO),
        EventName::RuntimeClaim => (RUNTIME, ORO),
        EventName::RuntimeContradiction => (RUNTIME, ORO),
        EventName::RuntimeTerminal => (RUNTIME, ORO),
        EventName::ArtifactStaged => (ARTIFACT, ARTIFACT_REQUIRED),
        EventName::ArtifactRegistered => (ARTIFACT, ARTIFACT_REQUIRED),
        EventName::ArtifactPromoted => (ARTIFACT, ARTIFACT_REQUIRED),
        EventName::ArtifactResolved => (ARTIFACT, ARTIFACT_REQUIRED),
        EventName::ArtifactCorruptionDetected => (ARTIFACT, ARTIFACT_REQUIRED),
        EventName::PushConfigChanged
        | EventName::PushDelivery
        | EventName::PushPolicyReconciled => (ORO, ORO),
        EventName::LeaseRenewed => (DISPATCH, DISPATCH_CORRELATION),
        EventName::WorkerState => (WORKER, &[K::Outcome, K::Worker]),
        EventName::TelemetryDropped => (DROP, &[K::Outcome, K::Signal, K::DropReason]),
        EventName::AuditProjectorState => (AUDIT, AUDIT),
    };
    validate_shape(attributes, allowed, required)?;
    if matches!(
        name,
        EventName::ArtifactStaged
            | EventName::ArtifactRegistered
            | EventName::ArtifactPromoted
            | EventName::ArtifactResolved
            | EventName::ArtifactCorruptionDetected
    ) {
        let causal = [K::DispatchId, K::TaskId, K::ContextId, K::MessageId]
            .iter()
            .filter(|key| {
                attributes
                    .iter()
                    .any(|attribute| attribute.key() == key.as_str())
            })
            .count();
        if causal != 0 && causal != 4 {
            return Err(TelemetrySchemaError::InvalidAttribute);
        }
    }
    Ok(())
}

#[allow(clippy::match_same_arms)] // Deliberate: every closed span has an auditable schema row.
fn validate_span_shape(
    name: SpanName,
    attributes: &[Attribute],
) -> Result<(), TelemetrySchemaError> {
    use AttributeKey as K;
    const HTTP: &[K] = &[
        K::RequestId,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::Protocol,
    ];
    const AUTH: &[K] = &[K::RequestId, K::Outcome, K::Reason, K::Operation];
    const DURABLE: &[K] = &[
        K::RequestId,
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::TaskState,
        K::Backend,
    ];
    const DISPATCH: &[K] = &[
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::LeaseKind,
        K::TaskState,
    ];
    const RUNTIME: &[K] = &[
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::SignalHash,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::TaskState,
    ];
    const ARTIFACT: &[K] = &[
        K::TaskId,
        K::ContextId,
        K::MessageId,
        K::DispatchId,
        K::ArtifactId,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::ArtifactState,
    ];
    const QUOTA: &[K] = &[
        K::RequestId,
        K::Outcome,
        K::Reason,
        K::Operation,
        K::ScopeKind,
        K::Dimension,
    ];
    const WORKER: &[K] = &[K::Outcome, K::Reason, K::Operation, K::Worker, K::Replica];
    const ORO: &[K] = &[K::Outcome, K::Reason, K::Operation];
    let (allowed, required): (&[K], &[K]) = match name {
        SpanName::HttpRequest => (HTTP, &[K::RequestId, K::Outcome, K::Reason, K::Operation]),
        SpanName::AuthVerify => (AUTH, &[K::Outcome, K::Reason]),
        SpanName::AuthJwksFetch => (AUTH, ORO),
        SpanName::AuthorizationResolve => (AUTH, ORO),
        SpanName::A2aOperation => (DURABLE, ORO),
        SpanName::DurableRead => (DURABLE, ORO),
        SpanName::DurableAdmission | SpanName::DurableCancel | SpanName::DurableCommit => (
            DURABLE,
            &[
                K::Outcome,
                K::Reason,
                K::Operation,
                K::TaskId,
                K::ContextId,
                K::MessageId,
            ],
        ),
        SpanName::OutboxClaim
        | SpanName::OutboxAttempt
        | SpanName::LeaseRenew
        | SpanName::ReceiverAdmit
        | SpanName::ReceiverExecute => (
            DISPATCH,
            &[
                K::Outcome,
                K::Reason,
                K::Operation,
                K::DispatchId,
                K::TaskId,
                K::ContextId,
                K::MessageId,
            ],
        ),
        SpanName::RuntimeProcess => (RUNTIME, ORO),
        SpanName::ArtifactOperation => (
            ARTIFACT,
            &[K::Outcome, K::Reason, K::Operation, K::ArtifactId],
        ),
        SpanName::QuotaOperation => (QUOTA, &[K::Outcome, K::Operation]),
        SpanName::WorkerCycle => (WORKER, &[K::Outcome, K::Worker]),
    };
    validate_shape(attributes, allowed, required)?;
    if name == SpanName::ArtifactOperation {
        let causal = [K::DispatchId, K::TaskId, K::ContextId, K::MessageId]
            .iter()
            .filter(|key| {
                attributes
                    .iter()
                    .any(|attribute| attribute.key() == key.as_str())
            })
            .count();
        if causal != 0 && causal != 4 {
            return Err(TelemetrySchemaError::InvalidAttribute);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricPoint {
    pub name: MetricName,
    pub value: u64,
    pub attributes: Vec<Attribute>,
    aggregation_start_unix_nano: u64,
    count: u64,
    sum: u64,
    bucket_counts: Vec<u64>,
    min: u64,
    max: u64,
}

/// Bounded live metric-series registry shared by every metric producer.
///
/// A series is identified by the static instrument name and its attributes
/// sorted by key and value, so caller attribute order cannot create a second
/// series. New series are rejected before either budget is exceeded.
#[derive(Debug)]
pub struct SeriesRegistry {
    per_instrument_limit: usize,
    global_limit: usize,
    by_instrument: std::collections::BTreeMap<&'static str, std::collections::BTreeSet<String>>,
    global: std::collections::BTreeSet<String>,
}

impl Default for SeriesRegistry {
    fn default() -> Self {
        Self::new(MAX_SERIES_PER_INSTRUMENT, MAX_GLOBAL_SERIES)
    }
}

impl SeriesRegistry {
    fn keys(point: &MetricPoint) -> (&'static str, String, String) {
        let instrument = point.name.as_str();
        let mut attributes: Vec<_> = point
            .attributes
            .iter()
            .map(|attribute| (attribute.key(), attribute.value()))
            .collect();
        attributes.sort_unstable();
        let mut local_key = String::new();
        for (key, value) in attributes {
            local_key.push_str(key);
            local_key.push('\0');
            local_key.push_str(value);
            local_key.push('\0');
        }
        let mut global_key = String::with_capacity(instrument.len() + 1 + local_key.len());
        global_key.push_str(instrument);
        global_key.push('\0');
        global_key.push_str(&local_key);
        (instrument, local_key, global_key)
    }

    fn new(per_instrument_limit: usize, global_limit: usize) -> Self {
        Self {
            per_instrument_limit,
            global_limit,
            by_instrument: std::collections::BTreeMap::new(),
            global: std::collections::BTreeSet::new(),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn with_limits_for_test(per_instrument_limit: usize, global_limit: usize) -> Self {
        Self::new(per_instrument_limit, global_limit)
    }

    #[must_use]
    pub fn admit(&mut self, point: &MetricPoint) -> bool {
        let (instrument, local_key, global_key) = Self::keys(point);
        if self
            .by_instrument
            .get(instrument)
            .is_some_and(|series| series.contains(&local_key))
        {
            return true;
        }
        if self.global.contains(&global_key) {
            return true;
        }
        if self.global.len() >= self.global_limit
            || self
                .by_instrument
                .get(instrument)
                .map_or(0, std::collections::BTreeSet::len)
                >= self.per_instrument_limit
        {
            return false;
        }
        self.by_instrument
            .entry(instrument)
            .or_default()
            .insert(local_key);
        self.global.insert(global_key);
        true
    }

    fn rollback(&mut self, point: &MetricPoint) {
        let (instrument, local_key, global_key) = Self::keys(point);
        self.global.remove(&global_key);
        if let Some(series) = self.by_instrument.get_mut(instrument) {
            series.remove(&local_key);
            if series.is_empty() {
                self.by_instrument.remove(instrument);
            }
        }
    }

    #[must_use]
    pub fn series_count(&self) -> usize {
        self.global.len()
    }
}

impl MetricPoint {
    pub fn new(
        name: MetricName,
        value: u64,
        attributes: Vec<Attribute>,
    ) -> Result<Self, TelemetrySchemaError> {
        if attributes.len() > MAX_METRIC_ATTRIBUTES {
            return Err(TelemetrySchemaError::TooManyAttributes);
        }
        ensure_unique_attributes(&attributes)?;
        for attribute in &attributes {
            let key = AttributeKey::parse(attribute.key())
                .map_err(|_| TelemetrySchemaError::MetricAttributeForbidden)?;
            if matches!(
                key,
                AttributeKey::RequestId
                    | AttributeKey::TaskId
                    | AttributeKey::ContextId
                    | AttributeKey::MessageId
                    | AttributeKey::DispatchId
                    | AttributeKey::SignalHash
                    | AttributeKey::ArtifactId
                    | AttributeKey::AuditDecisionId
                    | AttributeKey::EventId
                    | AttributeKey::EventSchema
            ) {
                return Err(TelemetrySchemaError::MetricAttributeForbidden);
            }
            validate_value(key, attribute.value())?;
        }
        Ok(Self {
            name,
            value,
            attributes,
            aggregation_start_unix_nano: 0,
            count: 1,
            sum: value,
            bucket_counts: Vec::new(),
            min: value,
            max: value,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanLink {
    trace_id: [u8; 16],
    span_id: [u8; 8],
}
impl SpanLink {
    #[must_use]
    pub const fn new(trace_id: [u8; 16], span_id: [u8; 8]) -> Self {
        Self { trace_id, span_id }
    }
    fn for_dispatch(tenant_scope: &str, dispatch_id: &str) -> Self {
        let digest = crate::content_digest(
            format!("smesh-dispatch-span-link/v2\0{tenant_scope}\0{dispatch_id}").as_bytes(),
        );
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = 7 + index * 2;
            let pair = &digest.as_bytes()[offset..offset + 2];
            let hex = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => 0,
            };
            *byte = (hex(pair[0]) << 4) | hex(pair[1]);
        }
        let mut trace_id = [0_u8; 16];
        trace_id.copy_from_slice(&bytes[..16]);
        let mut span_id = [0_u8; 8];
        span_id.copy_from_slice(&bytes[16..24]);
        Self { trace_id, span_id }
    }
}

/// A span that is already closed at an authoritative lifecycle seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedSpan {
    name: SpanName,
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    links: Vec<SpanLink>,
    start_time_unix_nano: u64,
    end_time_unix_nano: u64,
    attributes: Vec<Attribute>,
}
impl ClosedSpan {
    pub fn new(
        name: SpanName,
        trace_id: [u8; 16],
        span_id: [u8; 8],
        parent_span_id: Option<[u8; 8]>,
        links: Vec<SpanLink>,
        start_time_unix_nano: u64,
        end_time_unix_nano: u64,
        attributes: Vec<Attribute>,
    ) -> Result<Self, TelemetrySchemaError> {
        if trace_id == [0; 16]
            || span_id == [0; 8]
            || parent_span_id == Some([0; 8])
            || links.len() > 16
            || start_time_unix_nano == 0
            || end_time_unix_nano < start_time_unix_nano
            || attributes.len() > 24
        {
            return Err(TelemetrySchemaError::InvalidAttribute);
        }
        ensure_unique_attributes(&attributes)?;
        validate_span_shape(name, &attributes)?;
        for attribute in &attributes {
            let key = AttributeKey::parse(attribute.key())?;
            validate_value(key, attribute.value())?;
        }
        Ok(Self {
            name,
            trace_id,
            span_id,
            parent_span_id,
            links,
            start_time_unix_nano,
            end_time_unix_nano,
            attributes,
        })
    }
    #[must_use]
    pub const fn duration_nanos(&self) -> u64 {
        self.end_time_unix_nano - self.start_time_unix_nano
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TelemetryPayload {
    Log,
    Span(ClosedSpan),
    Metric(MetricPoint),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryRecord {
    signal: Signal,
    name: String,
    attributes: Vec<Attribute>,
    required: bool,
    payload: TelemetryPayload,
}
impl TelemetryRecord {
    pub fn log(
        name: EventName,
        mut attributes: Vec<Attribute>,
    ) -> Result<Self, TelemetrySchemaError> {
        if attributes.len() >= 24 {
            return Err(TelemetrySchemaError::TooManyAttributes);
        }
        validate_log_shape(name, &attributes)?;
        for attribute in &attributes {
            let key = AttributeKey::parse(attribute.key())?;
            validate_value(key, attribute.value())?;
        }
        attributes.push(Attribute::new(AttributeKey::EventSchema, EVENT_SCHEMA)?);
        let required = matches!(
            name,
            EventName::AuthenticationDecided
                | EventName::AuthorizationDecided
                | EventName::QuotaDecided
                | EventName::TaskAdmitted
                | EventName::TaskTransitioned
                | EventName::TaskTerminal
                | EventName::CancellationRequested
                | EventName::CancellationAcknowledged
                | EventName::CancellationStopped
                | EventName::DispatchDeadLettered
                | EventName::LeaseRenewed
                | EventName::WorkerState
                | EventName::RuntimeLifecycle
                | EventName::RuntimeClaim
                | EventName::RuntimeContradiction
                | EventName::RuntimeTerminal
                | EventName::ArtifactRegistered
                | EventName::ArtifactPromoted
                | EventName::ArtifactCorruptionDetected
                | EventName::AuditProjectorState
        );
        Ok(Self {
            signal: Signal::Log,
            name: name.as_str().to_owned(),
            attributes,
            required,
            payload: TelemetryPayload::Log,
        })
    }
    #[must_use]
    pub fn span(span: ClosedSpan) -> Self {
        Self {
            signal: Signal::Span,
            name: span.name.as_str().to_owned(),
            attributes: span.attributes.clone(),
            required: false,
            payload: TelemetryPayload::Span(span),
        }
    }
    #[must_use]
    pub fn metric(point: MetricPoint) -> Self {
        Self {
            signal: Signal::Metric,
            name: point.name.as_str().to_owned(),
            attributes: point.attributes.clone(),
            required: false,
            payload: TelemetryPayload::Metric(point),
        }
    }
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
    #[must_use]
    pub const fn signal(&self) -> Signal {
        self.signal
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }
    #[doc(hidden)]
    #[must_use]
    pub fn link_count_for_test(&self) -> usize {
        match &self.payload {
            TelemetryPayload::Span(span) => span.links.len(),
            TelemetryPayload::Log | TelemetryPayload::Metric(_) => 0,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn span_identity_for_test(&self) -> Option<([u8; 16], [u8; 8])> {
        match &self.payload {
            TelemetryPayload::Span(span) => Some((span.trace_id, span.span_id)),
            TelemetryPayload::Log | TelemetryPayload::Metric(_) => None,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn span_links_for_test(&self) -> Vec<([u8; 16], [u8; 8])> {
        match &self.payload {
            TelemetryPayload::Span(span) => span
                .links
                .iter()
                .map(|link| (link.trace_id, link.span_id))
                .collect(),
            TelemetryPayload::Log | TelemetryPayload::Metric(_) => Vec::new(),
        }
    }
    fn metric_point(&self) -> Option<&MetricPoint> {
        match &self.payload {
            TelemetryPayload::Metric(point) => Some(point),
            TelemetryPayload::Log | TelemetryPayload::Span(_) => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct DropCounters([std::sync::atomic::AtomicU64; 8]);
impl DropCounters {
    pub fn increment(&self, reason: DropReason) {
        self.0[reason.index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    #[must_use]
    pub fn get(&self, reason: DropReason) -> u64 {
        self.0[reason.index()].load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryShutdownOutcome {
    NotStarted,
    Completed,
    TimedOut,
    JoinFailed,
}
impl TelemetryShutdownOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Completed => "completed",
            Self::TimedOut => "timed_out",
            Self::JoinFailed => "join_failed",
        }
    }
}

#[derive(Debug, Default)]
struct ShutdownHealth {
    started: std::sync::atomic::AtomicBool,
    completed: std::sync::atomic::AtomicBool,
    timed_out: std::sync::atomic::AtomicU64,
    join_failed: std::sync::atomic::AtomicU64,
    workers_alive: std::sync::atomic::AtomicUsize,
    outcome: std::sync::atomic::AtomicU8,
}

/// Read-only, non-recursive exporter health snapshot that does not keep queues open.
#[derive(Debug, Clone)]
pub struct TelemetryHealthSnapshot {
    drops: std::sync::Arc<DropCounters>,
    shutdown: std::sync::Arc<ShutdownHealth>,
}
impl TelemetryHealthSnapshot {
    #[must_use]
    pub fn drop_count(&self, reason: DropReason) -> u64 {
        self.drops.get(reason)
    }
    #[must_use]
    pub fn shutdown_started(&self) -> bool {
        self.shutdown
            .started
            .load(std::sync::atomic::Ordering::Acquire)
    }
    #[must_use]
    pub fn shutdown_completed(&self) -> bool {
        self.shutdown
            .completed
            .load(std::sync::atomic::Ordering::Acquire)
    }
    #[must_use]
    pub fn shutdown_timed_out_count(&self) -> u64 {
        self.shutdown
            .timed_out
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    #[must_use]
    pub fn shutdown_join_failed_count(&self) -> u64 {
        self.shutdown
            .join_failed
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    #[must_use]
    pub fn worker_alive_count(&self) -> usize {
        self.shutdown
            .workers_alive
            .load(std::sync::atomic::Ordering::Acquire)
    }
    #[must_use]
    pub fn last_shutdown_outcome(&self) -> TelemetryShutdownOutcome {
        match self
            .shutdown
            .outcome
            .load(std::sync::atomic::Ordering::Acquire)
        {
            1 => TelemetryShutdownOutcome::Completed,
            2 => TelemetryShutdownOutcome::TimedOut,
            3 => TelemetryShutdownOutcome::JoinFailed,
            _ => TelemetryShutdownOutcome::NotStarted,
        }
    }
}

/// Per-signal exporter circuit state. Time is supplied by the owner clock in
/// monotonic milliseconds, which makes failure thresholds and cooldowns fully
/// deterministic in tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CircuitBreaker {
    consecutive_failures: u8,
    open_until_millis: Option<u64>,
}

impl CircuitBreaker {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            consecutive_failures: 0,
            open_until_millis: None,
        }
    }

    #[must_use]
    pub fn allow(&mut self, now_millis: u64) -> bool {
        match self.open_until_millis {
            Some(until) if now_millis < until => false,
            Some(_) => {
                self.open_until_millis = None;
                true
            }
            None => true,
        }
    }

    pub fn failure(&mut self, now_millis: u64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= 3 {
            self.open_until_millis = Some(now_millis.saturating_add(1_000));
        }
    }

    pub fn success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until_millis = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpMode {
    Disabled,
    Grpc,
    HttpProtobuf,
}

#[derive(Clone)]
pub struct OtlpConfig {
    pub mode: OtlpMode,
    pub endpoint: Option<url::Url>,
    pub trace_queue: usize,
    pub log_queue: usize,
    pub metric_queue: usize,
    pub batch_size: usize,
    pub schedule: std::time::Duration,
    pub export_timeout: std::time::Duration,
    pub metric_interval: std::time::Duration,
    pub shutdown_timeout: std::time::Duration,
    pub trace_sample_ratio: f64,
    ca_pem: Option<Vec<u8>>,
    client_cert_pem: Option<Vec<u8>>,
    client_key_pem: Option<Vec<u8>>,
    headers: Vec<(String, String)>,
}

impl std::fmt::Debug for OtlpConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OtlpConfig")
            .field("mode", &self.mode)
            .field("endpoint", &self.endpoint)
            .field("trace_queue", &self.trace_queue)
            .field("log_queue", &self.log_queue)
            .field("metric_queue", &self.metric_queue)
            .field("batch_size", &self.batch_size)
            .field("schedule", &self.schedule)
            .field("export_timeout", &self.export_timeout)
            .field("metric_interval", &self.metric_interval)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("trace_sample_ratio", &self.trace_sample_ratio)
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "[REDACTED]"))
            .field(
                "client_cert_pem",
                &self.client_cert_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_key_pem",
                &self.client_key_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "headers",
                &if self.headers.is_empty() {
                    "none"
                } else {
                    "[REDACTED]"
                },
            )
            .finish()
    }
}

impl OtlpConfig {
    /// Parse a closed environment snapshot without performing DNS or network I/O.
    pub fn parse<I>(values: I) -> Result<Self, TelemetryConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let env: std::collections::BTreeMap<String, String> = values.into_iter().collect();
        let mode = match env
            .get("SMESH_A2A_OTLP_MODE")
            .map_or("disabled", String::as_str)
        {
            "disabled" => OtlpMode::Disabled,
            "grpc" => OtlpMode::Grpc,
            "http-protobuf" => OtlpMode::HttpProtobuf,
            _ => return Err(TelemetryConfigError::Invalid("mode")),
        };
        let configured = env
            .keys()
            .any(|key| key.starts_with("SMESH_A2A_OTLP_") && key != "SMESH_A2A_OTLP_MODE");
        if mode == OtlpMode::Disabled {
            if configured {
                return Err(TelemetryConfigError::DisabledHasConfiguration);
            }
            return Ok(Self::disabled());
        }
        for key in env.keys().filter(|key| key.starts_with("SMESH_A2A_OTLP_")) {
            if !matches!(
                key.as_str(),
                "SMESH_A2A_OTLP_MODE"
                    | "SMESH_A2A_OTLP_ENDPOINT"
                    | "SMESH_A2A_OTLP_TRACE_QUEUE"
                    | "SMESH_A2A_OTLP_LOG_QUEUE"
                    | "SMESH_A2A_OTLP_METRIC_QUEUE"
                    | "SMESH_A2A_OTLP_BATCH_SIZE"
                    | "SMESH_A2A_OTLP_SCHEDULE_MILLIS"
                    | "SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS"
                    | "SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS"
                    | "SMESH_A2A_OTLP_SHUTDOWN_TIMEOUT_MILLIS"
                    | "SMESH_A2A_OTLP_TRACE_SAMPLE_RATIO"
                    | "SMESH_A2A_OTLP_COMPRESSION"
                    | "SMESH_A2A_OTLP_HEADERS_PATH"
                    | "SMESH_A2A_OTLP_CA_PATH"
                    | "SMESH_A2A_OTLP_CLIENT_CERT_PATH"
                    | "SMESH_A2A_OTLP_CLIENT_KEY_PATH"
            ) {
                return Err(TelemetryConfigError::Invalid("unknown setting"));
            }
        }
        let ca_pem = env
            .get("SMESH_A2A_OTLP_CA_PATH")
            .map(|path| read_otlp_material(std::path::Path::new(path), 1024 * 1024))
            .transpose()?;
        if let Some(ca) = &ca_pem {
            reqwest::Certificate::from_pem_bundle(ca)
                .map_err(|_| TelemetryConfigError::Invalid("CA material"))?;
        }
        let (client_cert_pem, client_key_pem) = match (
            env.get("SMESH_A2A_OTLP_CLIENT_CERT_PATH"),
            env.get("SMESH_A2A_OTLP_CLIENT_KEY_PATH"),
        ) {
            (None, None) => (None, None),
            (Some(cert), Some(key)) => {
                let cert = read_otlp_material(std::path::Path::new(cert), 1024 * 1024)?;
                let key = read_otlp_material(std::path::Path::new(key), 256 * 1024)?;
                let mut identity = cert.clone();
                identity.extend_from_slice(&key);
                reqwest::Identity::from_pem(&identity)
                    .map_err(|_| TelemetryConfigError::Invalid("client identity"))?;
                (Some(cert), Some(key))
            }
            _ => return Err(TelemetryConfigError::Invalid("client certificate/key pair")),
        };
        let headers = env
            .get("SMESH_A2A_OTLP_HEADERS_PATH")
            .map(|path| {
                parse_otlp_headers(&read_otlp_material(std::path::Path::new(path), 64 * 1024)?)
            })
            .transpose()?
            .unwrap_or_default();
        if env
            .get("SMESH_A2A_OTLP_COMPRESSION")
            .is_some_and(|value| value != "none")
        {
            return Err(TelemetryConfigError::Invalid("compression"));
        }
        let endpoint_text = env
            .get("SMESH_A2A_OTLP_ENDPOINT")
            .ok_or(TelemetryConfigError::MissingEndpoint)?;
        if endpoint_text.is_empty()
            || endpoint_text.len() > 2_048
            || endpoint_text.chars().any(char::is_control)
        {
            return Err(TelemetryConfigError::Invalid("endpoint"));
        }
        let endpoint = url::Url::parse(endpoint_text)
            .map_err(|_| TelemetryConfigError::Invalid("endpoint"))?;
        let insecure_gate = cfg!(debug_assertions)
            && env
                .get("SMESH_TEST_OTLP_INSECURE_LOOPBACK")
                .map(String::as_str)
                == Some("1")
            && endpoint.host_str().is_some_and(|host| {
                host.parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            });
        if (endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && insecure_gate))
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(TelemetryConfigError::Invalid("endpoint"));
        }
        let trace_queue = parse_bound(&env, "SMESH_A2A_OTLP_TRACE_QUEUE", 2_048, 64, 65_536)?;
        let log_queue = parse_bound(&env, "SMESH_A2A_OTLP_LOG_QUEUE", 4_096, 64, 65_536)?;
        let metric_queue = parse_bound(&env, "SMESH_A2A_OTLP_METRIC_QUEUE", 2_048, 64, 65_536)?;
        let default_batch = 256_usize.min(trace_queue).min(log_queue).min(metric_queue);
        let batch_size = parse_bound(
            &env,
            "SMESH_A2A_OTLP_BATCH_SIZE",
            default_batch,
            1,
            trace_queue.min(log_queue).min(metric_queue).min(1_024),
        )?;
        let schedule_ms = parse_bound(&env, "SMESH_A2A_OTLP_SCHEDULE_MILLIS", 500, 50, 10_000)?;
        let export_ms = parse_bound(
            &env,
            "SMESH_A2A_OTLP_EXPORT_TIMEOUT_MILLIS",
            3_000,
            100,
            10_000,
        )?;
        let metric_ms = parse_bound(
            &env,
            "SMESH_A2A_OTLP_METRIC_INTERVAL_MILLIS",
            10_000,
            1_000,
            300_000,
        )?;
        if metric_ms <= export_ms {
            return Err(TelemetryConfigError::Invalid("metric interval"));
        }
        let shutdown_ms = parse_bound(
            &env,
            "SMESH_A2A_OTLP_SHUTDOWN_TIMEOUT_MILLIS",
            5_000,
            100,
            10_000,
        )?;
        let ratio = env
            .get("SMESH_A2A_OTLP_TRACE_SAMPLE_RATIO")
            .map_or(Ok(0.1), |value| {
                value
                    .parse::<f64>()
                    .map_err(|_| TelemetryConfigError::Invalid("sample ratio"))
            })?;
        if !ratio.is_finite() || !(0.0..=1.0).contains(&ratio) {
            return Err(TelemetryConfigError::Invalid("sample ratio"));
        }
        Ok(Self {
            mode,
            endpoint: Some(endpoint),
            trace_queue,
            log_queue,
            metric_queue,
            batch_size,
            schedule: std::time::Duration::from_millis(schedule_ms as u64),
            export_timeout: std::time::Duration::from_millis(export_ms as u64),
            metric_interval: std::time::Duration::from_millis(metric_ms as u64),
            shutdown_timeout: std::time::Duration::from_millis(shutdown_ms as u64),
            trace_sample_ratio: ratio,
            ca_pem,
            client_cert_pem,
            client_key_pem,
            headers,
        })
    }
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            mode: OtlpMode::Disabled,
            endpoint: None,
            trace_queue: 2_048,
            log_queue: 4_096,
            metric_queue: 2_048,
            batch_size: 256,
            schedule: std::time::Duration::from_millis(500),
            export_timeout: std::time::Duration::from_secs(3),
            metric_interval: std::time::Duration::from_secs(10),
            shutdown_timeout: std::time::Duration::from_secs(5),
            trace_sample_ratio: 0.1,
            ca_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
            headers: Vec::new(),
        }
    }
}

fn parse_bound(
    env: &std::collections::BTreeMap<String, String>,
    key: &'static str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, TelemetryConfigError> {
    let value = env.get(key).map_or(Ok(default), |value| {
        value
            .parse::<usize>()
            .map_err(|_| TelemetryConfigError::Invalid(key))
    })?;
    if !(min..=max).contains(&value) {
        return Err(TelemetryConfigError::Invalid(key));
    }
    Ok(value)
}

fn read_otlp_material(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<Vec<u8>, TelemetryConfigError> {
    use std::io::Read as _;
    #[cfg(unix)]
    let file = {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| TelemetryConfigError::Invalid("secret material"))?;
        let stat =
            rustix::fs::fstat(&fd).map_err(|_| TelemetryConfigError::Invalid("secret material"))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || stat.st_mode & 0o077 != 0
            || stat.st_uid != rustix::process::getuid().as_raw()
        {
            return Err(TelemetryConfigError::Invalid("secret material"));
        }
        std::fs::File::from(fd)
    };
    #[cfg(not(unix))]
    let file =
        std::fs::File::open(path).map_err(|_| TelemetryConfigError::Invalid("secret material"))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(16 * 1024));
    file.take(
        u64::try_from(max_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|_| TelemetryConfigError::Invalid("secret material"))?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        bytes.fill(0);
        return Err(TelemetryConfigError::Invalid("secret material"));
    }
    Ok(bytes)
}

fn parse_otlp_headers(bytes: &[u8]) -> Result<Vec<(String, String)>, TelemetryConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|_| TelemetryConfigError::Invalid("headers"))?;
    let mut headers = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(TelemetryConfigError::Invalid("headers"))?;
        let name = name.trim();
        let value = value.trim();
        if headers.len() >= 32
            || value.is_empty()
            || value.len() > 8 * 1024
            || !names.insert(name.to_ascii_lowercase())
            || reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_str(value).is_err()
        {
            return Err(TelemetryConfigError::Invalid("headers"));
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    if headers.is_empty() {
        return Err(TelemetryConfigError::Invalid("headers"));
    }
    Ok(headers)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TelemetryConfigError {
    #[error("OTLP is disabled but exporter configuration was supplied")]
    DisabledHasConfiguration,
    #[error("OTLP endpoint is required")]
    MissingEndpoint,
    #[error("invalid OTLP {0}")]
    Invalid(&'static str),
}

/// Isolated, bounded optional projection owner. Each signal owns a bounded
/// queue and worker, preventing cross-signal head-of-line blocking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DispatchCorrelationKey {
    tenant_scope: String,
    dispatch_id: String,
    generation: String,
}

#[derive(Debug, Clone)]
struct ActiveDispatchCorrelation {
    correlation: crate::TelemetryCorrelation,
    retired: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone)]
pub struct TelemetryHandle {
    senders: [Option<std::sync::mpsc::SyncSender<TelemetryRecord>>; 3],
    drops: std::sync::Arc<DropCounters>,
    series: std::sync::Arc<std::sync::Mutex<SeriesRegistry>>,
    correlations: std::sync::Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<DispatchCorrelationKey, ActiveDispatchCorrelation>,
        >,
    >,
    correlation_capacity: usize,
    trace_sample_ratio: f64,
    emission_gate: std::sync::Arc<std::sync::Mutex<()>>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown_health: std::sync::Arc<ShutdownHealth>,
}

pub(crate) struct DispatchCorrelationGuard {
    handle: TelemetryHandle,
    key: DispatchCorrelationKey,
    retired: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for DispatchCorrelationGuard {
    fn drop(&mut self) {
        self.retired
            .store(true, std::sync::atomic::Ordering::Release);
        if let Ok(mut correlations) = self.handle.correlations.try_lock() {
            correlations.remove(&self.key);
        }
    }
}

impl TelemetryHandle {
    fn invalid_record(&self) {
        self.drops.increment(DropReason::InvalidAttribute);
        eprintln!("smesh telemetry record dropped: invalid authoritative correlation");
    }

    #[doc(hidden)]
    #[must_use]
    pub fn metric_capture_with_limits_for_test(
        capacity: usize,
        per_instrument_limit: usize,
        global_limit: usize,
    ) -> (Self, std::sync::mpsc::Receiver<TelemetryRecord>) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        (
            Self {
                senders: [None, None, Some(sender)],
                drops: std::sync::Arc::new(DropCounters::default()),
                series: std::sync::Arc::new(std::sync::Mutex::new(SeriesRegistry::new(
                    per_instrument_limit,
                    global_limit,
                ))),
                correlations: std::sync::Arc::new(std::sync::Mutex::new(
                    std::collections::BTreeMap::new(),
                )),
                correlation_capacity: capacity.max(1),
                trace_sample_ratio: 1.0,
                emission_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
                closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                shutdown_health: std::sync::Arc::new(ShutdownHealth::default()),
            },
            receiver,
        )
    }

    #[doc(hidden)]
    #[must_use]
    pub fn log_capture_for_test(
        capacity: usize,
    ) -> (Self, std::sync::mpsc::Receiver<TelemetryRecord>) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        (
            Self {
                senders: [None, Some(sender), None],
                drops: std::sync::Arc::new(DropCounters::default()),
                series: std::sync::Arc::new(std::sync::Mutex::new(SeriesRegistry::default())),
                correlations: std::sync::Arc::new(std::sync::Mutex::new(
                    std::collections::BTreeMap::new(),
                )),
                correlation_capacity: capacity.max(1),
                trace_sample_ratio: 1.0,
                emission_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
                closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                shutdown_health: std::sync::Arc::new(ShutdownHealth::default()),
            },
            receiver,
        )
    }

    #[doc(hidden)]
    #[must_use]
    pub fn multisignal_capture_for_test(
        capacity: usize,
        trace_sample_ratio: f64,
    ) -> (Self, std::sync::mpsc::Receiver<TelemetryRecord>) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        (
            Self {
                senders: [Some(sender.clone()), Some(sender.clone()), Some(sender)],
                drops: std::sync::Arc::new(DropCounters::default()),
                series: std::sync::Arc::new(std::sync::Mutex::new(SeriesRegistry::default())),
                correlations: std::sync::Arc::new(std::sync::Mutex::new(
                    std::collections::BTreeMap::new(),
                )),
                correlation_capacity: capacity.max(1),
                trace_sample_ratio,
                emission_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
                closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                shutdown_health: std::sync::Arc::new(ShutdownHealth::default()),
            },
            receiver,
        )
    }

    #[must_use]
    pub fn try_emit(&self, record: TelemetryRecord) -> bool {
        let Ok(_emission) = self.emission_gate.try_lock() else {
            self.drops.increment(DropReason::QueueFull);
            return false;
        };
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let mut registry_guard = None;
        let mut newly_reserved = false;
        if let Some(point) = record.metric_point() {
            match self.series.try_lock() {
                Ok(mut registry) => {
                    let before = registry.series_count();
                    if !registry.admit(point) {
                        self.drops.increment(DropReason::SeriesLimit);
                        return false;
                    }
                    newly_reserved = registry.series_count() != before;
                    registry_guard = Some(registry);
                }
                Err(_) => {
                    self.drops.increment(DropReason::QueueFull);
                    return false;
                }
            }
        }
        let index = match record.signal() {
            Signal::Span => 0,
            Signal::Log => 1,
            Signal::Metric => 2,
        };
        let Some(sender) = self.senders[index].as_ref() else {
            return false;
        };
        match sender.try_send(record) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(record)) => {
                if newly_reserved
                    && let (Some(registry), Some(point)) =
                        (registry_guard.as_mut(), record.metric_point())
                {
                    registry.rollback(point);
                }
                self.drops.increment(DropReason::QueueFull);
                false
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(record)) => {
                if newly_reserved
                    && let (Some(registry), Some(point)) =
                        (registry_guard.as_mut(), record.metric_point())
                {
                    registry.rollback(point);
                }
                self.drops.increment(DropReason::Transport);
                false
            }
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn try_emit_with_overlap_barrier_for_test(
        &self,
        record: TelemetryRecord,
        entered: &std::sync::Barrier,
        release: &std::sync::Barrier,
    ) -> bool {
        let _emission = self
            .emission_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        entered.wait();
        release.wait();
        let index = match record.signal() {
            Signal::Span => 0,
            Signal::Log => 1,
            Signal::Metric => 2,
        };
        self.senders[index]
            .as_ref()
            .is_some_and(|sender| sender.try_send(record).is_ok())
    }

    fn sample_trace(&self) -> bool {
        self.trace_sample_ratio >= 1.0
            || (self.trace_sample_ratio > 0.0 && rand::random::<f64>() < self.trace_sample_ratio)
    }

    pub(crate) fn authentication_decision(
        &self,
        context: Option<&RequestTelemetryContext>,
        outcome: &'static str,
        reason: &'static str,
        start: u64,
    ) {
        let mut log_attributes = vec![
            Attribute::new(AttributeKey::Outcome, outcome)
                .expect("static authentication outcome is valid"),
            Attribute::new(AttributeKey::Reason, reason)
                .expect("static authentication reason is valid"),
        ];
        if let Some(context) = context {
            log_attributes.push(
                Attribute::new(AttributeKey::RequestId, context.request_id())
                    .expect("server request identifier is valid"),
            );
        }
        let _ = self.try_emit(
            TelemetryRecord::log(EventName::AuthenticationDecided, log_attributes.clone())
                .expect("static authentication telemetry is valid"),
        );
        if self.sample_trace()
            && let Some(context) = context
        {
            let end = now_unix_nanos().max(start);
            let span = ClosedSpan::new(
                SpanName::AuthVerify,
                context.trace_id(),
                rand::random(),
                Some(context.span_id()),
                Vec::new(),
                start,
                end,
                log_attributes,
            )
            .expect("server authentication span is valid");
            let _ = self.try_emit(TelemetryRecord::span(span));
        }
    }

    pub(crate) fn authorization_decision(
        &self,
        outcome: &'static str,
        reason: &'static str,
        operation: &'static str,
    ) {
        let context = current_request_telemetry_context();
        let mut attributes = Vec::with_capacity(4);
        for attribute in [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Reason, reason),
            Attribute::new(AttributeKey::Operation, operation),
        ] {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        if let Some(context) = context.as_ref() {
            let Ok(attribute) = Attribute::new(AttributeKey::RequestId, context.request_id())
            else {
                return;
            };
            attributes.push(attribute);
        }
        if let Ok(record) = TelemetryRecord::log(EventName::AuthorizationDecided, attributes) {
            let _ = self.try_emit(record);
        }
    }

    pub(crate) fn durable_event(
        &self,
        name: EventName,
        outcome: &'static str,
        reason: &'static str,
        operation: &'static str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        message_id: Option<&str>,
    ) {
        let request = current_request_telemetry_context();
        let mut attributes = Vec::with_capacity(6);
        for attribute in [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Reason, reason),
            Attribute::new(AttributeKey::Operation, operation),
        ] {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        for attribute in [
            request
                .as_ref()
                .map(|v| Attribute::new(AttributeKey::RequestId, v.request_id())),
            task_id.map(|v| Attribute::new(AttributeKey::TaskId, v)),
            context_id.map(|v| Attribute::new(AttributeKey::ContextId, v)),
            message_id.map(|v| Attribute::new(AttributeKey::MessageId, v)),
        ]
        .into_iter()
        .flatten()
        {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        if let Ok(record) = TelemetryRecord::log(name, attributes.clone()) {
            let _ = self.try_emit(record);
        }
        if self.sample_trace()
            && let Some(request) = request.as_ref()
        {
            let span_name = match operation {
                "get_task" | "list_tasks" | "subscribe_to_task" => SpanName::DurableRead,
                "cancel_task" => SpanName::DurableCancel,
                "terminal_commit" => SpanName::DurableCommit,
                _ => SpanName::DurableAdmission,
            };
            let now = now_unix_nanos();
            if let Ok(span) = ClosedSpan::new(
                span_name,
                request.trace_id(),
                rand::random(),
                Some(request.span_id()),
                Vec::new(),
                now,
                now,
                attributes.clone(),
            ) {
                let _ = self.try_emit(TelemetryRecord::span(span));
            }
        }
        let metric_attributes = [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Operation, operation),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>();
        if let Ok(attributes) = metric_attributes
            && let Ok(point) = MetricPoint::new(MetricName::DurableOperation, 1, attributes)
        {
            let _ = self.try_emit(TelemetryRecord::metric(point));
        }
    }

    pub(crate) fn remember_dispatch_correlation(
        &self,
        tenant_scope: &str,
        generation: &str,
        dispatch_id: &str,
        correlation: crate::TelemetryCorrelation,
    ) -> Option<DispatchCorrelationGuard> {
        if tenant_scope.is_empty()
            || tenant_scope.len() > MAX_CORRELATION_BYTES
            || tenant_scope.chars().any(char::is_control)
            || generation.is_empty()
            || generation.len() > MAX_CORRELATION_BYTES
            || generation.chars().any(char::is_control)
            || Attribute::new(AttributeKey::DispatchId, dispatch_id).is_err()
        {
            self.invalid_record();
            return None;
        }
        let key = DispatchCorrelationKey {
            tenant_scope: tenant_scope.to_owned(),
            dispatch_id: dispatch_id.to_owned(),
            generation: generation.to_owned(),
        };
        let Ok(mut correlations) = self.correlations.try_lock() else {
            self.drops.increment(DropReason::QueueFull);
            return None;
        };
        correlations.retain(|_, active| !active.retired.load(std::sync::atomic::Ordering::Acquire));
        if !correlations.contains_key(&key) && correlations.len() >= self.correlation_capacity {
            self.drops.increment(DropReason::QueueFull);
            return None;
        }
        let retired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        correlations.insert(
            key.clone(),
            ActiveDispatchCorrelation {
                correlation,
                retired: std::sync::Arc::clone(&retired),
            },
        );
        Some(DispatchCorrelationGuard {
            handle: self.clone(),
            key,
            retired,
        })
    }

    #[doc(hidden)]
    #[must_use]
    pub fn dispatch_correlation_count_for_test(&self) -> usize {
        self.correlations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|active| !active.retired.load(std::sync::atomic::Ordering::Acquire))
            .count()
    }

    pub(crate) fn dispatch_event(
        &self,
        name: EventName,
        outcome: &'static str,
        reason: &'static str,
        operation: &'static str,
        tenant_scope: &str,
        generation: &str,
        dispatch_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
    ) {
        self.dispatch_event_with_task_state(
            name,
            outcome,
            reason,
            operation,
            tenant_scope,
            generation,
            dispatch_id,
            task_id,
            context_id,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_event_with_task_state(
        &self,
        name: EventName,
        outcome: &'static str,
        reason: &'static str,
        operation: &'static str,
        tenant_scope: &str,
        generation: &str,
        dispatch_id: &str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        task_state: Option<&'static str>,
    ) {
        let key = DispatchCorrelationKey {
            tenant_scope: tenant_scope.to_owned(),
            dispatch_id: dispatch_id.to_owned(),
            generation: generation.to_owned(),
        };
        let correlation = self
            .correlations
            .try_lock()
            .ok()
            .and_then(|correlations| correlations.get(&key).cloned())
            .filter(|active| !active.retired.load(std::sync::atomic::Ordering::Acquire))
            .map(|active| active.correlation);
        if correlation.is_none() {
            self.invalid_record();
            return;
        }
        let task_id = correlation
            .as_ref()
            .map_or(task_id, |value| Some(value.task_id.as_str()));
        let context_id = correlation
            .as_ref()
            .map_or(context_id, |value| Some(value.context_id.as_str()));
        let message_id = correlation.as_ref().map(|value| value.message_id.as_str());
        let mut attributes = Vec::with_capacity(8);
        for attribute in [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Reason, reason),
            Attribute::new(AttributeKey::Operation, operation),
            Attribute::new(AttributeKey::DispatchId, dispatch_id),
        ] {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        for attribute in [
            task_id.map(|v| Attribute::new(AttributeKey::TaskId, v)),
            context_id.map(|v| Attribute::new(AttributeKey::ContextId, v)),
            message_id.map(|v| Attribute::new(AttributeKey::MessageId, v)),
            task_state.map(|v| Attribute::new(AttributeKey::TaskState, v)),
        ]
        .into_iter()
        .flatten()
        {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        if let Ok(record) = TelemetryRecord::log(name, attributes.clone()) {
            let _ = self.try_emit(record);
        }
        if self.trace_sample_ratio > 0.0 {
            let span_name = match operation {
                "outbox_claim" => SpanName::OutboxClaim,
                "outbox_renew" => SpanName::LeaseRenew,
                "receiver_admit" => SpanName::ReceiverAdmit,
                "receiver_execute" => SpanName::ReceiverExecute,
                "terminal_commit" | "task_transition" => SpanName::DurableCommit,
                _ => SpanName::OutboxAttempt,
            };
            let root = SpanLink::for_dispatch(tenant_scope, dispatch_id);
            let (trace_id, span_id, links) = if operation == "outbox_claim" {
                (root.trace_id, root.span_id, Vec::new())
            } else {
                (rand::random(), rand::random(), vec![root])
            };
            let now = now_unix_nanos();
            if let Ok(span) = ClosedSpan::new(
                span_name, trace_id, span_id, None, links, now, now, attributes,
            ) {
                let _ = self.try_emit(TelemetryRecord::span(span));
            }
        }
        if let Ok(attributes) = [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Operation, operation),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
            && let Ok(point) = MetricPoint::new(MetricName::DurableOperation, 1, attributes)
        {
            let _ = self.try_emit(TelemetryRecord::metric(point));
        }
    }

    pub(crate) fn runtime_event(
        &self,
        name: EventName,
        reason: &'static str,
        task_id: Option<&str>,
        context_id: Option<&str>,
        signal_hash: Option<&str>,
    ) {
        let mut attributes = Vec::with_capacity(5);
        for attribute in [
            Attribute::new(AttributeKey::Outcome, "ok"),
            Attribute::new(AttributeKey::Reason, reason),
            Attribute::new(AttributeKey::Operation, "runtime_capture"),
        ] {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        for attribute in [
            task_id.map(|v| Attribute::new(AttributeKey::TaskId, v)),
            context_id.map(|v| Attribute::new(AttributeKey::ContextId, v)),
            signal_hash.map(|v| Attribute::new(AttributeKey::SignalHash, v)),
        ]
        .into_iter()
        .flatten()
        {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        if let Ok(record) = TelemetryRecord::log(name, attributes) {
            let _ = self.try_emit(record);
        }
    }

    pub(crate) fn artifact_event(
        &self,
        name: EventName,
        outcome: &'static str,
        reason: &'static str,
        operation: &'static str,
        artifact_id: Option<&str>,
        task_id: Option<&str>,
        context_id: Option<&str>,
        message_id: Option<&str>,
        tenant_scope: Option<&str>,
        generation: Option<&str>,
        dispatch_id: Option<&str>,
    ) {
        let correlation =
            tenant_scope
                .zip(generation)
                .zip(dispatch_id)
                .and_then(|((tenant, generation), id)| {
                    let key = DispatchCorrelationKey {
                        tenant_scope: tenant.to_owned(),
                        dispatch_id: id.to_owned(),
                        generation: generation.to_owned(),
                    };
                    self.correlations
                        .try_lock()
                        .ok()
                        .and_then(|correlations| correlations.get(&key).cloned())
                        .filter(|active| !active.retired.load(std::sync::atomic::Ordering::Acquire))
                        .map(|active| active.correlation)
                });
        if generation.is_some() && correlation.is_none()
            || generation.is_some() && tenant_scope.is_none()
            || generation.is_some() && dispatch_id.is_none()
        {
            self.invalid_record();
            return;
        }
        let task_id = correlation
            .as_ref()
            .map_or(task_id, |value| Some(value.task_id.as_str()));
        let context_id = correlation
            .as_ref()
            .map_or(context_id, |value| Some(value.context_id.as_str()));
        let message_id = correlation
            .as_ref()
            .map_or(message_id, |value| Some(value.message_id.as_str()));
        let mut attributes = Vec::with_capacity(8);
        for attribute in [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Reason, reason),
            Attribute::new(AttributeKey::Operation, operation),
        ] {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        for attribute in [
            artifact_id.map(|value| Attribute::new(AttributeKey::ArtifactId, value)),
            task_id.map(|value| Attribute::new(AttributeKey::TaskId, value)),
            context_id.map(|value| Attribute::new(AttributeKey::ContextId, value)),
            dispatch_id.map(|value| Attribute::new(AttributeKey::DispatchId, value)),
            message_id.map(|value| Attribute::new(AttributeKey::MessageId, value)),
        ]
        .into_iter()
        .flatten()
        {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        if let Ok(record) = TelemetryRecord::log(name, attributes.clone()) {
            let _ = self.try_emit(record);
        }
        if self.trace_sample_ratio > 0.0 {
            let now = now_unix_nanos();
            let links = tenant_scope
                .zip(dispatch_id)
                .map_or_else(Vec::new, |(tenant, id)| {
                    vec![SpanLink::for_dispatch(tenant, id)]
                });
            if let Ok(span) = ClosedSpan::new(
                SpanName::ArtifactOperation,
                rand::random(),
                rand::random(),
                None,
                links,
                now,
                now,
                attributes,
            ) {
                let _ = self.try_emit(TelemetryRecord::span(span));
            }
        }
    }

    pub(crate) fn quota_decision(&self, outcome: &'static str, operation: &'static str) {
        let context = current_request_telemetry_context();
        let mut attributes = Vec::with_capacity(3);
        for attribute in [
            Attribute::new(AttributeKey::Outcome, outcome),
            Attribute::new(AttributeKey::Operation, operation),
        ] {
            let Ok(attribute) = attribute else { return };
            attributes.push(attribute);
        }
        if let Some(context) = context {
            let Ok(attribute) = Attribute::new(AttributeKey::RequestId, context.request_id())
            else {
                return;
            };
            attributes.push(attribute);
        }
        if let Ok(record) = TelemetryRecord::log(EventName::QuotaDecided, attributes.clone()) {
            let _ = self.try_emit(record);
        }
        attributes.retain(|a| a.key() != AttributeKey::RequestId.as_str());
        if let Ok(point) = MetricPoint::new(MetricName::QuotaDecision, 1, attributes) {
            let _ = self.try_emit(TelemetryRecord::metric(point));
        }
    }

    /// Read the non-recursive owner-side drop snapshot.
    #[must_use]
    pub fn drop_count(&self, reason: DropReason) -> u64 {
        self.drops.get(reason)
    }
}

pub struct OtlpOwner {
    senders: [Option<std::sync::mpsc::SyncSender<TelemetryRecord>>; 3],
    drops: std::sync::Arc<DropCounters>,
    series: std::sync::Arc<std::sync::Mutex<SeriesRegistry>>,
    correlations: std::sync::Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<DispatchCorrelationKey, ActiveDispatchCorrelation>,
        >,
    >,
    correlation_capacity: usize,
    held_receiver: Option<std::sync::mpsc::Receiver<TelemetryRecord>>,
    workers: Vec<std::thread::JoinHandle<()>>,
    stops: Vec<std::sync::mpsc::SyncSender<std::time::Instant>>,
    done: Option<std::sync::mpsc::Receiver<()>>,
    trace_sample_ratio: f64,
    emission_gate: std::sync::Arc<std::sync::Mutex<()>>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown_health: std::sync::Arc<ShutdownHealth>,
}
impl OtlpOwner {
    pub fn start(config: OtlpConfig) -> Result<Option<Self>, TelemetryConfigError> {
        if config.mode == OtlpMode::Disabled {
            return Ok(None);
        }
        let trace_sample_ratio = config.trace_sample_ratio;
        let (trace_tx, trace_rx) = std::sync::mpsc::sync_channel(config.trace_queue);
        let (log_tx, log_rx) = std::sync::mpsc::sync_channel(config.log_queue);
        let (metric_tx, metric_rx) = std::sync::mpsc::sync_channel(config.metric_queue);
        let drops = std::sync::Arc::new(DropCounters::default());
        let series = std::sync::Arc::new(std::sync::Mutex::new(SeriesRegistry::default()));
        let emission_gate = std::sync::Arc::new(std::sync::Mutex::new(()));
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_health = std::sync::Arc::new(ShutdownHealth::default());
        shutdown_health
            .workers_alive
            .store(3, std::sync::atomic::Ordering::Release);
        let (done_tx, done) = std::sync::mpsc::sync_channel(3);
        let mut workers = Vec::with_capacity(3);
        let mut stops = Vec::with_capacity(3);
        for (signal, receiver) in [
            (Signal::Span, trace_rx),
            (Signal::Log, log_rx),
            (Signal::Metric, metric_rx),
        ] {
            let config = config.clone();
            let drops = std::sync::Arc::clone(&drops);
            let done_tx = done_tx.clone();
            let worker_health = std::sync::Arc::clone(&shutdown_health);
            let (stop_tx, stop_rx) = std::sync::mpsc::sync_channel(1);
            stops.push(stop_tx);
            workers.push(
                std::thread::Builder::new()
                    .name(format!("smesh-otlp-{}", signal_name(signal)))
                    .spawn(move || {
                        run_otlp_worker(config, signal, receiver, stop_rx, &drops);
                        worker_health
                            .workers_alive
                            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                        let _ = done_tx.try_send(());
                    })
                    .map_err(|_| TelemetryConfigError::Invalid("worker"))?,
            );
        }
        Ok(Some(Self {
            senders: [Some(trace_tx), Some(log_tx), Some(metric_tx)],
            drops,
            series,
            correlations: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            correlation_capacity: config.log_queue.max(1),
            held_receiver: None,
            workers,
            stops,
            done: Some(done),
            trace_sample_ratio,
            emission_gate,
            closed,
            shutdown_health,
        }))
    }
    #[doc(hidden)]
    #[must_use]
    pub fn blocked_for_test(capacity: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        Self {
            senders: [None, Some(tx), None],
            drops: std::sync::Arc::new(DropCounters::default()),
            series: std::sync::Arc::new(std::sync::Mutex::new(SeriesRegistry::default())),
            correlations: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            correlation_capacity: capacity.max(1),
            held_receiver: Some(rx),
            workers: Vec::new(),
            stops: Vec::new(),
            done: None,
            trace_sample_ratio: 1.0,
            emission_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
            closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown_health: std::sync::Arc::new(ShutdownHealth::default()),
        }
    }
    #[doc(hidden)]
    #[must_use]
    pub fn blocked_metrics_for_test(
        capacity: usize,
        per_instrument_limit: usize,
        global_limit: usize,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        Self {
            senders: [None, None, Some(tx)],
            drops: std::sync::Arc::new(DropCounters::default()),
            series: std::sync::Arc::new(std::sync::Mutex::new(
                SeriesRegistry::with_limits_for_test(per_instrument_limit, global_limit),
            )),
            correlations: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            correlation_capacity: capacity.max(1),
            held_receiver: Some(rx),
            workers: Vec::new(),
            stops: Vec::new(),
            done: None,
            trace_sample_ratio: 1.0,
            emission_gate: std::sync::Arc::new(std::sync::Mutex::new(())),
            closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown_health: std::sync::Arc::new(ShutdownHealth::default()),
        }
    }
    #[must_use]
    pub fn handle(&self) -> TelemetryHandle {
        TelemetryHandle {
            senders: self.senders.clone(),
            drops: std::sync::Arc::clone(&self.drops),
            series: std::sync::Arc::clone(&self.series),
            correlations: std::sync::Arc::clone(&self.correlations),
            correlation_capacity: self.correlation_capacity,
            trace_sample_ratio: self.trace_sample_ratio,
            emission_gate: std::sync::Arc::clone(&self.emission_gate),
            closed: std::sync::Arc::clone(&self.closed),
            shutdown_health: std::sync::Arc::clone(&self.shutdown_health),
        }
    }
    /// Capture exporter health without retaining any queue sender.
    #[must_use]
    pub fn health_snapshot(&self) -> TelemetryHealthSnapshot {
        TelemetryHealthSnapshot {
            drops: std::sync::Arc::clone(&self.drops),
            shutdown: std::sync::Arc::clone(&self.shutdown_health),
        }
    }
    #[must_use]
    pub fn try_emit(&self, record: TelemetryRecord) -> bool {
        let Ok(_emission) = self.emission_gate.try_lock() else {
            self.drops.increment(DropReason::QueueFull);
            return false;
        };
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let mut registry_guard = None;
        let mut newly_reserved = false;
        if let Some(point) = record.metric_point() {
            match self.series.try_lock() {
                Ok(mut registry) => {
                    let before = registry.series_count();
                    if !registry.admit(point) {
                        self.drops.increment(DropReason::SeriesLimit);
                        return false;
                    }
                    newly_reserved = registry.series_count() != before;
                    registry_guard = Some(registry);
                }
                Err(_) => {
                    self.drops.increment(DropReason::QueueFull);
                    return false;
                }
            }
        }
        let index = match record.signal() {
            Signal::Span => 0,
            Signal::Log => 1,
            Signal::Metric => 2,
        };
        let Some(sender) = self.senders[index].as_ref() else {
            return false;
        };
        match sender.try_send(record) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(record)) => {
                if newly_reserved
                    && let (Some(registry), Some(point)) =
                        (registry_guard.as_mut(), record.metric_point())
                {
                    registry.rollback(point);
                }
                self.drops.increment(DropReason::QueueFull);
                false
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(record)) => {
                if newly_reserved
                    && let (Some(registry), Some(point)) =
                        (registry_guard.as_mut(), record.metric_point())
                {
                    registry.rollback(point);
                }
                self.drops.increment(DropReason::Transport);
                false
            }
        }
    }
    #[must_use]
    pub fn drop_count(&self, reason: DropReason) -> u64 {
        self.drops.get(reason)
    }
    #[must_use]
    pub fn shutdown(mut self, deadline: std::time::Duration) -> bool {
        let shutdown_deadline = std::time::Instant::now() + deadline;
        self.shutdown_health
            .started
            .store(true, std::sync::atomic::Ordering::Release);
        {
            let _emission = self
                .emission_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
            for stop in &self.stops {
                let _ = stop.try_send(shutdown_deadline);
            }
            self.senders = [None, None, None];
        }
        if self.held_receiver.is_some() && deadline.is_zero() {
            self.shutdown_health
                .timed_out
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.shutdown_health
                .outcome
                .store(2, std::sync::atomic::Ordering::Release);
            return false;
        }
        let Some(done) = self.done.take() else {
            self.shutdown_health
                .completed
                .store(true, std::sync::atomic::Ordering::Release);
            self.shutdown_health
                .outcome
                .store(1, std::sync::atomic::Ordering::Release);
            return true;
        };
        let start = std::time::Instant::now();
        for _ in 0..self.workers.len() {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() || done.recv_timeout(remaining).is_err() {
                self.shutdown_health
                    .timed_out
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.shutdown_health
                    .outcome
                    .store(2, std::sync::atomic::Ordering::Release);
                // A timed-out shutdown is observable, but workers are still joined so
                // no task, transport, or secret-bearing runtime can detach.
                for worker in self.workers.drain(..) {
                    let _ = worker.join();
                }
                return false;
            }
        }
        let joined = self.workers.drain(..).all(|worker| worker.join().is_ok());
        if joined {
            self.shutdown_health
                .completed
                .store(true, std::sync::atomic::Ordering::Release);
            self.shutdown_health
                .outcome
                .store(1, std::sync::atomic::Ordering::Release);
        } else {
            self.shutdown_health
                .join_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.shutdown_health
                .outcome
                .store(3, std::sync::atomic::Ordering::Release);
        }
        joined
    }
}
impl Drop for OtlpOwner {
    fn drop(&mut self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        for stop in &self.stops {
            let _ = stop.try_send(std::time::Instant::now());
        }
        self.senders = [None, None, None];
    }
}

const fn signal_name(signal: Signal) -> &'static str {
    match signal {
        Signal::Span => "traces",
        Signal::Log => "logs",
        Signal::Metric => "metrics",
    }
}
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}
fn proto_attributes(
    attributes: &[Attribute],
) -> Vec<opentelemetry_proto::tonic::common::v1::KeyValue> {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    attributes
        .iter()
        .map(|a| KeyValue {
            key: a.key().to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::StringValue(a.value().to_owned())),
            }),
            key_strindex: 0,
        })
        .collect()
}
fn proto_scope() -> opentelemetry_proto::tonic::common::v1::InstrumentationScope {
    opentelemetry_proto::tonic::common::v1::InstrumentationScope {
        name: "smesh-a2a".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        ..Default::default()
    }
}
fn trace_request(
    spans: &[&ClosedSpan],
) -> opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest {
    use opentelemetry_proto::tonic::{collector::trace::v1::ExportTraceServiceRequest, trace::v1};
    let wire = spans
        .iter()
        .map(|span| v1::Span {
            trace_id: span.trace_id.to_vec(),
            span_id: span.span_id.to_vec(),
            parent_span_id: span.parent_span_id.map_or_else(Vec::new, |v| v.to_vec()),
            name: span.name.as_str().to_owned(),
            kind: v1::span::SpanKind::Internal as i32,
            start_time_unix_nano: span.start_time_unix_nano,
            end_time_unix_nano: span.end_time_unix_nano,
            attributes: proto_attributes(&span.attributes),
            links: span
                .links
                .iter()
                .map(|link| v1::span::Link {
                    trace_id: link.trace_id.to_vec(),
                    span_id: link.span_id.to_vec(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
        .collect();
    ExportTraceServiceRequest {
        resource_spans: vec![v1::ResourceSpans {
            scope_spans: vec![v1::ScopeSpans {
                scope: Some(proto_scope()),
                spans: wire,
                schema_url: String::new(),
            }],
            ..Default::default()
        }],
    }
}
fn log_request(
    records: &[&TelemetryRecord],
) -> opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest {
    use opentelemetry_proto::tonic::{
        collector::logs::v1::ExportLogsServiceRequest,
        common::v1::{AnyValue, any_value},
        logs::v1,
    };
    let now = now_unix_nanos();
    ExportLogsServiceRequest {
        resource_logs: vec![v1::ResourceLogs {
            scope_logs: vec![v1::ScopeLogs {
                scope: Some(proto_scope()),
                log_records: records
                    .iter()
                    .map(|record| v1::LogRecord {
                        time_unix_nano: now,
                        observed_time_unix_nano: now,
                        severity_number: v1::SeverityNumber::Info as i32,
                        severity_text: "INFO".to_owned(),
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(record.name.clone())),
                        }),
                        attributes: proto_attributes(&record.attributes),
                        event_name: record.name.clone(),
                        ..Default::default()
                    })
                    .collect(),
                schema_url: String::new(),
            }],
            ..Default::default()
        }],
    }
}
const HISTOGRAM_BOUNDS: [f64; 10] = [
    1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0,
];
fn metric_unit(name: MetricName) -> &'static str {
    match name {
        MetricName::A2aRequestDuration | MetricName::TaskSettlementDuration => "ms",
        MetricName::OutboxRows => "{row}",
        MetricName::AuditProjectionLag => "s",
        MetricName::TelemetryQueue => "{item}",
        MetricName::TaskAdmitted | MetricName::TaskSettled => "{task}",
        _ => "{event}",
    }
}
fn metric_request(
    point: &MetricPoint,
) -> opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest {
    use opentelemetry_proto::tonic::{
        collector::metrics::v1::ExportMetricsServiceRequest, metrics::v1,
    };
    let now = now_unix_nanos();
    let start = if point.aggregation_start_unix_nano == 0 {
        now
    } else {
        point.aggregation_start_unix_nano
    };
    let attributes = proto_attributes(&point.attributes);
    let data = if matches!(
        point.name,
        MetricName::A2aRequestDuration | MetricName::TaskSettlementDuration
    ) {
        let bucket = HISTOGRAM_BOUNDS
            .iter()
            .position(|b| point.value as f64 <= *b)
            .unwrap_or(HISTOGRAM_BOUNDS.len());
        let mut counts = if point.bucket_counts.is_empty() {
            vec![0; HISTOGRAM_BOUNDS.len() + 1]
        } else {
            point.bucket_counts.clone()
        };
        if point.bucket_counts.is_empty() {
            counts[bucket] = 1;
        }
        v1::metric::Data::Histogram(v1::Histogram {
            data_points: vec![v1::HistogramDataPoint {
                attributes,
                start_time_unix_nano: start,
                time_unix_nano: now,
                count: point.count,
                sum: Some(point.sum as f64),
                bucket_counts: counts,
                explicit_bounds: HISTOGRAM_BOUNDS.to_vec(),
                min: Some(point.min as f64),
                max: Some(point.max as f64),
                ..Default::default()
            }],
            aggregation_temporality: v1::AggregationTemporality::Cumulative as i32,
        })
    } else {
        let number = v1::NumberDataPoint {
            attributes,
            start_time_unix_nano: start,
            time_unix_nano: now,
            value: Some(v1::number_data_point::Value::AsInt(
                i64::try_from(point.value).unwrap_or(i64::MAX),
            )),
            ..Default::default()
        };
        if matches!(
            point.name,
            MetricName::OutboxRows | MetricName::AuditProjectionLag | MetricName::TelemetryQueue
        ) {
            v1::metric::Data::Gauge(v1::Gauge {
                data_points: vec![number],
            })
        } else {
            v1::metric::Data::Sum(v1::Sum {
                data_points: vec![number],
                aggregation_temporality: v1::AggregationTemporality::Cumulative as i32,
                is_monotonic: true,
            })
        }
    };
    ExportMetricsServiceRequest {
        resource_metrics: vec![v1::ResourceMetrics {
            scope_metrics: vec![v1::ScopeMetrics {
                scope: Some(proto_scope()),
                metrics: vec![v1::Metric {
                    name: point.name.as_str().to_owned(),
                    description: format!("SMESH {}", point.name.as_str()),
                    unit: metric_unit(point.name).to_owned(),
                    data: Some(data),
                    ..Default::default()
                }],
                schema_url: String::new(),
            }],
            ..Default::default()
        }],
    }
}

fn metric_series_key(point: &MetricPoint) -> String {
    let mut attributes: Vec<_> = point
        .attributes
        .iter()
        .map(|attribute| (attribute.key(), attribute.value()))
        .collect();
    attributes.sort_unstable();
    let mut key = point.name.as_str().to_owned();
    for (name, value) in attributes {
        key.push('\0');
        key.push_str(name);
        key.push('\0');
        key.push_str(value);
    }
    key
}

fn accumulate_metric(
    aggregates: &mut std::collections::BTreeMap<String, MetricPoint>,
    point: &MetricPoint,
    start: u64,
) -> MetricPoint {
    let key = metric_series_key(point);
    let histogram = matches!(
        point.name,
        MetricName::A2aRequestDuration | MetricName::TaskSettlementDuration
    );
    let gauge = matches!(
        point.name,
        MetricName::OutboxRows | MetricName::AuditProjectionLag | MetricName::TelemetryQueue
    );
    match aggregates.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            let mut initial = point.clone();
            initial.aggregation_start_unix_nano = start;
            if histogram {
                initial.bucket_counts = vec![0; HISTOGRAM_BOUNDS.len() + 1];
                let bucket = HISTOGRAM_BOUNDS
                    .iter()
                    .position(|bound| point.value as f64 <= *bound)
                    .unwrap_or(HISTOGRAM_BOUNDS.len());
                initial.bucket_counts[bucket] = 1;
            }
            entry.insert(initial).clone()
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let aggregate = entry.get_mut();
            if gauge {
                aggregate.value = point.value;
                aggregate.count = 1;
                aggregate.sum = point.value;
                aggregate.min = point.value;
                aggregate.max = point.value;
            } else {
                aggregate.value = aggregate.value.saturating_add(point.value);
                aggregate.count = aggregate.count.saturating_add(1);
                aggregate.sum = aggregate.sum.saturating_add(point.value);
                aggregate.min = aggregate.min.min(point.value);
                aggregate.max = aggregate.max.max(point.value);
                if histogram {
                    let bucket = HISTOGRAM_BOUNDS
                        .iter()
                        .position(|bound| point.value as f64 <= *bound)
                        .unwrap_or(HISTOGRAM_BOUNDS.len());
                    aggregate.bucket_counts[bucket] =
                        aggregate.bucket_counts[bucket].saturating_add(1);
                }
            }
            aggregate.clone()
        }
    }
}

fn run_otlp_worker(
    config: OtlpConfig,
    signal: Signal,
    receiver: std::sync::mpsc::Receiver<TelemetryRecord>,
    stop: std::sync::mpsc::Receiver<std::time::Instant>,
    drops: &DropCounters,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            drops.increment(DropReason::Transport);
            return;
        }
    };
    let started = std::time::Instant::now();
    let metric_start = now_unix_nanos();
    let mut metric_aggregates = std::collections::BTreeMap::new();
    let mut metric_dirty = false;
    let mut pending = Vec::with_capacity(config.batch_size);
    let mut batch_deadline: Option<std::time::Instant> = None;
    let mut metric_deadline = std::time::Instant::now() + config.metric_interval;
    let mut circuit = CircuitBreaker::new();
    let mut stopping = false;
    let mut shutdown_deadline = None;
    let mut transport = None;
    loop {
        if let Ok(deadline) = stop.try_recv() {
            stopping = true;
            shutdown_deadline = Some(deadline);
        }
        if stopping {
            while shutdown_deadline.is_some_and(|deadline| std::time::Instant::now() < deadline)
                && pending.len() < config.batch_size
            {
                let Ok(record) = receiver.try_recv() else {
                    break;
                };
                if signal == Signal::Metric {
                    if let Some(point) = record.metric_point() {
                        accumulate_metric(&mut metric_aggregates, point, metric_start);
                        metric_dirty = true;
                    }
                } else {
                    pending.push(record);
                }
            }
        } else {
            let now = std::time::Instant::now();
            let due = if signal == Signal::Metric {
                metric_deadline
            } else {
                batch_deadline.unwrap_or(now + config.schedule)
            };
            let wait = due
                .saturating_duration_since(now)
                .min(std::time::Duration::from_millis(10));
            match receiver.recv_timeout(wait) {
                Ok(record) if signal == Signal::Metric => {
                    if let Some(point) = record.metric_point() {
                        accumulate_metric(&mut metric_aggregates, point, metric_start);
                        metric_dirty = true;
                    }
                }
                Ok(record) => {
                    if pending.is_empty() {
                        batch_deadline = Some(std::time::Instant::now() + config.schedule);
                    }
                    pending.push(record);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => stopping = true,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }

        let now = std::time::Instant::now();
        let due = if signal == Signal::Metric {
            metric_dirty && (stopping || now >= metric_deadline)
        } else {
            !pending.is_empty()
                && (stopping
                    || pending.len() >= config.batch_size
                    || batch_deadline.is_some_and(|deadline| now >= deadline))
        };
        if due {
            let batch = if signal == Signal::Metric {
                metric_aggregates
                    .values()
                    .cloned()
                    .map(TelemetryRecord::metric)
                    .collect()
            } else {
                std::mem::take(&mut pending)
            };
            batch_deadline = None;
            let mut all_exported = true;
            for chunk in batch.chunks(config.batch_size) {
                let now_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let remaining = shutdown_deadline.map_or(config.export_timeout, |deadline| {
                    deadline.saturating_duration_since(std::time::Instant::now())
                });
                if remaining.is_zero() {
                    all_exported = false;
                    for _ in chunk {
                        drops.increment(DropReason::Shutdown);
                    }
                    continue;
                }
                if stopping || circuit.allow(now_millis) {
                    let exported = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        runtime.block_on(export_records(
                            &config,
                            signal,
                            chunk,
                            &mut transport,
                            config.export_timeout.min(remaining),
                        ))
                    }));
                    match exported {
                        Ok(Ok(())) if !stopping => circuit.success(),
                        Ok(Ok(())) => {}
                        Ok(Err(reason)) => {
                            all_exported = false;
                            drops.increment(reason);
                            if !stopping {
                                circuit.failure(now_millis);
                            }
                            transport = None;
                        }
                        Err(_) => {
                            all_exported = false;
                            drops.increment(DropReason::Serialization);
                            if !stopping {
                                circuit.failure(now_millis);
                            }
                            transport = None;
                        }
                    }
                } else {
                    all_exported = false;
                    drops.increment(DropReason::CircuitOpen);
                }
            }
            if signal == Signal::Metric && all_exported {
                metric_dirty = false;
            }
            if signal == Signal::Metric {
                metric_deadline = now + config.metric_interval;
            }
        }
        if stopping {
            let queue_empty = match receiver.try_recv() {
                Ok(record) => {
                    if signal == Signal::Metric {
                        if let Some(point) = record.metric_point() {
                            accumulate_metric(&mut metric_aggregates, point, metric_start);
                            metric_dirty = true;
                        }
                    } else {
                        pending.push(record);
                    }
                    false
                }
                Err(_) => true,
            };
            if queue_empty
                || shutdown_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                while receiver.try_recv().is_ok() {
                    drops.increment(DropReason::Shutdown);
                }
                break;
            }
        }
    }
}
enum WorkerTransport {
    Http(reqwest::Client),
    Grpc(tonic::transport::Channel),
}

fn http_client(config: &OtlpConfig) -> Result<reqwest::Client, ()> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.export_timeout);
    if let Some(ca) = &config.ca_pem {
        for certificate in reqwest::Certificate::from_pem_bundle(ca).map_err(|_| ())? {
            builder = builder.add_root_certificate(certificate);
        }
    }
    if let (Some(cert), Some(key)) = (&config.client_cert_pem, &config.client_key_pem) {
        let mut identity = cert.clone();
        identity.extend_from_slice(key);
        builder = builder.identity(reqwest::Identity::from_pem(&identity).map_err(|_| ())?);
    }
    builder.build().map_err(|_| ())
}

async fn export_records(
    config: &OtlpConfig,
    signal: Signal,
    records: &[TelemetryRecord],
    transport: &mut Option<WorkerTransport>,
    timeout: std::time::Duration,
) -> Result<(), DropReason> {
    let operation = async {
        if transport.is_none() {
            *transport = Some(match config.mode {
                OtlpMode::HttpProtobuf => WorkerTransport::Http(http_client(config)?),
                OtlpMode::Grpc => WorkerTransport::Grpc(grpc_channel(config).await?),
                OtlpMode::Disabled => return Ok(()),
            });
        }
        match transport.as_ref().ok_or(())? {
            WorkerTransport::Http(client) => export_http(config, client, signal, records).await,
            WorkerTransport::Grpc(channel) => export_grpc(config, channel, signal, records).await,
        }
    };
    match tokio::time::timeout(timeout, operation).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(())) => Err(DropReason::Transport),
        Err(_) => Err(DropReason::Timeout),
    }
}
fn metric_batch_request(
    points: &[&MetricPoint],
) -> opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest {
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    let mut combined = ExportMetricsServiceRequest::default();
    for point in points {
        let mut request = metric_request(point);
        if let Some(resource) = request.resource_metrics.pop() {
            if combined.resource_metrics.is_empty() {
                combined.resource_metrics.push(resource);
            } else if let (Some(target), Some(mut source)) = (
                combined.resource_metrics[0].scope_metrics.first_mut(),
                resource.scope_metrics.into_iter().next(),
            ) {
                target.metrics.append(&mut source.metrics);
            }
        }
    }
    combined
}

async fn export_http(
    config: &OtlpConfig,
    client: &reqwest::Client,
    signal: Signal,
    records: &[TelemetryRecord],
) -> Result<(), ()> {
    use prost::Message as _;
    let endpoint = config
        .endpoint
        .as_ref()
        .ok_or(())?
        .join(&format!("v1/{}", signal_name(signal)))
        .map_err(|_| ())?;
    let bytes = match signal {
        Signal::Span => {
            let values: Vec<_> = records
                .iter()
                .filter_map(|record| match &record.payload {
                    TelemetryPayload::Span(value) => Some(value),
                    _ => None,
                })
                .collect();
            if values.len() != records.len() {
                return Err(());
            }
            trace_request(&values).encode_to_vec()
        }
        Signal::Log => {
            if records
                .iter()
                .any(|record| !matches!(record.payload, TelemetryPayload::Log))
            {
                return Err(());
            }
            log_request(&records.iter().collect::<Vec<_>>()).encode_to_vec()
        }
        Signal::Metric => {
            let values: Vec<_> = records
                .iter()
                .filter_map(TelemetryRecord::metric_point)
                .collect();
            if values.len() != records.len() {
                return Err(());
            }
            metric_batch_request(&values).encode_to_vec()
        }
    };
    let mut request = client
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf");
    for (name, value) in &config.headers {
        request = request.header(name, value);
    }
    let response = request.body(bytes).send().await.map_err(|_| ())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(())
    }
}
async fn grpc_channel(config: &OtlpConfig) -> Result<tonic::transport::Channel, ()> {
    let url = config.endpoint.as_ref().ok_or(())?;
    let mut endpoint = tonic::transport::Endpoint::from_shared(url.as_str().to_owned())
        .map_err(|_| ())?
        .connect_timeout(config.export_timeout)
        .timeout(config.export_timeout);
    if url.scheme() == "https" {
        let mut tls = tonic::transport::ClientTlsConfig::new()
            .with_enabled_roots()
            .domain_name(url.host_str().ok_or(())?);
        if let Some(ca) = &config.ca_pem {
            tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(ca));
        }
        if let (Some(cert), Some(key)) = (&config.client_cert_pem, &config.client_key_pem) {
            tls = tls.identity(tonic::transport::Identity::from_pem(cert, key));
        }
        endpoint = endpoint.tls_config(tls).map_err(|_| ())?;
    }
    endpoint.connect().await.map_err(|_| ())
}

fn grpc_request<T>(config: &OtlpConfig, payload: T) -> Result<tonic::Request<T>, ()> {
    let mut request = tonic::Request::new(payload);
    for (name, value) in &config.headers {
        let key: tonic::metadata::MetadataKey<tonic::metadata::Ascii> =
            name.parse().map_err(|_| ())?;
        let value: tonic::metadata::MetadataValue<tonic::metadata::Ascii> =
            value.parse().map_err(|_| ())?;
        request.metadata_mut().insert(key, value);
    }
    Ok(request)
}

async fn export_grpc(
    config: &OtlpConfig,
    channel: &tonic::transport::Channel,
    signal: Signal,
    records: &[TelemetryRecord],
) -> Result<(), ()> {
    match signal {
        Signal::Span => {
            use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;
            let values: Vec<_> = records
                .iter()
                .filter_map(|record| match &record.payload {
                    TelemetryPayload::Span(value) => Some(value),
                    _ => None,
                })
                .collect();
            if values.len() != records.len() {
                return Err(());
            }
            TraceServiceClient::new(channel.clone())
                .export(grpc_request(config, trace_request(&values))?)
                .await
                .map_err(|_| ())?;
        }
        Signal::Log => {
            use opentelemetry_proto::tonic::collector::logs::v1::logs_service_client::LogsServiceClient;
            if records
                .iter()
                .any(|record| !matches!(&record.payload, TelemetryPayload::Log))
            {
                return Err(());
            }
            LogsServiceClient::new(channel.clone())
                .export(grpc_request(
                    config,
                    log_request(&records.iter().collect::<Vec<_>>()),
                )?)
                .await
                .map_err(|_| ())?;
        }
        Signal::Metric => {
            use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
            let values: Vec<_> = records
                .iter()
                .filter_map(TelemetryRecord::metric_point)
                .collect();
            if values.len() != records.len() {
                return Err(());
            }
            MetricsServiceClient::new(channel.clone())
                .export(grpc_request(config, metric_batch_request(&values))?)
                .await
                .map_err(|_| ())?;
        }
    }
    Ok(())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuditProjectorError {
    #[error("invalid audit projector configuration")]
    InvalidConfig,
    #[error("audit projector is unsupported")]
    Unsupported,
    #[error("audit projector shutdown timed out")]
    ShutdownTimeout,
    #[error("audit projector task failed")]
    Join,
}

#[derive(Debug, Clone)]
pub struct AuditProjectorConfig {
    owner: String,
    poll_interval: std::time::Duration,
    batch_size: usize,
    lease_duration_ms: i64,
    retention_ms: i64,
    cleanup_limit: usize,
}
impl AuditProjectorConfig {
    /// Derive a stable, bounded, opaque projector lease owner from a replica ID.
    pub fn for_replica_id(
        replica_id: &str,
        poll_interval: std::time::Duration,
        batch_size: usize,
    ) -> Result<Self, AuditProjectorError> {
        if replica_id.is_empty()
            || replica_id.len() > 128
            || !replica_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(AuditProjectorError::InvalidConfig);
        }
        let mut owner_input = b"smesh-audit-projector-owner-v1\0".to_vec();
        owner_input.extend_from_slice(replica_id.as_bytes());
        let digest = crate::content_digest(&owner_input);
        Self::new(format!("ap-{}", &digest[..61]), poll_interval, batch_size)
    }

    pub fn new(
        owner: impl Into<String>,
        poll_interval: std::time::Duration,
        batch_size: usize,
    ) -> Result<Self, AuditProjectorError> {
        let owner = owner.into();
        if owner.is_empty()
            || owner.len() > 64
            || !owner.is_ascii()
            || !(std::time::Duration::from_millis(10)..=std::time::Duration::from_secs(5))
                .contains(&poll_interval)
            || !(1..=1_000).contains(&batch_size)
        {
            return Err(AuditProjectorError::InvalidConfig);
        }
        Ok(Self {
            owner,
            poll_interval,
            batch_size,
            lease_duration_ms: 30_000,
            retention_ms: 7 * 24 * 60 * 60 * 1_000,
            cleanup_limit: batch_size,
        })
    }
}

/// Joinable production owner for the durable audit projection outbox.
pub struct AuditProjectorWorker {
    stop: tokio_util::sync::CancellationToken,
    join: tokio::task::JoinHandle<()>,
    completed_cycles: tokio::sync::watch::Receiver<u64>,
    shutdown_health: std::sync::Arc<ShutdownHealth>,
}
impl AuditProjectorWorker {
    pub fn spawn<A>(
        authority: std::sync::Arc<A>,
        telemetry: TelemetryHandle,
        config: AuditProjectorConfig,
    ) -> Result<Self, AuditProjectorError>
    where
        A: crate::AuthorityIdentity + ?Sized + 'static,
    {
        let projection = authority
            .audit_projection_authority()
            .ok_or(AuditProjectorError::Unsupported)?;
        if !projection.audit_projection_capabilities().enabled {
            return Err(AuditProjectorError::Unsupported);
        }
        let shutdown_health = std::sync::Arc::clone(&telemetry.shutdown_health);
        let stop = tokio_util::sync::CancellationToken::new();
        let stopped = stop.clone();
        let (cycle_tx, completed_cycles) = tokio::sync::watch::channel(0_u64);
        let join = tokio::spawn(async move {
            let mut consecutive_errors = 0_u32;
            let mut cycle = 0_u64;
            loop {
                if stopped.is_cancelled() {
                    break;
                }
                let Some(projection) = authority.audit_projection_authority() else {
                    break;
                };
                match projection
                    .claim_audit_projection(
                        &config.owner,
                        config.lease_duration_ms,
                        config.batch_size,
                    )
                    .await
                {
                    Ok(rows) => {
                        consecutive_errors = 0;
                        if rows.is_empty()
                            && let Ok(metric) =
                                MetricPoint::new(MetricName::AuditProjectionLag, 0, vec![])
                        {
                            let _ = telemetry.try_emit(TelemetryRecord::metric(metric));
                        }
                        for row in rows {
                            if stopped.is_cancelled() {
                                break;
                            }
                            let accepted = audit_projection_record(&row)
                                .is_ok_and(|record| telemetry.try_emit(record));
                            if accepted {
                                let now = chrono::Utc::now().timestamp_millis();
                                let lag = now.saturating_sub(row.occurred_at()).max(0) / 1_000;
                                if let Ok(metric) = MetricPoint::new(
                                    MetricName::AuditProjectionLag,
                                    u64::try_from(lag).unwrap_or(u64::MAX),
                                    vec![],
                                ) {
                                    let _ = telemetry.try_emit(TelemetryRecord::metric(metric));
                                }
                                let _ = projection.commit_audit_projection(&row).await;
                            } else {
                                let digest =
                                    crate::content_digest(b"audit-projection-queue-rejected");
                                let _ =
                                    projection.fail_audit_projection(&row, &digest, 1_000).await;
                                if let Ok(metric) =
                                    MetricPoint::new(MetricName::AuditProjectionFailure, 1, vec![])
                                {
                                    let _ = telemetry.try_emit(TelemetryRecord::metric(metric));
                                }
                            }
                        }
                        let _ = projection
                            .cleanup_audit_projection(config.retention_ms, config.cleanup_limit)
                            .await;
                    }
                    Err(_) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        if let Ok(metric) =
                            MetricPoint::new(MetricName::AuditProjectionFailure, 1, vec![])
                        {
                            let _ = telemetry.try_emit(TelemetryRecord::metric(metric));
                        }
                    }
                }
                cycle = cycle.saturating_add(1);
                let _ = cycle_tx.send(cycle);
                let multiplier = 1_u32 << consecutive_errors.min(6);
                let wait = config
                    .poll_interval
                    .saturating_mul(multiplier)
                    .min(std::time::Duration::from_secs(5));
                tokio::select! { () = stopped.cancelled() => break, () = tokio::time::sleep(wait) => {} }
            }
        });
        Ok(Self {
            stop,
            join,
            completed_cycles,
            shutdown_health,
        })
    }

    #[doc(hidden)]
    pub async fn wait_for_completed_cycle(
        &self,
        timeout: std::time::Duration,
    ) -> Result<(), AuditProjectorError> {
        let mut cycles = self.completed_cycles.clone();
        let baseline = *cycles.borrow();
        tokio::time::timeout(timeout, async move {
            loop {
                cycles
                    .changed()
                    .await
                    .map_err(|_| AuditProjectorError::Join)?;
                if *cycles.borrow() > baseline {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| AuditProjectorError::ShutdownTimeout)?
    }

    pub async fn shutdown(
        mut self,
        timeout: std::time::Duration,
    ) -> Result<(), AuditProjectorError> {
        self.stop.cancel();
        match tokio::time::timeout(timeout, &mut self.join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => {
                self.shutdown_health
                    .join_failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.shutdown_health
                    .outcome
                    .store(3, std::sync::atomic::Ordering::Release);
                Err(AuditProjectorError::Join)
            }
            Err(_) => {
                self.join.abort();
                let _ = (&mut self.join).await;
                self.shutdown_health
                    .timed_out
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.shutdown_health
                    .outcome
                    .store(2, std::sync::atomic::Ordering::Release);
                Err(AuditProjectorError::ShutdownTimeout)
            }
        }
    }
}
impl Drop for AuditProjectorWorker {
    fn drop(&mut self) {
        self.stop.cancel();
        self.join.abort();
    }
}

fn audit_projection_record(
    row: &crate::AuditProjectionLease,
) -> Result<TelemetryRecord, TelemetrySchemaError> {
    let operation = audit_projection_operation(row.event_kind(), row.source())
        .ok_or(TelemetrySchemaError::InvalidAttribute)?;
    TelemetryRecord::log(
        EventName::AuditProjectorState,
        vec![
            Attribute::new(AttributeKey::AuditSource, row.source().as_str())?,
            Attribute::new(AttributeKey::EventId, row.event_id())?,
            // `ok` describes successful projection processing, not the effect
            // of the authoritative event. The closed operation preserves that
            // committed fact class without fabricating allow/deny semantics.
            Attribute::new(AttributeKey::Outcome, "ok")?,
            Attribute::new(AttributeKey::Reason, "committed")?,
            Attribute::new(AttributeKey::Operation, operation)?,
        ],
    )
}

#[allow(clippy::match_same_arms)] // Each event kind is intentionally an exhaustive schema row.
const fn audit_projection_operation(
    kind: crate::AuditProjectionEventKind,
    source: crate::AuditProjectionSource,
) -> Option<&'static str> {
    use crate::{AuditProjectionEventKind as K, AuditProjectionSource as S};
    match kind {
        K::AuthorizationDecided => match source {
            S::AuthorizationDecision => Some("authorization_decision"),
            _ => None,
        },
        K::TaskTerminal => match source {
            S::TaskEvent => Some("task_terminal"),
            _ => None,
        },
        K::TaskCanceled => match source {
            S::TaskEvent | S::CancellationIntent => Some("task_canceled"),
            _ => None,
        },
        K::QuotaDenied => match source {
            S::QuotaDenial => Some("quota_denied"),
            _ => None,
        },
        K::QuotaOverridden => match source {
            S::QuotaOverride => Some("quota_overridden"),
            _ => None,
        },
        K::QuotaReconciled => match source {
            S::QuotaReconciliation => Some("quota_reconciled"),
            _ => None,
        },
        K::ArtifactCorruptionDetected => match source {
            S::ArtifactCorruption => Some("artifact_corruption"),
            _ => None,
        },
        K::ArtifactKeyChanged => match source {
            S::ArtifactKey => Some("artifact_key_changed"),
            _ => None,
        },
        K::ArtifactOperatorCompleted => match source {
            S::ArtifactMigration => Some("artifact_migration_completed"),
            S::ArtifactBackup => Some("artifact_backup_completed"),
            S::ArtifactRestore => Some("artifact_restore_completed"),
            S::ArtifactKeyRotation => Some("artifact_rotation_completed"),
            S::AuthorizationDecision
            | S::TaskEvent
            | S::CancellationIntent
            | S::QuotaDenial
            | S::QuotaOverride
            | S::QuotaReconciliation
            | S::ArtifactCorruption
            | S::ArtifactKey
            | S::CallbackPolicy
            | S::CallbackConfig
            | S::CallbackEvent
            | S::CallbackDelivery
            | S::CallbackAttempt => None,
        },
        K::CallbackPolicyReconciled => match source {
            S::CallbackPolicy => Some("callback_policy_reconciled"),
            _ => None,
        },
        K::CallbackConfigCreated => match source {
            S::CallbackConfig => Some("callback_config_created"),
            _ => None,
        },
        K::CallbackConfigDeleted => match source {
            S::CallbackConfig => Some("callback_config_deleted"),
            _ => None,
        },
        K::CallbackEventEnqueued => match source {
            S::CallbackEvent => Some("callback_event_enqueued"),
            _ => None,
        },
        K::CallbackDeliveryAttempted => match source {
            S::CallbackDelivery | S::CallbackAttempt => Some("callback_delivery_attempted"),
            _ => None,
        },
        K::CallbackDelivered => match source {
            S::CallbackDelivery | S::CallbackAttempt => Some("callback_delivered"),
            _ => None,
        },
        K::CallbackRetryScheduled => match source {
            S::CallbackDelivery | S::CallbackAttempt => Some("callback_retry_scheduled"),
            _ => None,
        },
        K::CallbackDead => match source {
            S::CallbackDelivery | S::CallbackAttempt => Some("callback_dead"),
            _ => None,
        },
    }
}

#[cfg(test)]
mod dispatch_correlation_tests {
    use std::time::{Duration, Instant};

    use super::{EventName, SpanLink, TelemetryHandle};
    use crate::TelemetryCorrelation;

    fn correlation(label: &str) -> TelemetryCorrelation {
        TelemetryCorrelation::new(
            format!("message-{label}"),
            format!("task-{label}"),
            format!("context-{label}"),
        )
        .unwrap()
    }

    #[test]
    fn scoped_fenced_correlations_plateau_and_retire_without_stale_identity_removal() {
        assert_ne!(
            SpanLink::for_dispatch("tenant-a", "shared-dispatch"),
            SpanLink::for_dispatch("tenant-b", "shared-dispatch")
        );
        let (handle, receiver) = TelemetryHandle::log_capture_for_test(2);
        let first = handle
            .remember_dispatch_correlation(
                "tenant-a",
                "lease-a1",
                "shared-dispatch",
                correlation("a1"),
            )
            .unwrap();
        let second = handle
            .remember_dispatch_correlation(
                "tenant-b",
                "lease-b1",
                "shared-dispatch",
                correlation("b1"),
            )
            .unwrap();
        assert_eq!(handle.correlations.lock().unwrap().len(), 2);
        assert!(
            handle
                .remember_dispatch_correlation(
                    "tenant-c",
                    "lease-c1",
                    "third-dispatch",
                    correlation("c1"),
                )
                .is_none()
        );
        let started = Instant::now();
        for offender in 0..10_000 {
            assert!(
                handle
                    .remember_dispatch_correlation(
                        "tenant-offender",
                        "lease-offender",
                        &format!("offender-{offender}"),
                        correlation("offender"),
                    )
                    .is_none()
            );
        }
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(handle.correlations.lock().unwrap().len(), 2);

        drop(second);
        let replacement = handle
            .remember_dispatch_correlation(
                "tenant-a",
                "lease-a2",
                "shared-dispatch",
                correlation("a2"),
            )
            .unwrap();
        for (generation, expected_task) in [("lease-a1", "task-a1"), ("lease-a2", "task-a2")] {
            handle.dispatch_event(
                EventName::DispatchClaimed,
                "ok",
                "claimed",
                "outbox_claim",
                "tenant-a",
                generation,
                "shared-dispatch",
                None,
                None,
            );
            let record = receiver.recv_timeout(Duration::from_millis(50)).unwrap();
            assert!(record.attributes().iter().any(|attribute| {
                attribute.key() == "a2a.task.id" && attribute.value() == expected_task
            }));
        }
        drop(first);
        assert_eq!(handle.correlations.lock().unwrap().len(), 1);
        handle.dispatch_event(
            EventName::DispatchClaimed,
            "ok",
            "claimed",
            "outbox_claim",
            "tenant-a",
            "lease-a1",
            "shared-dispatch",
            None,
            None,
        );
        assert!(receiver.recv_timeout(Duration::from_millis(10)).is_err());
        drop(replacement);
        assert!(handle.correlations.lock().unwrap().is_empty());
        let healthy = handle
            .remember_dispatch_correlation(
                "tenant-healthy",
                "lease-healthy",
                "healthy-dispatch",
                correlation("healthy"),
            )
            .unwrap();
        handle.dispatch_event(
            EventName::DispatchClaimed,
            "ok",
            "claimed",
            "outbox_claim",
            "tenant-healthy",
            "lease-healthy",
            "healthy-dispatch",
            None,
            None,
        );
        let record = receiver.recv_timeout(Duration::from_millis(50)).unwrap();
        assert!(record.attributes().iter().any(|attribute| {
            attribute.key() == "a2a.task.id" && attribute.value() == "task-healthy"
        }));
        let lock = handle.correlations.lock().unwrap();
        let retirement_started = Instant::now();
        drop(healthy);
        assert!(retirement_started.elapsed() < Duration::from_millis(10));
        drop(lock);
        assert_eq!(handle.dispatch_correlation_count_for_test(), 0);
        handle.dispatch_event(
            EventName::DispatchClaimed,
            "ok",
            "claimed",
            "outbox_claim",
            "tenant-healthy",
            "lease-healthy",
            "healthy-dispatch",
            None,
            None,
        );
        assert!(receiver.recv_timeout(Duration::from_millis(10)).is_err());
    }

    #[test]
    fn direct_artifact_authority_emits_complete_or_absent_causal_identity() {
        let (handle, receiver) = TelemetryHandle::log_capture_for_test(4);
        handle.artifact_event(
            EventName::ArtifactRegistered,
            "ok",
            "committed",
            "artifact_register",
            Some("artifact-registered"),
            Some("task-registered"),
            Some("context-registered"),
            Some("message-registered"),
            Some("tenant-registered"),
            None,
            Some("dispatch-registered"),
        );
        let registered = receiver.recv_timeout(Duration::from_millis(50)).unwrap();
        assert_eq!(registered.name(), EventName::ArtifactRegistered.as_str());
        for key in [
            "a2a.task.id",
            "a2a.context.id",
            "a2a.message.id",
            "smesh.dispatch.id",
        ] {
            assert!(
                registered
                    .attributes()
                    .iter()
                    .any(|attribute| attribute.key() == key)
            );
        }

        handle.artifact_event(
            EventName::ArtifactCorruptionDetected,
            "failed",
            "quarantined",
            "artifact_resolve",
            Some("artifact-corrupt"),
            None,
            None,
            None,
            Some("tenant-corrupt"),
            None,
            None,
        );
        let corruption = receiver.recv_timeout(Duration::from_millis(50)).unwrap();
        assert_eq!(
            corruption.name(),
            EventName::ArtifactCorruptionDetected.as_str()
        );
        assert!(corruption.attributes().iter().all(|attribute| {
            !matches!(
                attribute.key(),
                "a2a.task.id" | "a2a.context.id" | "a2a.message.id" | "smesh.dispatch.id"
            )
        }));
    }
}

#[cfg(test)]
mod audit_projection_mapping_tests {
    use super::audit_projection_operation;
    use crate::{AuditProjectionEventKind as K, AuditProjectionSource as S};

    #[test]
    fn every_production_event_kind_has_a_closed_operation_mapping() {
        let cases = [
            (
                K::AuthorizationDecided,
                S::AuthorizationDecision,
                "authorization_decision",
            ),
            (K::TaskTerminal, S::TaskEvent, "task_terminal"),
            (K::TaskCanceled, S::TaskEvent, "task_canceled"),
            (K::TaskCanceled, S::CancellationIntent, "task_canceled"),
            (K::QuotaDenied, S::QuotaDenial, "quota_denied"),
            (K::QuotaOverridden, S::QuotaOverride, "quota_overridden"),
            (
                K::QuotaReconciled,
                S::QuotaReconciliation,
                "quota_reconciled",
            ),
            (
                K::ArtifactCorruptionDetected,
                S::ArtifactCorruption,
                "artifact_corruption",
            ),
            (
                K::ArtifactKeyChanged,
                S::ArtifactKey,
                "artifact_key_changed",
            ),
            (
                K::ArtifactOperatorCompleted,
                S::ArtifactMigration,
                "artifact_migration_completed",
            ),
            (
                K::ArtifactOperatorCompleted,
                S::ArtifactBackup,
                "artifact_backup_completed",
            ),
            (
                K::ArtifactOperatorCompleted,
                S::ArtifactRestore,
                "artifact_restore_completed",
            ),
            (
                K::ArtifactOperatorCompleted,
                S::ArtifactKeyRotation,
                "artifact_rotation_completed",
            ),
            (
                K::CallbackPolicyReconciled,
                S::CallbackPolicy,
                "callback_policy_reconciled",
            ),
            (
                K::CallbackConfigCreated,
                S::CallbackConfig,
                "callback_config_created",
            ),
            (
                K::CallbackConfigDeleted,
                S::CallbackConfig,
                "callback_config_deleted",
            ),
            (
                K::CallbackEventEnqueued,
                S::CallbackEvent,
                "callback_event_enqueued",
            ),
            (
                K::CallbackDeliveryAttempted,
                S::CallbackDelivery,
                "callback_delivery_attempted",
            ),
            (
                K::CallbackDeliveryAttempted,
                S::CallbackAttempt,
                "callback_delivery_attempted",
            ),
            (
                K::CallbackDelivered,
                S::CallbackDelivery,
                "callback_delivered",
            ),
            (
                K::CallbackDelivered,
                S::CallbackAttempt,
                "callback_delivered",
            ),
            (
                K::CallbackRetryScheduled,
                S::CallbackDelivery,
                "callback_retry_scheduled",
            ),
            (
                K::CallbackRetryScheduled,
                S::CallbackAttempt,
                "callback_retry_scheduled",
            ),
            (K::CallbackDead, S::CallbackDelivery, "callback_dead"),
            (K::CallbackDead, S::CallbackAttempt, "callback_dead"),
        ];
        for (kind, source, expected) in cases {
            assert_eq!(audit_projection_operation(kind, source), Some(expected));
        }
        assert_eq!(
            audit_projection_operation(K::QuotaDenied, S::TaskEvent),
            None,
            "mismatched source/kind pairs must not receive a fallback operation"
        );
    }
}
