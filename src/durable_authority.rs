//! Backend-neutral durable authority capabilities.
//!
//! The authority exposes complete, scoped durable commands rather than
//! transactions or generic CRUD. Backend constructors, migrations, schema
//! administration, and local-development compatibility remain outside the
//! production authority contract.

#![allow(clippy::missing_errors_doc)]

use std::{sync::Arc, time::Duration};

use a2a::{
    A2AError, ListTasksRequest, ListTasksResponse, SendMessageRequest, SendMessageResponse,
    StreamResponse, Task,
};
use async_trait::async_trait;

use crate::{
    DurableDispatchEnvelope, DurableReceiverResult, InputLimits, MeshEvent, MeshRequest,
    VisibilityScope, content_digest,
};

const MAX_AUTHORIZATION_TEXT_BYTES: usize = 4_096;
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Fixed compatibility scope used only by local, unauthenticated development mode.
pub const TRUSTED_SINGLE_TENANT_SCOPE: &str = "smesh-dev-only-tenant";

pub(crate) fn valid_bounded_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.is_ascii()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTaskScope {
    pub(crate) tenant_scope: String,
    pub(crate) owner_account_id: String,
    pub(crate) visibility: VisibilityScope,
}

#[allow(clippy::missing_errors_doc)]
impl OwnedTaskScope {
    pub fn new(
        tenant_scope: impl Into<String>,
        owner_account_id: impl Into<String>,
        visibility: VisibilityScope,
    ) -> Result<Self, A2AError> {
        let value = Self {
            tenant_scope: tenant_scope.into(),
            owner_account_id: owner_account_id.into(),
            visibility,
        };
        if !valid_bounded_identity(&value.tenant_scope)
            || !valid_bounded_identity(&value.owner_account_id)
        {
            return Err(A2AError::invalid_request("invalid owned task scope"));
        }
        Ok(value)
    }

    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }

    #[must_use]
    pub fn owner_account_id(&self) -> &str {
        &self.owner_account_id
    }

    #[must_use]
    pub const fn visibility(&self) -> VisibilityScope {
        self.visibility
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDecisionEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationAuditInput {
    pub(crate) decision_id: String,
    pub(crate) tenant_scope: String,
    pub(crate) actor_account_id: String,
    pub(crate) policy_id: String,
    pub(crate) policy_revision: u64,
    pub(crate) policy_digest: String,
    pub(crate) operation: String,
    pub(crate) effect: AuthorizationDecisionEffect,
    pub(crate) reason: String,
    pub(crate) resource_kind: String,
    pub(crate) resource_digest: String,
    pub(crate) task_id: Option<String>,
    pub(crate) decided_at: i64,
}

/// Owned, externally persistable representation of a validated audit decision.
///
/// Backends may destructure this value for storage, while construction and
/// validation remain controlled by [`AuthorizationAuditInput::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationAuditParts {
    pub decision_id: String,
    pub tenant_scope: String,
    pub actor_account_id: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub policy_digest: String,
    pub operation: String,
    pub effect: AuthorizationDecisionEffect,
    pub reason: String,
    pub resource_kind: String,
    pub resource_digest: String,
    pub task_id: Option<String>,
    pub decided_at: i64,
}

#[allow(clippy::missing_errors_doc)]
impl AuthorizationAuditInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_id: impl Into<String>,
        tenant_scope: impl Into<String>,
        actor_account_id: impl Into<String>,
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: impl Into<String>,
        operation: impl Into<String>,
        effect: AuthorizationDecisionEffect,
        reason: impl Into<String>,
        resource_kind: impl Into<String>,
        resource_digest: impl Into<String>,
        task_id: Option<String>,
        decided_at: i64,
    ) -> Result<Self, A2AError> {
        let value = Self {
            decision_id: decision_id.into(),
            tenant_scope: tenant_scope.into(),
            actor_account_id: actor_account_id.into(),
            policy_id: policy_id.into(),
            policy_revision,
            policy_digest: policy_digest.into(),
            operation: operation.into(),
            effect,
            reason: reason.into(),
            resource_kind: resource_kind.into(),
            resource_digest: resource_digest.into(),
            task_id,
            decided_at,
        };
        let short = [
            &value.decision_id,
            &value.tenant_scope,
            &value.actor_account_id,
            &value.policy_id,
            &value.operation,
            &value.reason,
            &value.resource_kind,
            &value.resource_digest,
        ];
        if short.iter().any(|v| v.is_empty() || v.len() > 256)
            || value.policy_revision == 0
            || value.policy_digest.is_empty()
            || value.policy_digest.len() > 256
            || value
                .task_id
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > MAX_AUTHORIZATION_TEXT_BYTES)
        {
            return Err(A2AError::invalid_request(
                "invalid authorization audit input",
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }
    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }
    #[must_use]
    pub fn actor_account_id(&self) -> &str {
        &self.actor_account_id
    }
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }
    #[must_use]
    pub const fn effect(&self) -> AuthorizationDecisionEffect {
        self.effect
    }
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
    #[must_use]
    pub fn resource_kind(&self) -> &str {
        &self.resource_kind
    }
    #[must_use]
    pub fn resource_digest(&self) -> &str {
        &self.resource_digest
    }
    #[must_use]
    pub fn task_id(&self) -> Option<&str> {
        self.task_id.as_deref()
    }
    #[must_use]
    pub const fn decided_at(&self) -> i64 {
        self.decided_at
    }

    /// Consume a validated input into fields suitable for backend persistence.
    #[must_use]
    pub fn into_parts(self) -> AuthorizationAuditParts {
        AuthorizationAuditParts {
            decision_id: self.decision_id,
            tenant_scope: self.tenant_scope,
            actor_account_id: self.actor_account_id,
            policy_id: self.policy_id,
            policy_revision: self.policy_revision,
            policy_digest: self.policy_digest,
            operation: self.operation,
            effect: self.effect,
            reason: self.reason,
            resource_kind: self.resource_kind,
            resource_digest: self.resource_digest,
            task_id: self.task_id,
            decided_at: self.decided_at,
        }
    }

    pub(crate) fn decided(
        mut self,
        effect: AuthorizationDecisionEffect,
        reason: &str,
        task_id: Option<String>,
    ) -> Self {
        self.effect = effect;
        reason.clone_into(&mut self.reason);
        self.task_id = task_id;
        self
    }
}

/// Canonical semantic identity for local-development `SendMessage` admission.
#[allow(clippy::missing_errors_doc)]
pub fn canonical_send_message_digest(
    request: &SendMessageRequest,
    streaming: bool,
) -> Result<String, A2AError> {
    let semantic = serde_json::json!({
        "executionConfiguration": { "outputMode": "application/json" },
        "invocation": if streaming { "streaming" } else { "unary" },
        "message": request.message,
        "metadata": request.metadata,
        "operation": "sendMessage",
        "trustedScope": TRUSTED_SINGLE_TENANT_SCOPE,
    });
    serde_json::to_vec(&semantic)
        .map(|encoded| content_digest(&encoded))
        .map_err(|_| A2AError::internal("failed to canonicalize send-message request"))
}

/// Version 2 semantic digest for authorized admissions.
#[allow(clippy::missing_errors_doc)]
pub fn canonical_send_message_digest_v2(
    tenant_scope: &str,
    actor_account_id: &str,
    request: &SendMessageRequest,
    streaming: bool,
) -> Result<String, A2AError> {
    if !valid_bounded_identity(tenant_scope) || !valid_bounded_identity(actor_account_id) {
        return Err(A2AError::invalid_request("invalid authorization identity"));
    }
    let semantic = serde_json::json!({
        "digestVersion": 2,
        "tenantScope": tenant_scope,
        "actorAccountId": actor_account_id,
        "invocation": if streaming { "streaming" } else { "unary" },
        "operation": "sendMessage",
        "executionConfiguration": { "outputMode": "application/json" },
        "message": request.message,
        "metadata": request.metadata,
    });
    serde_json::to_vec(&semantic)
        .map(|encoded| content_digest(&encoded))
        .map_err(|_| A2AError::internal("failed to canonicalize authorized request"))
}

#[must_use]
pub fn authorized_message_identity(
    tenant_scope: &str,
    actor_account_id: &str,
    message_id: &str,
) -> String {
    content_digest(
        format!("message-v2\0{tenant_scope}\0{actor_account_id}\0{message_id}").as_bytes(),
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct SendMessageAdmission {
    pub request: SendMessageRequest,
    pub streaming: bool,
    pub task: Task,
    pub original_result: SendMessageResponse,
    pub input_limits: InputLimits,
    pub now: i64,
    pub max_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub task_id: String,
    pub revision: u64,
    pub dispatch_id: String,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionOutcome {
    Admitted(AdmissionRecord),
    Replay(SendMessageResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxLease {
    pub tenant_scope: String,
    pub outbox_id: i64,
    pub dispatch_id: String,
    pub task_id: String,
    pub attempt_no: u32,
    pub max_attempts: u32,
    pub lease_owner: String,
    pub lease_token: String,
    pub lease_until: i64,
    pub request: MeshRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptDisposition {
    Retry { available_at: i64, error: String },
    Permanent { error: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverLease {
    pub tenant_scope: String,
    pub dispatch_id: String,
    pub payload_digest: String,
    pub lease_owner: String,
    pub lease_token: String,
    pub lease_epoch: u64,
    pub lease_until: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverAdmission {
    Execute(ReceiverLease),
    Replay(Vec<MeshEvent>),
    ReplayOutcome(DurableReceiverResult),
    Busy,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum CancellationOutcome {
    Canceled(Task),
    AwaitReceiver {
        dispatch_id: String,
        message_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionOutcome {
    Applied,
    Idempotent,
    Stale,
    DeadLettered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicRecordCounts {
    pub tasks: u64,
    pub events: u64,
    pub idempotency_records: u64,
    pub outbox: u64,
}

/// Validated interval for correctness polling when change notifications are lost
/// or originate in another process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollInterval(Duration);

impl PollInterval {
    /// Validate an operational poll interval (`10ms..=5s`).
    #[allow(clippy::missing_errors_doc)]
    pub fn new(value: Duration) -> Result<Self, A2AError> {
        if !(MIN_POLL_INTERVAL..=MAX_POLL_INTERVAL).contains(&value) {
            return Err(A2AError::invalid_request(
                "durable poll interval must be between 10ms and 5s",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl Default for PollInterval {
    fn default() -> Self {
        Self(Duration::from_millis(100))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChangeObservation {
    poll_interval: PollInterval,
}

impl ChangeObservation {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(value: Duration) -> Result<Self, A2AError> {
        PollInterval::new(value).map(|poll_interval| Self { poll_interval })
    }

    #[must_use]
    pub const fn poll_interval(self) -> PollInterval {
        self.poll_interval
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamTranscriptBatch {
    pub frames: Vec<StreamResponse>,
    pub closed: bool,
    pub interruption: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionCursor {
    Transcript { message_id: String, cursor: usize },
    TaskRevision(u64),
}

pub struct TaskEventBatch {
    pub frames: Vec<StreamResponse>,
    pub closed: bool,
    pub last_revision: u64,
}

pub trait AuthorityIdentity: Send + Sync {
    fn completion_receipt_key(&self) -> Option<[u8; 32]>;
    fn authorization_resource_digest(&self, resource: &str) -> Result<String, A2AError>;
}

#[async_trait]
pub trait AuthorizedTaskRead: Send + Sync {
    async fn get_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<Task>, A2AError>;
    async fn list_authorized(
        &self,
        scope: &OwnedTaskScope,
        request: &ListTasksRequest,
        audit: AuthorizationAuditInput,
        cursor_scope_digest: &str,
    ) -> Result<ListTasksResponse, A2AError>;
}

#[async_trait]
pub trait TaskAdmission: Send + Sync {
    async fn replay_authorized(
        &self,
        scope: &OwnedTaskScope,
        actor_account_id: &str,
        request: &SendMessageRequest,
        streaming: bool,
        audit: AuthorizationAuditInput,
    ) -> Result<Option<SendMessageResponse>, A2AError>;
    async fn authorize_and_admit(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError>;
    async fn authorize_and_continue(
        &self,
        scope: &OwnedTaskScope,
        command: SendMessageAdmission,
        audit: AuthorizationAuditInput,
    ) -> Result<AdmissionOutcome, A2AError>;
}

#[async_trait]
pub trait TaskLifecycle: Send + Sync {
    async fn final_result_scoped(
        &self,
        tenant_scope: &str,
        message_id: &str,
    ) -> Result<Option<SendMessageResponse>, A2AError>;
}

#[async_trait]
pub trait OutboxAuthority: Send + Sync {
    async fn claim_outbox(
        &self,
        lease_owner: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<Option<OutboxLease>, A2AError>;
    async fn task_for_outbox(&self, lease: &OutboxLease) -> Result<Option<Task>, A2AError>;
    async fn finish_outbox_attempt(
        &self,
        lease: &OutboxLease,
        disposition: AttemptDisposition,
        now: i64,
    ) -> Result<TransitionOutcome, A2AError>;
    async fn append_stream_progress(
        &self,
        tenant_scope: &str,
        dispatch_id: &str,
        frame: StreamResponse,
        now: i64,
    ) -> Result<Option<StreamResponse>, A2AError>;
    async fn commit_delivery(
        &self,
        lease: &OutboxLease,
        task: Task,
        result: SendMessageResponse,
        public_transcript: &[StreamResponse],
        now: i64,
    ) -> Result<TransitionOutcome, A2AError>;
}

#[async_trait]
pub trait ReceiverAuthority: Send + Sync {
    async fn begin_receive(
        &self,
        envelope: DurableDispatchEnvelope,
        lease_owner: &str,
        now: i64,
        lease_duration: i64,
    ) -> Result<ReceiverAdmission, A2AError>;
    async fn complete_loopback_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError>;
    async fn complete_loopback_outcome(
        &self,
        lease: &ReceiverLease,
        outcome: &DurableReceiverResult,
        now: i64,
    ) -> Result<(), A2AError>;
    async fn complete_canceled_receive(
        &self,
        lease: &ReceiverLease,
        events: &[MeshEvent],
        now: i64,
    ) -> Result<(), A2AError>;
    async fn cancellation_requested(&self, dispatch_id: &str) -> Result<bool, A2AError>;
}

#[async_trait]
pub trait TranscriptAuthority: Send + Sync {
    async fn stream_frames_after_scoped(
        &self,
        tenant_scope: &str,
        message_id: &str,
        last_sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError>;
    async fn subscription_snapshot_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError>;
    async fn task_events_after_scoped(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError>;
}

#[async_trait]
pub trait CancellationAuthority: Send + Sync {
    async fn cancel_authorized(
        &self,
        scope: &OwnedTaskScope,
        task_id: &str,
        now: i64,
        audit: AuthorizationAuditInput,
    ) -> Result<CancellationOutcome, A2AError>;
}

#[async_trait]
pub trait AuthorizationAuditSink: Send + Sync {
    async fn append_denied_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError>;
    async fn append_authorization_decision(
        &self,
        audit: AuthorizationAuditInput,
    ) -> Result<(), A2AError>;
}

pub trait ChangeObserver: Send + Sync {
    fn change_observation(&self) -> ChangeObservation;
}

#[async_trait]
pub trait AuthorityDiagnostics: Send + Sync {
    async fn authorization_decision_count(&self) -> Result<u64, A2AError>;
    async fn atomic_record_counts(&self) -> Result<AtomicRecordCounts, A2AError>;
    async fn durable_effect_count(&self) -> Result<u64, A2AError>;
}

#[async_trait]
pub trait AuthorityShutdown: Send + Sync {
    async fn shutdown(&self) -> Result<(), A2AError>;
    fn close_owned_sync(&self);
}

/// Complete production authority capability set.
///
/// Required methods intentionally have no defaults. In particular, a blank fake
/// cannot claim production conformance:
///
/// ```compile_fail
/// use smesh_a2a::DurableAuthority;
/// struct Blank;
/// impl DurableAuthority for Blank {}
/// ```
pub trait DurableAuthority:
    AuthorityIdentity
    + AuthorizedTaskRead
    + TaskAdmission
    + TaskLifecycle
    + OutboxAuthority
    + ReceiverAuthority
    + TranscriptAuthority
    + CancellationAuthority
    + AuthorizationAuditSink
    + ChangeObserver
    + AuthorityDiagnostics
    + AuthorityShutdown
    + Send
    + Sync
{
}

impl<T> DurableAuthority for T where
    T: AuthorityIdentity
        + AuthorizedTaskRead
        + TaskAdmission
        + TaskLifecycle
        + OutboxAuthority
        + ReceiverAuthority
        + TranscriptAuthority
        + CancellationAuthority
        + AuthorizationAuditSink
        + ChangeObserver
        + AuthorityDiagnostics
        + AuthorityShutdown
        + Send
        + Sync
{
}

/// Opaque conversion result. The optional local adapter is crate-private and is
/// never part of [`DurableAuthority`].
pub struct DurableAuthorityParts {
    pub(crate) authority: Arc<dyn DurableAuthority>,
    pub(crate) local: Option<Arc<dyn LocalDevelopmentCompatibility>>,
}

impl DurableAuthorityParts {
    fn production(authority: Arc<dyn DurableAuthority>) -> Self {
        Self {
            authority,
            local: None,
        }
    }

    pub(crate) fn local(
        authority: Arc<dyn DurableAuthority>,
        local: Arc<dyn LocalDevelopmentCompatibility>,
    ) -> Self {
        Self {
            authority,
            local: Some(local),
        }
    }
}

pub trait IntoDurableAuthority {
    fn into_durable_authority(self) -> Arc<dyn DurableAuthority>;

    #[doc(hidden)]
    fn into_durable_authority_parts(self) -> DurableAuthorityParts
    where
        Self: Sized,
    {
        DurableAuthorityParts::production(self.into_durable_authority())
    }
}

impl IntoDurableAuthority for Arc<dyn DurableAuthority> {
    fn into_durable_authority(self) -> Arc<dyn DurableAuthority> {
        self
    }
}

/// Sealed local-loopback surface. Authenticated production code never receives
/// this dependency, and PostgreSQL adapters cannot implement it outside the crate.
#[async_trait]
pub(crate) trait LocalDevelopmentCompatibility: Send + Sync {
    async fn get(&self, task_id: &str) -> Result<Option<Task>, A2AError>;
    async fn list(&self, request: &ListTasksRequest) -> Result<ListTasksResponse, A2AError>;
    async fn replay(
        &self,
        request: &SendMessageRequest,
        streaming: bool,
    ) -> Result<Option<SendMessageResponse>, A2AError>;
    async fn admit(&self, command: SendMessageAdmission) -> Result<AdmissionOutcome, A2AError>;
    async fn continue_task(
        &self,
        command: SendMessageAdmission,
    ) -> Result<AdmissionOutcome, A2AError>;
    async fn final_result(&self, message_id: &str)
    -> Result<Option<SendMessageResponse>, A2AError>;
    async fn cancel(&self, task_id: &str, now: i64) -> Result<CancellationOutcome, A2AError>;
    async fn stream_frames_after(
        &self,
        message_id: &str,
        last_sequence: usize,
    ) -> Result<StreamTranscriptBatch, A2AError>;
    async fn subscription_snapshot(
        &self,
        task_id: &str,
    ) -> Result<Option<(Task, SubscriptionCursor)>, A2AError>;
    async fn task_events_after(
        &self,
        task_id: &str,
        last_revision: u64,
    ) -> Result<TaskEventBatch, A2AError>;
}
