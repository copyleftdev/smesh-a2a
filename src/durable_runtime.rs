use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::{
    DurableReceiverResult, ExecutionBudget, ExecutionReservation, MeshRequest, content_digest,
};

const MAX_RUNTIME_IDENTITY_BYTES: usize = 256;

fn bounded_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUNTIME_IDENTITY_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Persisted provenance of the server authorization decision bound to a task.
///
/// This records the policy generation that authorized the durable request. It
/// intentionally carries neither transient roles nor account kind: current
/// storage cannot reconstruct either after restart, so the runtime boundary
/// must not invent them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct DurableAuthorizationDecisionProvenance {
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
}

impl DurableAuthorizationDecisionProvenance {
    #[allow(dead_code)]
    pub(crate) fn new(
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: impl Into<String>,
    ) -> Result<Self, a2a::A2AError> {
        let value = Self {
            policy_id: policy_id.into(),
            policy_revision,
            policy_digest: policy_digest.into(),
        };
        if !bounded_identity(&value.policy_id)
            || value.policy_revision == 0
            || !bounded_identity(&value.policy_digest)
        {
            return Err(a2a::A2AError::internal(
                "invalid durable authorization provenance",
            ));
        }
        Ok(value)
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
}

/// Persisted tenant, account, principal, authentication, visibility, and
/// authorization-decision bindings crossing into a runtime.
///
/// These fields are immutable provenance bindings, not runtime authorization.
/// The adapter must not use them to make or repeat an authorization decision.
/// The type is never deserialized from client input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableRuntimeScope {
    tenant_scope: String,
    account_id: String,
    principal_scope: String,
    authentication_method: String,
    visibility: crate::VisibilityScope,
    authorization: DurableAuthorizationDecisionProvenance,
}

impl DurableRuntimeScope {
    pub(crate) fn new(
        tenant_scope: impl Into<String>,
        account_id: impl Into<String>,
        principal_scope: impl Into<String>,
        authentication_method: impl Into<String>,
        visibility: crate::VisibilityScope,
    ) -> Result<Self, a2a::A2AError> {
        Self::from_persisted_task_bindings(
            crate::OwnedTaskScope::new_with_principal_and_authentication(
                tenant_scope,
                account_id,
                principal_scope,
                visibility,
                authentication_method,
            )?,
            DurableAuthorizationDecisionProvenance::new(
                "legacy-test-policy",
                1,
                crate::content_digest(b"legacy-test-policy-v1"),
            )?,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn from_persisted_task_bindings(
        persisted: crate::OwnedTaskScope,
        authorization: DurableAuthorizationDecisionProvenance,
    ) -> Result<Self, a2a::A2AError> {
        let value = Self {
            tenant_scope: persisted.tenant_scope,
            account_id: persisted.owner_account_id,
            principal_scope: persisted.principal_scope,
            authentication_method: persisted.authentication_method,
            visibility: persisted.visibility,
            authorization,
        };
        if !bounded_identity(&value.tenant_scope)
            || !bounded_identity(&value.account_id)
            || !bounded_identity(&value.principal_scope)
            || !bounded_identity(&value.authentication_method)
        {
            return Err(a2a::A2AError::internal("invalid durable runtime scope"));
        }
        Ok(value)
    }

    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }

    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    #[must_use]
    pub fn principal_scope(&self) -> &str {
        &self.principal_scope
    }

    #[must_use]
    pub fn authentication_method(&self) -> &str {
        &self.authentication_method
    }

    #[must_use]
    pub const fn visibility(&self) -> crate::VisibilityScope {
        self.visibility
    }

    #[must_use]
    pub fn authorization_policy_id(&self) -> &str {
        self.authorization.policy_id()
    }

    #[must_use]
    pub const fn authorization_policy_revision(&self) -> u64 {
        self.authorization.policy_revision()
    }

    #[must_use]
    pub fn authorization_policy_digest(&self) -> &str {
        self.authorization.policy_digest()
    }
}

/// Non-secret authoritative key for one runtime execution attempt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableDispatchCorrelation {
    tenant_scope: String,
    dispatch_id: String,
    attempt: u32,
    fence: u64,
}

impl DurableDispatchCorrelation {
    // Constructed by the durable driver once authority wiring lands in the next slice.
    #[allow(dead_code)]
    pub(crate) fn new(
        scope: DurableRuntimeScope,
        dispatch_id: impl Into<String>,
        attempt: u32,
        fence: u64,
    ) -> Result<Self, a2a::A2AError> {
        let dispatch_id = dispatch_id.into();
        if !bounded_identity(&dispatch_id) || attempt == 0 || fence == 0 {
            return Err(a2a::A2AError::internal(
                "invalid durable runtime correlation",
            ));
        }
        Ok(Self {
            tenant_scope: scope.tenant_scope,
            dispatch_id,
            attempt,
            fence,
        })
    }

    pub(crate) fn from_authority_parts(
        tenant_scope: impl Into<String>,
        dispatch_id: impl Into<String>,
        attempt: u32,
        fence: u64,
    ) -> Result<Self, a2a::A2AError> {
        let tenant_scope = tenant_scope.into();
        let dispatch_id = dispatch_id.into();
        if !bounded_identity(&tenant_scope)
            || !bounded_identity(&dispatch_id)
            || attempt == 0
            || fence == 0
        {
            return Err(a2a::A2AError::internal(
                "invalid durable runtime correlation",
            ));
        }
        Ok(Self {
            tenant_scope,
            dispatch_id,
            attempt,
            fence,
        })
    }

    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }

    #[must_use]
    pub fn dispatch_id(&self) -> &str {
        &self.dispatch_id
    }

    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }
}

/// Exact reservation representation loaded by the authority boundary.
///
/// Production always carries the persisted reservation. The payload-free
/// loopback variant is crate-private and exists only for explicit development
/// and unit-test adapters; it is rejected by the channel runtime adapter.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "reservation")]
enum DurableExecutionReservation {
    Production(ExecutionReservation),
    LoopbackDevelopment,
}

/// Crate-owned authority snapshot used to validate immutable runtime bindings.
///
/// Construction is private to the crate so adapters receive an already-made
/// server decision and cannot authorize from the provenance fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DurableRuntimeAuthorityContext {
    scope: DurableRuntimeScope,
    correlation: DurableDispatchCorrelation,
    request: MeshRequest,
    transport_payload_digest: String,
    authorized_request_digest: String,
    execution_reservation: DurableExecutionReservation,
    budget: ExecutionBudget,
}

impl DurableRuntimeAuthorityContext {
    /// Builds a validated production context from durable authority rows.
    ///
    /// External trusted authority implementations use this after authenticating
    /// their persisted sender, receiver, request, authorization, and reservation
    /// bindings. The execution budget is derived from `execution_reservation` and
    /// cannot be supplied independently.
    ///
    /// # Errors
    ///
    /// Returns an internal error when any scope, policy, correlation, request
    /// digest, or reservation binding is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_authority(
        persisted_scope: crate::OwnedTaskScope,
        authorization_policy_id: impl Into<String>,
        authorization_policy_revision: u64,
        authorization_policy_digest: impl Into<String>,
        dispatch_id: impl Into<String>,
        attempt: u32,
        receiver_fence: u64,
        request: MeshRequest,
        transport_payload_digest: impl Into<String>,
        authorized_request_digest: impl Into<String>,
        execution_reservation: ExecutionReservation,
    ) -> Result<Self, a2a::A2AError> {
        let scope = DurableRuntimeScope::from_persisted_task_bindings(
            persisted_scope,
            DurableAuthorizationDecisionProvenance::new(
                authorization_policy_id,
                authorization_policy_revision,
                authorization_policy_digest,
            )?,
        )?;
        let correlation =
            DurableDispatchCorrelation::new(scope.clone(), dispatch_id, attempt, receiver_fence)?;
        Self::production(
            scope,
            correlation,
            request,
            transport_payload_digest,
            authorized_request_digest,
            execution_reservation,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn production(
        scope: DurableRuntimeScope,
        correlation: DurableDispatchCorrelation,
        request: MeshRequest,
        transport_payload_digest: impl Into<String>,
        authorized_request_digest: impl Into<String>,
        execution_reservation: ExecutionReservation,
    ) -> Result<Self, a2a::A2AError> {
        if !bounded_identity(&execution_reservation.reservation_id)
            || execution_reservation.reservation_version == 0
            || !bounded_identity(&execution_reservation.binding_digest)
            || !bounded_identity(&execution_reservation.policy_id)
            || execution_reservation.policy_revision == 0
            || !bounded_identity(&execution_reservation.policy_digest)
        {
            return Err(a2a::A2AError::internal(
                "invalid durable execution reservation",
            ));
        }
        let budget = execution_reservation.budget;
        Self::new(
            scope,
            correlation,
            request,
            transport_payload_digest.into(),
            authorized_request_digest.into(),
            DurableExecutionReservation::Production(execution_reservation),
            budget,
        )
    }

    pub(crate) fn loopback_development(
        scope: DurableRuntimeScope,
        correlation: DurableDispatchCorrelation,
        request: MeshRequest,
        transport_payload_digest: impl Into<String>,
        authorized_request_digest: impl Into<String>,
        budget: ExecutionBudget,
    ) -> Result<Self, a2a::A2AError> {
        Self::new(
            scope,
            correlation,
            request,
            transport_payload_digest.into(),
            authorized_request_digest.into(),
            DurableExecutionReservation::LoopbackDevelopment,
            budget,
        )
    }

    #[allow(dead_code)]
    fn new(
        scope: DurableRuntimeScope,
        correlation: DurableDispatchCorrelation,
        request: MeshRequest,
        transport_payload_digest: String,
        authorized_request_digest: String,
        execution_reservation: DurableExecutionReservation,
        budget: ExecutionBudget,
    ) -> Result<Self, a2a::A2AError> {
        let request_digest = content_digest(
            &serde_json::to_vec(&request)
                .map_err(|_| a2a::A2AError::internal("invalid durable runtime request"))?,
        );
        if correlation.tenant_scope != scope.tenant_scope
            || transport_payload_digest != request_digest
            || !bounded_identity(&transport_payload_digest)
            || !bounded_identity(&authorized_request_digest)
        {
            return Err(a2a::A2AError::internal(
                "invalid durable runtime authority context",
            ));
        }
        Ok(Self {
            scope,
            correlation,
            request,
            transport_payload_digest,
            authorized_request_digest,
            execution_reservation,
            budget,
        })
    }

    #[must_use]
    pub const fn scope(&self) -> &DurableRuntimeScope {
        &self.scope
    }

    #[must_use]
    pub const fn correlation(&self) -> &DurableDispatchCorrelation {
        &self.correlation
    }

    #[must_use]
    pub const fn request(&self) -> &MeshRequest {
        &self.request
    }

    #[must_use]
    pub fn transport_payload_digest(&self) -> &str {
        &self.transport_payload_digest
    }

    #[must_use]
    pub fn authorized_request_digest(&self) -> &str {
        &self.authorized_request_digest
    }

    #[must_use]
    pub const fn budget(&self) -> ExecutionBudget {
        self.budget
    }

    #[must_use]
    pub const fn production_reservation(&self) -> Option<&ExecutionReservation> {
        match &self.execution_reservation {
            DurableExecutionReservation::Production(reservation) => Some(reservation),
            DurableExecutionReservation::LoopbackDevelopment => None,
        }
    }

    #[must_use]
    pub const fn is_loopback_development(&self) -> bool {
        matches!(
            self.execution_reservation,
            DurableExecutionReservation::LoopbackDevelopment
        )
    }
}

/// Immutable, server-authored work admitted to a durable runtime adapter.
///
/// Durable lease tokens and authority capabilities are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableWorkEnvelope {
    scope: DurableRuntimeScope,
    correlation: DurableDispatchCorrelation,
    request: MeshRequest,
    /// Digest of the exact stored outbox payload bytes.
    transport_payload_digest: String,
    /// Digest of the canonical authorized A2A request/idempotency domain.
    /// This is not the ADR-0003 text-concordance workload digest owned by #95.
    authorized_request_digest: String,
    execution_reservation: DurableExecutionReservation,
    budget: ExecutionBudget,
}

impl DurableWorkEnvelope {
    // Constructed by the durable driver once authority wiring lands in the next slice.
    #[allow(dead_code)]
    pub(crate) fn new(authority: DurableRuntimeAuthorityContext) -> Self {
        Self {
            scope: authority.scope,
            correlation: authority.correlation,
            request: authority.request,
            transport_payload_digest: authority.transport_payload_digest,
            authorized_request_digest: authority.authorized_request_digest,
            execution_reservation: authority.execution_reservation,
            budget: authority.budget,
        }
    }

    #[must_use]
    pub const fn scope(&self) -> &DurableRuntimeScope {
        &self.scope
    }

    #[must_use]
    pub const fn correlation(&self) -> &DurableDispatchCorrelation {
        &self.correlation
    }

    #[must_use]
    pub const fn request(&self) -> &MeshRequest {
        &self.request
    }

    #[must_use]
    pub fn transport_payload_digest(&self) -> &str {
        &self.transport_payload_digest
    }

    #[must_use]
    pub fn authorized_request_digest(&self) -> &str {
        &self.authorized_request_digest
    }

    #[must_use]
    pub const fn execution_reservation(&self) -> Option<&ExecutionReservation> {
        match &self.execution_reservation {
            DurableExecutionReservation::Production(reservation) => Some(reservation),
            DurableExecutionReservation::LoopbackDevelopment => None,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> ExecutionBudget {
        self.budget
    }
}

/// Closed, payload-free reasons established before runtime admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePreAdmissionFailure {
    Capacity,
    Unavailable,
    DuplicateCorrelation,
    Canceled,
    MissingExecutionReservation,
}

/// Result of reserving adapter capacity before durable receiver admission.
pub enum RuntimeAdapterPreparation {
    Rejected(RuntimePreAdmissionFailure),
    Retryable(RuntimePreAdmissionFailure),
    Ready(Box<dyn PreparedDurableRuntimeDispatch>),
}

impl std::fmt::Debug for RuntimeAdapterPreparation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(reason) => formatter.debug_tuple("Rejected").field(reason).finish(),
            Self::Retryable(reason) => formatter.debug_tuple("Retryable").field(reason).finish(),
            Self::Ready(_) => formatter.write_str("Ready(<reserved runtime capacity>)"),
        }
    }
}

/// Payload-free class of a locally observed execution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeExecutionFailure {
    Budget,
    Ingress,
    Processor,
}

/// Untrusted terminal proposal observed after runtime admission.
///
/// The production coordinator cannot publish this proposal in issue #94. Unknown
/// outcomes never carry runtime payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeAdapterOutcome {
    Terminal(DurableReceiverResult),
    ExecutionFailed(RuntimeExecutionFailure),
    ConfirmedStopped,
    AdmittedUnknown,
}

/// Owned admitted execution. Dropped completion channels fail closed as unknown.
#[must_use = "finish the admitted execution so unknown outcomes are contained"]
pub struct RuntimeAdapterExecution {
    outcome: oneshot::Receiver<RuntimeAdapterOutcome>,
}

impl RuntimeAdapterExecution {
    /// Observe an adapter-owned outcome channel without granting durable authority.
    /// Terminal outcomes remain proposals; dropping the sender reports unknown.
    pub fn new(outcome: oneshot::Receiver<RuntimeAdapterOutcome>) -> Self {
        Self { outcome }
    }

    pub async fn finish(self) -> RuntimeAdapterOutcome {
        self.outcome
            .await
            .unwrap_or(RuntimeAdapterOutcome::AdmittedUnknown)
    }
}

/// Admission acknowledgement after a prepared dispatch is handed to the worker.
pub enum RuntimeAdapterAdmission {
    Rejected(RuntimePreAdmissionFailure),
    Retryable(RuntimePreAdmissionFailure),
    Admitted(RuntimeAdapterExecution),
}

/// Capacity reserved before the durable receiver is moved to processing.
#[async_trait]
pub trait PreparedDurableRuntimeDispatch: Send {
    async fn admit(
        self: Box<Self>,
        envelope: DurableWorkEnvelope,
        cancellation: CancellationToken,
    ) -> RuntimeAdapterAdmission;
}

/// Payload-free result of requesting cancellation for an admitted correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCancellationRequest {
    /// The request reached the worker; this does not confirm execution stopped.
    Requested,
    NotActive,
    Unknown,
}

/// Authority-free runtime adapter boundary.
#[async_trait]
pub trait DurableRuntimeAdapter: Send + Sync + 'static {
    async fn prepare(&self) -> RuntimeAdapterPreparation;

    async fn cancel_durable(
        &self,
        correlation: &DurableDispatchCorrelation,
    ) -> RuntimeCancellationRequest;
}

#[async_trait]
impl<T> DurableRuntimeAdapter for std::sync::Arc<T>
where
    T: DurableRuntimeAdapter + ?Sized,
{
    async fn prepare(&self) -> RuntimeAdapterPreparation {
        self.as_ref().prepare().await
    }

    async fn cancel_durable(
        &self,
        correlation: &DurableDispatchCorrelation,
    ) -> RuntimeCancellationRequest {
        self.as_ref().cancel_durable(correlation).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ChannelDispatcher, DurableAuthorizationDecisionProvenance, DurableDispatchCorrelation,
        DurableRuntimeAdapter, DurableRuntimeAuthorityContext, DurableRuntimeScope,
        DurableWorkEnvelope, ExecutionBudget, ExecutionReservation, MeshRequest, OwnedTaskScope,
        RuntimeAdapterAdmission, RuntimeAdapterOutcome, RuntimeAdapterPreparation,
        RuntimePreAdmissionFailure, content_digest,
    };
    use tokio_util::sync::CancellationToken;

    fn work_envelope(dispatch: &str) -> DurableWorkEnvelope {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation = DurableDispatchCorrelation::new(scope.clone(), dispatch, 2, 7).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            text: "work".to_owned(),
        };
        let transport_payload_digest = content_digest(&serde_json::to_vec(&request).unwrap());
        let authorized_request_digest = content_digest(b"authorized-request");
        let budget = ExecutionBudget::new(4096, 8).unwrap();
        let authority = DurableRuntimeAuthorityContext::loopback_development(
            scope,
            correlation,
            request,
            transport_payload_digest,
            authorized_request_digest,
            budget,
        )
        .unwrap();
        DurableWorkEnvelope::new(authority)
    }

    fn production_work_envelope(dispatch: &str) -> DurableWorkEnvelope {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation = DurableDispatchCorrelation::new(scope.clone(), dispatch, 2, 7).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            text: "work".to_owned(),
        };
        let transport = content_digest(&serde_json::to_vec(&request).unwrap());
        let authorized = content_digest(b"authorized-request");
        let budget = ExecutionBudget::new(4096, 8).unwrap();
        let reservation = ExecutionReservation {
            reservation_id: format!("reservation-{dispatch}"),
            reservation_version: 1,
            binding_digest: content_digest(dispatch.as_bytes()),
            policy_id: "quota-runtime".to_owned(),
            policy_revision: 1,
            policy_digest: content_digest(b"quota-runtime-v1"),
            budget,
        };
        let authority = DurableRuntimeAuthorityContext::production(
            scope,
            correlation,
            request,
            transport,
            authorized,
            reservation,
        )
        .unwrap();
        DurableWorkEnvelope::new(authority)
    }

    #[test]
    fn persisted_policy_generation_is_part_of_runtime_identity_binding() {
        let persisted = OwnedTaskScope::new_with_principal_and_authentication(
            "tenant-a",
            "account-a",
            "principal-a",
            crate::VisibilityScope::Own,
            "mutual-tls",
        )
        .unwrap();
        let first = DurableRuntimeScope::from_persisted_task_bindings(
            persisted.clone(),
            DurableAuthorizationDecisionProvenance::new(
                "authorization-policy",
                7,
                content_digest(b"authorization-policy-v7"),
            )
            .unwrap(),
        )
        .unwrap();
        let second = DurableRuntimeScope::from_persisted_task_bindings(
            persisted,
            DurableAuthorizationDecisionProvenance::new(
                "authorization-policy",
                8,
                content_digest(b"authorization-policy-v8"),
            )
            .unwrap(),
        )
        .unwrap();

        assert_ne!(first, second);
        assert_eq!(first.authorization_policy_revision(), 7);
        assert_eq!(second.authorization_policy_revision(), 8);
        assert_eq!(first.authentication_method(), "mutual-tls");
    }

    #[test]
    fn same_normalized_request_can_retain_distinct_authorized_request_digests() {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            text: "normalized work".to_owned(),
        };
        let reservation = ExecutionReservation {
            reservation_id: "reservation-a".to_owned(),
            reservation_version: 3,
            binding_digest: content_digest(b"binding-a"),
            policy_id: "quota-a".to_owned(),
            policy_revision: 4,
            policy_digest: content_digest(b"quota-a-v4"),
            budget: ExecutionBudget::new(4096, 8).unwrap(),
        };
        let transport = content_digest(&serde_json::to_vec(&request).unwrap());
        let first_authorized = content_digest(b"canonical-authorized-a2a-request-a");
        let second_authorized = content_digest(b"canonical-authorized-a2a-request-b");
        let first = DurableWorkEnvelope::new(
            DurableRuntimeAuthorityContext::production(
                scope.clone(),
                DurableDispatchCorrelation::new(scope.clone(), "dispatch-a", 1, 7).unwrap(),
                request.clone(),
                transport.clone(),
                first_authorized.clone(),
                reservation.clone(),
            )
            .unwrap(),
        );
        let second = DurableWorkEnvelope::new(
            DurableRuntimeAuthorityContext::production(
                scope.clone(),
                DurableDispatchCorrelation::new(scope, "dispatch-b", 1, 8).unwrap(),
                request,
                transport,
                second_authorized.clone(),
                reservation,
            )
            .unwrap(),
        );

        assert_eq!(first.request(), second.request());
        assert_eq!(first.authorized_request_digest(), first_authorized);
        assert_eq!(second.authorized_request_digest(), second_authorized);
        assert_ne!(
            first.authorized_request_digest(),
            second.authorized_request_digest()
        );
    }

    #[test]
    fn swapped_digest_domains_are_rejected_against_authority_context() {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            DurableDispatchCorrelation::new(scope.clone(), "dispatch-swap", 1, 9).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-swap".to_owned(),
            context_id: "context-swap".to_owned(),
            text: "work".to_owned(),
        };
        let transport = content_digest(&serde_json::to_vec(&request).unwrap());
        let authorized = content_digest(b"canonical-authorized-request");
        let reservation = ExecutionReservation {
            reservation_id: "reservation-swap".to_owned(),
            reservation_version: 1,
            binding_digest: content_digest(b"binding-swap"),
            policy_id: "quota-a".to_owned(),
            policy_revision: 4,
            policy_digest: content_digest(b"quota-a-v4"),
            budget: ExecutionBudget::new(4096, 8).unwrap(),
        };

        assert!(
            DurableRuntimeAuthorityContext::production(
                scope,
                correlation,
                request,
                authorized,
                transport,
                reservation,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn authority_request_substitution_is_rejected_before_worker_send() {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            DurableDispatchCorrelation::new(scope.clone(), "dispatch-request-binding", 1, 10)
                .unwrap();
        let authorized_request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-authorized".to_owned(),
            context_id: "context-authorized".to_owned(),
            text: "authorized work".to_owned(),
        };
        let substituted_request = MeshRequest {
            text: "substituted work".to_owned(),
            ..authorized_request.clone()
        };
        let transport = content_digest(&serde_json::to_vec(&authorized_request).unwrap());
        let authorized = content_digest(b"canonical-authorized-request");
        let reservation = ExecutionReservation {
            reservation_id: "reservation-request-binding".to_owned(),
            reservation_version: 1,
            binding_digest: content_digest(b"binding-request-binding"),
            policy_id: "quota-a".to_owned(),
            policy_revision: 4,
            policy_digest: content_digest(b"quota-a-v4"),
            budget: ExecutionBudget::new(4096, 8).unwrap(),
        };
        let authority = DurableRuntimeAuthorityContext::production(
            scope,
            correlation,
            substituted_request,
            transport,
            authorized,
            reservation,
        );
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node")
            .with_runtime_capacity(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
        let RuntimeAdapterPreparation::Ready(_permit) = dispatcher.prepare().await else {
            panic!("capacity must be reserved");
        };

        assert!(
            authority.is_err(),
            "a request not owned by the authority context must be rejected"
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn reservation_binding_policy_and_budget_mutations_are_rejected() {
        let envelope = production_work_envelope("dispatch-reservation-mutation");
        let reservation = envelope.execution_reservation().unwrap().clone();

        for mutated in [
            ExecutionReservation {
                binding_digest: content_digest(b"mutated-binding"),
                ..reservation.clone()
            },
            ExecutionReservation {
                policy_revision: reservation.policy_revision + 1,
                policy_digest: content_digest(b"mutated-policy"),
                ..reservation.clone()
            },
            ExecutionReservation {
                budget: ExecutionBudget::new(4095, 8).unwrap(),
                ..reservation.clone()
            },
        ] {
            assert_ne!(envelope.execution_reservation(), Some(&mutated));
        }
    }

    #[test]
    fn external_authority_constructor_rejects_invalid_reservation_structure() {
        let scope = OwnedTaskScope::new_with_principal_and_authentication(
            "tenant-a",
            "account-a",
            "principal-a",
            crate::VisibilityScope::Tenant,
            "mutual-tls",
        )
        .unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            text: "work".to_owned(),
        };
        let transport = content_digest(&serde_json::to_vec(&request).unwrap());
        let baseline = ExecutionReservation {
            reservation_id: "reservation-a".to_owned(),
            reservation_version: 1,
            binding_digest: content_digest(b"binding-a"),
            policy_id: "quota-a".to_owned(),
            policy_revision: 1,
            policy_digest: content_digest(b"quota-a-v1"),
            budget: ExecutionBudget::new(4096, 8).unwrap(),
        };
        let invalid = [
            ExecutionReservation {
                reservation_id: String::new(),
                ..baseline.clone()
            },
            ExecutionReservation {
                reservation_version: 0,
                ..baseline.clone()
            },
            ExecutionReservation {
                binding_digest: String::new(),
                ..baseline.clone()
            },
            ExecutionReservation {
                policy_id: String::new(),
                ..baseline.clone()
            },
            ExecutionReservation {
                policy_revision: 0,
                ..baseline.clone()
            },
            ExecutionReservation {
                policy_digest: String::new(),
                ..baseline
            },
        ];
        for reservation in invalid {
            assert!(
                DurableRuntimeAuthorityContext::from_persisted_authority(
                    scope.clone(),
                    "authz-a",
                    1,
                    content_digest(b"authz-a-v1"),
                    "dispatch-a",
                    1,
                    1,
                    request.clone(),
                    transport.clone(),
                    content_digest(b"authorized-a"),
                    reservation,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn server_authored_work_envelope_closes_authoritative_identity_and_budget() {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let correlation =
            DurableDispatchCorrelation::new(scope.clone(), "dispatch-a", 2, 7).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            text: "work".to_owned(),
        };
        let transport_payload_digest = content_digest(&serde_json::to_vec(&request).unwrap());
        let reservation = ExecutionReservation {
            reservation_id: "reservation-a".to_owned(),
            reservation_version: 3,
            binding_digest: content_digest(b"binding-a"),
            policy_id: "quota-a".to_owned(),
            policy_revision: 4,
            policy_digest: content_digest(b"quota-a-v4"),
            budget: ExecutionBudget::new(4096, 8).unwrap(),
        };
        let authorized_request_digest = content_digest(b"authorized-a2a-request");
        let authority = DurableRuntimeAuthorityContext::production(
            scope.clone(),
            correlation.clone(),
            request.clone(),
            transport_payload_digest.clone(),
            authorized_request_digest,
            reservation.clone(),
        )
        .unwrap();

        let envelope = DurableWorkEnvelope::new(authority);

        assert_eq!(envelope.scope(), &scope);
        assert_eq!(envelope.scope().authentication_method(), "trusted-local");
        assert_eq!(envelope.scope().visibility(), crate::VisibilityScope::Own);
        assert_eq!(envelope.correlation(), &correlation);
        assert_eq!(envelope.request(), &request);
        assert_eq!(
            envelope.transport_payload_digest(),
            transport_payload_digest
        );
        assert_eq!(envelope.execution_reservation(), Some(&reservation));
        assert_eq!(envelope.budget(), reservation.budget);
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(!encoded.contains("lease_token"));
        assert!(!encoded.contains("leaseToken"));
        assert!(!encoded.contains("authority"));
    }

    #[tokio::test]
    async fn channel_capacity_and_closure_are_typed_before_receiver_admission() {
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node")
            .with_runtime_capacity(std::sync::Arc::new(tokio::sync::Semaphore::new(2)));
        let held = dispatcher.prepare().await;
        assert!(matches!(held, RuntimeAdapterPreparation::Ready(_)));
        assert!(matches!(
            dispatcher.prepare().await,
            RuntimeAdapterPreparation::Retryable(RuntimePreAdmissionFailure::Capacity)
        ));
        drop(receiver);
        drop(held);
        assert!(matches!(
            dispatcher.prepare().await,
            RuntimeAdapterPreparation::Rejected(RuntimePreAdmissionFailure::Unavailable)
        ));
    }

    #[tokio::test]
    async fn bare_channel_dispatcher_cannot_prepare_durable_execution() {
        let (commands, _receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node");
        assert!(matches!(
            dispatcher.prepare().await,
            RuntimeAdapterPreparation::Rejected(RuntimePreAdmissionFailure::Unavailable)
        ));
    }

    #[tokio::test]
    async fn channel_adapter_rejects_loopback_envelope_before_worker_send() {
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node")
            .with_runtime_capacity(std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
            .with_timeout(std::time::Duration::from_millis(20));
        let RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity must be reserved");
        };

        assert!(matches!(
            permit
                .admit(
                    work_envelope("missing-reservation"),
                    CancellationToken::new()
                )
                .await,
            RuntimeAdapterAdmission::Rejected(
                RuntimePreAdmissionFailure::MissingExecutionReservation
            )
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn worker_capacity_after_prepare_is_retryable_proven_non_admission() {
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node")
            .with_runtime_capacity(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
        let RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity must be reserved");
        };
        let worker = tokio::spawn(async move {
            let crate::DispatchCommand::ExecuteDurable { admitted, .. } =
                receiver.recv().await.unwrap()
            else {
                panic!("expected durable command");
            };
            admitted
                .send(Err(RuntimePreAdmissionFailure::Capacity))
                .unwrap();
        });

        assert!(matches!(
            permit
                .admit(
                    production_work_envelope("worker-capacity"),
                    CancellationToken::new()
                )
                .await,
            RuntimeAdapterAdmission::Retryable(RuntimePreAdmissionFailure::Capacity)
        ));
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn reserved_channel_permit_reports_admission_then_terminal_outcome() {
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node")
            .with_runtime_capacity(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
        let RuntimeAdapterPreparation::Ready(permit) = dispatcher.prepare().await else {
            panic!("capacity must be reserved");
        };
        let envelope = production_work_envelope("dispatch-terminal");
        let expected = crate::DurableReceiverResult {
            events: vec![crate::MeshEvent::Progress("runtime progress".to_owned())],
            termination: crate::DurableReceiverTermination::Success,
        };
        let worker_expected = expected.clone();
        let worker_envelope = envelope.clone();
        let worker = tokio::spawn(async move {
            let crate::DispatchCommand::ExecuteDurable {
                envelope,
                admitted,
                outcome,
                ..
            } = receiver.recv().await.unwrap()
            else {
                panic!("expected durable runtime command");
            };
            assert_eq!(*envelope, worker_envelope);
            admitted.send(Ok(())).unwrap();
            outcome
                .send(RuntimeAdapterOutcome::Terminal(worker_expected))
                .unwrap();
        });

        let RuntimeAdapterAdmission::Admitted(execution) =
            permit.admit(envelope, CancellationToken::new()).await
        else {
            panic!("reserved command must be admitted");
        };
        assert_eq!(
            execution.finish().await,
            RuntimeAdapterOutcome::Terminal(expected)
        );
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_durable_cancellation_acknowledgement_is_unknown() {
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        let dispatcher = ChannelDispatcher::new(commands, "runtime-node")
            .with_timeout(std::time::Duration::from_millis(50));
        let envelope = work_envelope("dispatch-cancel-ack");
        let worker = tokio::spawn(async move {
            let crate::DispatchCommand::CancelDurable { ack, .. } = receiver.recv().await.unwrap()
            else {
                panic!("expected durable cancellation");
            };
            drop(ack);
        });
        assert_eq!(
            dispatcher.cancel_durable(envelope.correlation()).await,
            crate::RuntimeCancellationRequest::Unknown
        );
        worker.await.unwrap();
    }

    #[test]
    fn work_envelope_rejects_cross_scope_correlation_and_unreserved_budget_drift() {
        let scope = DurableRuntimeScope::new(
            "tenant-a",
            "account-a",
            "principal-a",
            "trusted-local",
            crate::VisibilityScope::Own,
        )
        .unwrap();
        let other = DurableRuntimeScope::new(
            "tenant-b",
            "account-a",
            "principal-a",
            "mutual-tls",
            crate::VisibilityScope::Tenant,
        )
        .unwrap();
        let correlation = DurableDispatchCorrelation::new(other, "dispatch-a", 1, 1).unwrap();
        let request = MeshRequest {
            protocol: "a2a-v1".to_owned(),
            task_id: "task-a".to_owned(),
            context_id: "context-a".to_owned(),
            text: "work".to_owned(),
        };
        let digest = content_digest(&serde_json::to_vec(&request).unwrap());
        assert!(
            DurableRuntimeAuthorityContext::loopback_development(
                scope,
                correlation,
                request,
                digest,
                content_digest(b"authorized-request"),
                ExecutionBudget::new(4096, 8).unwrap(),
            )
            .is_err()
        );
    }
}
