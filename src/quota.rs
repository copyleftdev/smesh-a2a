//! Server-owned distributed quota policy and closed accounting vocabulary.
#![allow(clippy::missing_errors_doc)]

use std::{collections::BTreeSet, io::Read as _, path::Path, sync::Arc};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{content_digest, durable_authority::valid_bounded_identity};

const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_RATE_CAP: u64 = 1_000_000;
const MAX_CONCURRENCY_CAP: u64 = 4_096;
const MAX_BYTE_CAP: u64 = 64 * 1024 * 1024;
const MAX_EVENT_CAP: u64 = 1_000_000;
const MAX_WINDOW_MILLIS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaOperation {
    TaskCreate,
    TaskContinue,
    TaskCancel,
    TaskGet,
    TaskList,
    SendStream,
    Subscribe,
    Reconnect,
    PublicEgress,
}

impl QuotaOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskCreate => "taskCreate",
            Self::TaskContinue => "taskContinue",
            Self::TaskCancel => "taskCancel",
            Self::TaskGet => "taskGet",
            Self::TaskList => "taskList",
            Self::SendStream => "sendStream",
            Self::Subscribe => "subscribe",
            Self::Reconnect => "reconnect",
            Self::PublicEgress => "publicEgress",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaDimension {
    RequestCount,
    ConcurrentActiveWork,
    InputBytes,
    OutputBytes,
    EventCount,
    ConcurrentStreams,
    ConcurrentSubscriptions,
    ReconnectCount,
    RetainedAuthorityBytes,
}

impl QuotaDimension {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestCount => "requestCount",
            Self::ConcurrentActiveWork => "concurrentActiveWork",
            Self::InputBytes => "inputBytes",
            Self::OutputBytes => "outputBytes",
            Self::EventCount => "eventCount",
            Self::ConcurrentStreams => "concurrentStreams",
            Self::ConcurrentSubscriptions => "concurrentSubscriptions",
            Self::ReconnectCount => "reconnectCount",
            Self::RetainedAuthorityBytes => "retainedAuthorityBytes",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaScopeKind {
    Tenant,
    Account,
    Principal,
}

impl QuotaScopeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Account => "account",
            Self::Principal => "principal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaAlgorithm {
    FixedWindow,
    TokenBucket,
    Gauge,
}

impl QuotaAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FixedWindow => "fixedWindow",
            Self::TokenBucket => "tokenBucket",
            Self::Gauge => "gauge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QuotaLeaseKind {
    MessageStream,
    TaskSubscription,
}

impl QuotaLeaseKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MessageStream => "messageStream",
            Self::TaskSubscription => "taskSubscription",
        }
    }

    #[must_use]
    pub const fn dimension(self) -> QuotaDimension {
        match self {
            Self::MessageStream => QuotaDimension::ConcurrentStreams,
            Self::TaskSubscription => QuotaDimension::ConcurrentSubscriptions,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum QuotaPolicyError {
    #[error("quota policy is invalid")]
    Invalid,
    #[error("quota policy is unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyDocument {
    schema_version: String,
    policy_id: String,
    revision: u64,
    request_window_millis: u64,
    reconnect_window_millis: u64,
    limits: Limits,
    overrides: Vec<OverrideDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Limits {
    request_count: LimitPair,
    concurrent_active_work: LimitPair,
    input_bytes: LimitPair,
    output_bytes: LimitPair,
    event_count: LimitPair,
    concurrent_streams: LimitPair,
    concurrent_subscriptions: LimitPair,
    reconnect_count: LimitPair,
    retained_authority_bytes: LimitPair,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LimitPair {
    tenant: u64,
    account: u64,
    principal: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OverrideDocument {
    pub(crate) override_id: String,
    pub(crate) actor: String,
    pub(crate) reason: String,
    pub(crate) scope_kind: QuotaScopeKind,
    pub(crate) scope_id: String,
    pub(crate) operation: QuotaOperation,
    pub(crate) dimension: QuotaDimension,
    pub(crate) old_limit: u64,
    pub(crate) new_limit: u64,
    pub(crate) effective_at: i64,
    pub(crate) expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct QuotaPolicy {
    document: Arc<PolicyDocument>,
    canonical_json: Arc<str>,
    digest: Arc<str>,
}

/// One exact tenant/scope/dimension authorized for a non-destructive policy drain.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct QuotaReconciliationTarget {
    pub(crate) tenant_scope: Arc<str>,
    pub(crate) scope_kind: QuotaScopeKind,
    pub(crate) dimension: QuotaDimension,
}

impl QuotaReconciliationTarget {
    pub fn new(
        tenant_scope: impl Into<String>,
        scope_kind: QuotaScopeKind,
        dimension: QuotaDimension,
    ) -> Result<Self, QuotaPolicyError> {
        let tenant_scope = tenant_scope.into();
        if !valid_bounded_identity(&tenant_scope) {
            return Err(QuotaPolicyError::Invalid);
        }
        Ok(Self {
            tenant_scope: tenant_scope.into(),
            scope_kind,
            dimension,
        })
    }
}

/// Audited server/operator input for a lower-limit policy revision.
/// The only supported action is drain; destructive eviction is not representable.
#[derive(Clone, Debug)]
pub struct QuotaReconciliationPlan {
    pub(crate) old_policy_digest: Arc<str>,
    pub(crate) new_policy_digest: Arc<str>,
    pub(crate) actor: Arc<str>,
    pub(crate) reason: Arc<str>,
    pub(crate) effective_at: i64,
    pub(crate) targets: Arc<[QuotaReconciliationTarget]>,
}

impl QuotaReconciliationPlan {
    pub fn drain(
        old_policy_digest: impl Into<String>,
        new_policy_digest: impl Into<String>,
        actor: impl Into<String>,
        reason: impl Into<String>,
        effective_at: i64,
        mut targets: Vec<QuotaReconciliationTarget>,
    ) -> Result<Self, QuotaPolicyError> {
        let old_policy_digest = old_policy_digest.into();
        let new_policy_digest = new_policy_digest.into();
        let actor = actor.into();
        let reason = reason.into();
        targets.sort();
        if old_policy_digest.len() != 71
            || new_policy_digest.len() != 71
            || old_policy_digest == new_policy_digest
            || !valid_id(&actor, 256)
            || reason.is_empty()
            || reason.len() > 1024
            || !reason.is_ascii()
            || effective_at < 1
            || targets.is_empty()
            || targets.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(QuotaPolicyError::Invalid);
        }
        Ok(Self {
            old_policy_digest: old_policy_digest.into(),
            new_policy_digest: new_policy_digest.into(),
            actor: actor.into(),
            reason: reason.into(),
            effective_at,
            targets: targets.into(),
        })
    }

    #[must_use]
    pub fn authorizes(
        &self,
        tenant_scope: &str,
        old_policy_digest: &str,
        new_policy_digest: &str,
        scope_kind: QuotaScopeKind,
        dimension: QuotaDimension,
    ) -> bool {
        self.old_policy_digest.as_ref() == old_policy_digest
            && self.new_policy_digest.as_ref() == new_policy_digest
            && self.targets.iter().any(|target| {
                target.tenant_scope.as_ref() == tenant_scope
                    && target.scope_kind == scope_kind
                    && target.dimension == dimension
            })
    }
}

/// Trusted server-resolved quota subject. It is never deserialized from transport data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaSubject {
    tenant_scope: Arc<str>,
    account_id: Arc<str>,
    principal_scope: Arc<str>,
}

impl QuotaSubject {
    pub fn new(
        tenant_scope: impl Into<String>,
        account_id: impl Into<String>,
        principal_scope: impl Into<String>,
    ) -> Result<Self, QuotaPolicyError> {
        let tenant_scope = tenant_scope.into();
        let account_id = account_id.into();
        let principal_scope = principal_scope.into();
        if !valid_bounded_identity(&tenant_scope)
            || !valid_bounded_identity(&account_id)
            || principal_scope.is_empty()
            || principal_scope.len() > 256
            || !principal_scope.is_ascii()
        {
            return Err(QuotaPolicyError::Invalid);
        }
        Ok(Self {
            tenant_scope: tenant_scope.into(),
            account_id: account_id.into(),
            principal_scope: principal_scope.into(),
        })
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaCharge {
    pub(crate) scope_kind: QuotaScopeKind,
    pub(crate) scope_id: Arc<str>,
    pub(crate) dimension: QuotaDimension,
    pub(crate) algorithm: QuotaAlgorithm,
    pub(crate) units: u64,
    pub(crate) capacity: u64,
    pub(crate) window_millis: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaIntent {
    pub(crate) policy_id: Arc<str>,
    pub(crate) policy_revision: u64,
    pub(crate) policy_digest: Arc<str>,
    pub(crate) tenant_scope: Arc<str>,
    pub(crate) account_id: Arc<str>,
    pub(crate) principal_scope: Arc<str>,
    pub(crate) operation: QuotaOperation,
    pub(crate) semantic_id: Arc<str>,
    pub(crate) binding_digest: Arc<str>,
    pub(crate) charges: Arc<[QuotaCharge]>,
}

/// Immutable private ceiling attached to one durable execution dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutionBudget {
    max_output_bytes: u64,
    max_event_count: u64,
}

impl ExecutionBudget {
    pub fn new(max_output_bytes: u64, max_event_count: u64) -> Result<Self, QuotaPolicyError> {
        if max_output_bytes == 0
            || max_output_bytes > MAX_BYTE_CAP
            || max_event_count == 0
            || max_event_count > MAX_EVENT_CAP
        {
            return Err(QuotaPolicyError::Invalid);
        }
        Ok(Self {
            max_output_bytes,
            max_event_count,
        })
    }

    #[must_use]
    pub const fn max_output_bytes(self) -> u64 {
        self.max_output_bytes
    }

    #[must_use]
    pub const fn max_event_count(self) -> u64 {
        self.max_event_count
    }
}

impl QuotaIntent {
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
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    #[must_use]
    pub fn principal_scope(&self) -> &str {
        &self.principal_scope
    }
    #[must_use]
    pub const fn operation(&self) -> QuotaOperation {
        self.operation
    }
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
    #[must_use]
    pub fn charges(&self) -> &[QuotaCharge] {
        &self.charges
    }

    /// Resolve the strictest tenant/account/principal execution ceiling carried by this intent.
    #[must_use]
    pub fn execution_budget(&self) -> Option<ExecutionBudget> {
        if !matches!(
            self.operation,
            QuotaOperation::TaskCreate | QuotaOperation::TaskContinue | QuotaOperation::SendStream
        ) {
            return None;
        }
        let minimum = |dimension| {
            let values = self
                .charges
                .iter()
                .filter(|charge| charge.dimension == dimension);
            (values.clone().count() == 3)
                .then(|| values.map(|charge| charge.units).min())
                .flatten()
        };
        ExecutionBudget::new(
            minimum(QuotaDimension::OutputBytes)?,
            minimum(QuotaDimension::EventCount)?,
        )
        .ok()
    }
}

impl QuotaCharge {
    #[must_use]
    pub const fn scope_kind(&self) -> QuotaScopeKind {
        self.scope_kind
    }

    #[must_use]
    pub const fn dimension(&self) -> QuotaDimension {
        self.dimension
    }

    #[must_use]
    pub const fn units(&self) -> u64 {
        self.units
    }
}

impl QuotaPolicy {
    /// Parse a complete strict policy. Unknown, duplicate, fractional, zero,
    /// overflowing, or hard-cap-exceeding values are rejected at startup.
    pub fn from_json(bytes: &[u8]) -> Result<Self, QuotaPolicyError> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(QuotaPolicyError::Invalid);
        }
        let document: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|_| QuotaPolicyError::Invalid)?;
        if document.schema_version != "smesh-quota-policy/v1"
            || !valid_id(&document.policy_id, 128)
            || document.revision == 0
            || !(1..=MAX_WINDOW_MILLIS).contains(&document.request_window_millis)
            || !(1..=MAX_WINDOW_MILLIS).contains(&document.reconnect_window_millis)
        {
            return Err(QuotaPolicyError::Invalid);
        }
        validate_pair(document.limits.request_count, MAX_RATE_CAP)?;
        validate_pair(document.limits.concurrent_active_work, MAX_CONCURRENCY_CAP)?;
        validate_pair(document.limits.input_bytes, MAX_BYTE_CAP)?;
        validate_pair(document.limits.output_bytes, MAX_BYTE_CAP)?;
        validate_pair(document.limits.event_count, MAX_EVENT_CAP)?;
        validate_pair(document.limits.concurrent_streams, MAX_CONCURRENCY_CAP)?;
        validate_pair(
            document.limits.concurrent_subscriptions,
            MAX_CONCURRENCY_CAP,
        )?;
        validate_pair(document.limits.reconnect_count, MAX_RATE_CAP)?;
        validate_pair(document.limits.retained_authority_bytes, MAX_BYTE_CAP)?;
        if document.overrides.len() > 1024 {
            return Err(QuotaPolicyError::Invalid);
        }
        let mut ids = BTreeSet::new();
        for value in &document.overrides {
            let cap = dimension_cap(value.dimension);
            let baseline = limit_from_document(&document, value.dimension, value.scope_kind);
            if !valid_id(&value.override_id, 128)
                || !valid_visible_ascii(&value.actor, 256)
                || !valid_visible_ascii(&value.reason, 1024)
                || !valid_id(&value.scope_id, 256)
                || value.old_limit == 0
                || value.new_limit == 0
                || value.old_limit > cap
                || value.new_limit > cap
                || value.old_limit != baseline
                || value.effective_at < 1
                || value.expires_at <= value.effective_at
                || !ids.insert(value.override_id.as_str())
            {
                return Err(QuotaPolicyError::Invalid);
            }
        }
        for (index, left) in document.overrides.iter().enumerate() {
            if document.overrides[index + 1..].iter().any(|right| {
                left.scope_kind == right.scope_kind
                    && left.scope_id == right.scope_id
                    && left.operation == right.operation
                    && left.dimension == right.dimension
                    && left.effective_at < right.expires_at
                    && right.effective_at < left.expires_at
            }) {
                return Err(QuotaPolicyError::Invalid);
            }
        }
        let canonical_json =
            serde_json::to_string(&document).map_err(|_| QuotaPolicyError::Invalid)?;
        let digest = content_digest(canonical_json.as_bytes());
        Ok(Self {
            document: Arc::new(document),
            canonical_json: canonical_json.into(),
            digest: digest.into(),
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, QuotaPolicyError> {
        #[cfg(unix)]
        let file = std::fs::File::from(
            rustix::fs::open(
                path.as_ref(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| QuotaPolicyError::Unavailable)?,
        );
        #[cfg(not(unix))]
        let mut file =
            std::fs::File::open(path.as_ref()).map_err(|_| QuotaPolicyError::Unavailable)?;
        let metadata = file.metadata().map_err(|_| QuotaPolicyError::Unavailable)?;
        if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES as u64 {
            return Err(QuotaPolicyError::Invalid);
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| QuotaPolicyError::Invalid)?,
        );
        file.take((MAX_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| QuotaPolicyError::Unavailable)?;
        Self::from_json(&bytes)
    }

    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.document.policy_id
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.document.revision
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn canonical_json(&self) -> &str {
        &self.canonical_json
    }

    /// Return every typed scope/dimension whose baseline is lower than `old`.
    #[must_use]
    pub fn lowered_limits_from(&self, old: &Self) -> Vec<(QuotaScopeKind, QuotaDimension)> {
        const DIMENSIONS: [QuotaDimension; 9] = [
            QuotaDimension::RequestCount,
            QuotaDimension::ConcurrentActiveWork,
            QuotaDimension::InputBytes,
            QuotaDimension::OutputBytes,
            QuotaDimension::EventCount,
            QuotaDimension::ConcurrentStreams,
            QuotaDimension::ConcurrentSubscriptions,
            QuotaDimension::ReconnectCount,
            QuotaDimension::RetainedAuthorityBytes,
        ];
        let mut lowered = Vec::new();
        for scope in [
            QuotaScopeKind::Tenant,
            QuotaScopeKind::Account,
            QuotaScopeKind::Principal,
        ] {
            for dimension in DIMENSIONS {
                if self.limit(dimension, scope) < old.limit(dimension, scope) {
                    lowered.push((scope, dimension));
                }
            }
        }
        lowered
    }

    pub(crate) fn overrides(&self) -> &[OverrideDocument] {
        &self.document.overrides
    }

    /// Resolve one named static operator override at authoritative database time.
    /// Overrides never wildcard and never affect a different scope, operation, or dimension.
    #[must_use]
    pub fn limit_at(
        &self,
        scope_kind: QuotaScopeKind,
        scope_id: &str,
        operation: QuotaOperation,
        dimension: QuotaDimension,
        database_millis: i64,
    ) -> u64 {
        let baseline = self.limit(dimension, scope_kind);
        self.document
            .overrides
            .iter()
            .find(|value| {
                value.scope_kind == scope_kind
                    && value.scope_id == scope_id
                    && value.operation == operation
                    && value.dimension == dimension
                    && value.old_limit == baseline
                    && value.effective_at <= database_millis
                    && database_millis < value.expires_at
            })
            .map_or(baseline, |value| value.new_limit)
    }

    /// Build a bounded multi-dimensional server-owned admission intent.
    pub fn admission_intent(
        &self,
        subject: &QuotaSubject,
        semantic_id: &str,
        input_bytes: u64,
        streaming: bool,
    ) -> Result<QuotaIntent, QuotaPolicyError> {
        self.operation_intent(
            subject,
            if streaming {
                QuotaOperation::SendStream
            } else {
                QuotaOperation::TaskCreate
            },
            semantic_id,
            input_bytes,
        )
    }

    /// Build a server-owned intent for one concrete live operation.
    /// Continuations retain the task's active-work allocation and do not
    /// allocate another active-work unit.
    pub fn operation_intent(
        &self,
        subject: &QuotaSubject,
        operation: QuotaOperation,
        semantic_id: &str,
        input_bytes: u64,
    ) -> Result<QuotaIntent, QuotaPolicyError> {
        if !valid_id(semantic_id, 256) || input_bytes > MAX_BYTE_CAP {
            return Err(QuotaPolicyError::Invalid);
        }
        let execution_output_budget = self.execution_limit(QuotaDimension::OutputBytes);
        let execution_event_budget = self.execution_limit(QuotaDimension::EventCount);
        let mut charges = Vec::with_capacity(9);
        for (scope_kind, scope_id) in [
            (QuotaScopeKind::Tenant, subject.tenant_scope()),
            (QuotaScopeKind::Account, subject.account_id()),
            (QuotaScopeKind::Principal, subject.principal_scope()),
        ] {
            let mut operation_charges = vec![(
                QuotaDimension::RequestCount,
                QuotaAlgorithm::FixedWindow,
                1,
                self.window_millis(QuotaDimension::RequestCount),
            )];
            if matches!(
                operation,
                QuotaOperation::TaskCreate | QuotaOperation::SendStream
            ) {
                operation_charges.push((
                    QuotaDimension::ConcurrentActiveWork,
                    QuotaAlgorithm::Gauge,
                    1,
                    None,
                ));
            }
            if input_bytes != 0 {
                operation_charges.push((
                    QuotaDimension::InputBytes,
                    QuotaAlgorithm::FixedWindow,
                    input_bytes,
                    self.window_millis(QuotaDimension::RequestCount),
                ));
            }
            if matches!(
                operation,
                QuotaOperation::TaskCreate
                    | QuotaOperation::TaskContinue
                    | QuotaOperation::SendStream
            ) {
                operation_charges.push((
                    QuotaDimension::OutputBytes,
                    QuotaAlgorithm::FixedWindow,
                    execution_output_budget,
                    self.window_millis(QuotaDimension::RequestCount),
                ));
                operation_charges.push((
                    QuotaDimension::EventCount,
                    QuotaAlgorithm::FixedWindow,
                    execution_event_budget,
                    self.window_millis(QuotaDimension::RequestCount),
                ));
            }
            for (dimension, algorithm, units, window_millis) in operation_charges {
                charges.push(QuotaCharge {
                    scope_kind,
                    scope_id: Arc::from(scope_id),
                    dimension,
                    algorithm,
                    units,
                    capacity: self.limit(dimension, scope_kind),
                    window_millis,
                });
            }
        }
        charges.sort_by(|a, b| {
            (a.scope_kind, a.scope_id.as_ref(), a.dimension).cmp(&(
                b.scope_kind,
                b.scope_id.as_ref(),
                b.dimension,
            ))
        });
        let binding_digest = content_digest(
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                self.digest(),
                subject.tenant_scope(),
                subject.account_id(),
                subject.principal_scope(),
                operation.as_str(),
                semantic_id
            )
            .as_bytes(),
        );
        Ok(QuotaIntent {
            policy_id: Arc::from(self.policy_id()),
            policy_revision: self.revision(),
            policy_digest: Arc::from(self.digest()),
            tenant_scope: Arc::from(subject.tenant_scope()),
            account_id: Arc::from(subject.account_id()),
            principal_scope: Arc::from(subject.principal_scope()),
            operation,
            semantic_id: Arc::from(semantic_id),
            binding_digest: binding_digest.into(),
            charges: charges.into(),
        })
    }

    /// Build a one-frame/public-response egress charge from canonical serialized bytes.
    pub fn egress_intent(
        &self,
        subject: &QuotaSubject,
        semantic_id: &str,
        output_bytes: u64,
        event_count: u64,
    ) -> Result<QuotaIntent, QuotaPolicyError> {
        if !valid_id(semantic_id, 256)
            || output_bytes == 0
            || output_bytes > MAX_BYTE_CAP
            || event_count == 0
            || event_count > MAX_EVENT_CAP
        {
            return Err(QuotaPolicyError::Invalid);
        }
        let mut charges = Vec::with_capacity(6);
        for (scope_kind, scope_id) in [
            (QuotaScopeKind::Tenant, subject.tenant_scope()),
            (QuotaScopeKind::Account, subject.account_id()),
            (QuotaScopeKind::Principal, subject.principal_scope()),
        ] {
            for (dimension, units) in [
                (QuotaDimension::OutputBytes, output_bytes),
                (QuotaDimension::EventCount, event_count),
            ] {
                charges.push(QuotaCharge {
                    scope_kind,
                    scope_id: Arc::from(scope_id),
                    dimension,
                    algorithm: QuotaAlgorithm::FixedWindow,
                    units,
                    capacity: self.limit(dimension, scope_kind),
                    window_millis: self.window_millis(QuotaDimension::RequestCount),
                });
            }
        }
        charges.sort_by(|a, b| {
            (a.scope_kind, a.scope_id.as_ref(), a.dimension).cmp(&(
                b.scope_kind,
                b.scope_id.as_ref(),
                b.dimension,
            ))
        });
        let binding_digest = content_digest(
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}",
                self.digest(),
                subject.tenant_scope(),
                subject.account_id(),
                subject.principal_scope(),
                QuotaOperation::PublicEgress.as_str(),
                semantic_id
            )
            .as_bytes(),
        );
        Ok(QuotaIntent {
            policy_id: Arc::from(self.policy_id()),
            policy_revision: self.revision(),
            policy_digest: Arc::from(self.digest()),
            tenant_scope: Arc::from(subject.tenant_scope()),
            account_id: Arc::from(subject.account_id()),
            principal_scope: Arc::from(subject.principal_scope()),
            operation: QuotaOperation::PublicEgress,
            semantic_id: Arc::from(semantic_id),
            binding_digest: binding_digest.into(),
            charges: charges.into(),
        })
    }

    /// Build server-owned accounting for a durable stream/subscription lease.
    pub fn lease_intent(
        &self,
        subject: &QuotaSubject,
        kind: QuotaLeaseKind,
        semantic_id: &str,
        reconnect: bool,
    ) -> Result<QuotaIntent, QuotaPolicyError> {
        if !valid_id(semantic_id, 256) {
            return Err(QuotaPolicyError::Invalid);
        }
        let operation = if reconnect {
            QuotaOperation::Reconnect
        } else {
            match kind {
                QuotaLeaseKind::MessageStream => QuotaOperation::SendStream,
                QuotaLeaseKind::TaskSubscription => QuotaOperation::Subscribe,
            }
        };
        let mut charges = Vec::with_capacity(9);
        for (scope_kind, scope_id) in [
            (QuotaScopeKind::Tenant, subject.tenant_scope()),
            (QuotaScopeKind::Account, subject.account_id()),
            (QuotaScopeKind::Principal, subject.principal_scope()),
        ] {
            if reconnect {
                charges.push(QuotaCharge {
                    scope_kind,
                    scope_id: Arc::from(scope_id),
                    dimension: QuotaDimension::ReconnectCount,
                    algorithm: QuotaAlgorithm::TokenBucket,
                    units: 1,
                    capacity: self.limit(QuotaDimension::ReconnectCount, scope_kind),
                    window_millis: self.window_millis(QuotaDimension::ReconnectCount),
                });
            }
            charges.push(QuotaCharge {
                scope_kind,
                scope_id: Arc::from(scope_id),
                dimension: kind.dimension(),
                algorithm: QuotaAlgorithm::Gauge,
                units: 1,
                capacity: self.limit(kind.dimension(), scope_kind),
                window_millis: None,
            });
        }
        charges.sort_by(|a, b| {
            (a.scope_kind, a.scope_id.as_ref(), a.dimension).cmp(&(
                b.scope_kind,
                b.scope_id.as_ref(),
                b.dimension,
            ))
        });
        let binding_digest = content_digest(
            format!(
                "{}\0{}\0{}\0{}\0{}\0{}\0{}",
                self.digest(),
                subject.tenant_scope(),
                subject.account_id(),
                subject.principal_scope(),
                operation.as_str(),
                kind.as_str(),
                semantic_id
            )
            .as_bytes(),
        );
        Ok(QuotaIntent {
            policy_id: Arc::from(self.policy_id()),
            policy_revision: self.revision(),
            policy_digest: Arc::from(self.digest()),
            tenant_scope: Arc::from(subject.tenant_scope()),
            account_id: Arc::from(subject.account_id()),
            principal_scope: Arc::from(subject.principal_scope()),
            operation,
            semantic_id: Arc::from(semantic_id),
            binding_digest: binding_digest.into(),
            charges: charges.into(),
        })
    }

    #[must_use]
    fn execution_limit(&self, dimension: QuotaDimension) -> u64 {
        self.limit(dimension, QuotaScopeKind::Tenant)
            .min(self.limit(dimension, QuotaScopeKind::Account))
            .min(self.limit(dimension, QuotaScopeKind::Principal))
    }

    #[must_use]
    pub(crate) fn limit(&self, dimension: QuotaDimension, scope: QuotaScopeKind) -> u64 {
        let pair = match dimension {
            QuotaDimension::RequestCount => self.document.limits.request_count,
            QuotaDimension::ConcurrentActiveWork => self.document.limits.concurrent_active_work,
            QuotaDimension::InputBytes => self.document.limits.input_bytes,
            QuotaDimension::OutputBytes => self.document.limits.output_bytes,
            QuotaDimension::EventCount => self.document.limits.event_count,
            QuotaDimension::ConcurrentStreams => self.document.limits.concurrent_streams,
            QuotaDimension::ConcurrentSubscriptions => {
                self.document.limits.concurrent_subscriptions
            }
            QuotaDimension::ReconnectCount => self.document.limits.reconnect_count,
            QuotaDimension::RetainedAuthorityBytes => self.document.limits.retained_authority_bytes,
        };
        match scope {
            QuotaScopeKind::Tenant => pair.tenant,
            QuotaScopeKind::Account => pair.account,
            QuotaScopeKind::Principal => pair.principal,
        }
    }

    #[must_use]
    pub(crate) fn window_millis(&self, dimension: QuotaDimension) -> Option<u64> {
        match dimension {
            QuotaDimension::RequestCount => Some(self.document.request_window_millis),
            QuotaDimension::ReconnectCount => Some(self.document.reconnect_window_millis),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaExceeded {
    retry_after_seconds: u16,
}

impl QuotaExceeded {
    #[must_use]
    pub fn new(retry_after_seconds: u64) -> Self {
        Self {
            retry_after_seconds: u16::try_from(retry_after_seconds.clamp(1, 3_600))
                .unwrap_or(3_600),
        }
    }

    #[must_use]
    pub const fn retry_after_seconds(self) -> u16 {
        self.retry_after_seconds
    }

    #[must_use]
    pub fn into_a2a_error(self) -> a2a::A2AError {
        let detail = a2a::TypedDetail::from_struct(std::collections::HashMap::from([(
            "retryAfterSeconds".to_owned(),
            serde_json::Value::from(self.retry_after_seconds),
        )]));
        a2a::A2AError::new(-32_010, "quota exceeded").with_details(vec![detail])
    }
}

pub fn quota_exceeded() -> a2a::A2AError {
    QuotaExceeded::new(1).into_a2a_error()
}

pub fn quota_authority_unavailable() -> a2a::A2AError {
    a2a::A2AError::new(-32_011, "quota authority unavailable")
}

fn validate_pair(pair: LimitPair, cap: u64) -> Result<(), QuotaPolicyError> {
    if pair.tenant == 0
        || pair.account == 0
        || pair.principal == 0
        || pair.tenant > cap
        || pair.account > cap
        || pair.principal > cap
        || pair.account > pair.tenant
        || pair.principal > pair.account
    {
        return Err(QuotaPolicyError::Invalid);
    }
    Ok(())
}

fn limit_from_document(
    document: &PolicyDocument,
    dimension: QuotaDimension,
    scope: QuotaScopeKind,
) -> u64 {
    let pair = match dimension {
        QuotaDimension::RequestCount => document.limits.request_count,
        QuotaDimension::ConcurrentActiveWork => document.limits.concurrent_active_work,
        QuotaDimension::InputBytes => document.limits.input_bytes,
        QuotaDimension::OutputBytes => document.limits.output_bytes,
        QuotaDimension::EventCount => document.limits.event_count,
        QuotaDimension::ConcurrentStreams => document.limits.concurrent_streams,
        QuotaDimension::ConcurrentSubscriptions => document.limits.concurrent_subscriptions,
        QuotaDimension::ReconnectCount => document.limits.reconnect_count,
        QuotaDimension::RetainedAuthorityBytes => document.limits.retained_authority_bytes,
    };
    match scope {
        QuotaScopeKind::Tenant => pair.tenant,
        QuotaScopeKind::Account => pair.account,
        QuotaScopeKind::Principal => pair.principal,
    }
}

const fn dimension_cap(dimension: QuotaDimension) -> u64 {
    match dimension {
        QuotaDimension::RequestCount | QuotaDimension::ReconnectCount => MAX_RATE_CAP,
        QuotaDimension::ConcurrentActiveWork
        | QuotaDimension::ConcurrentStreams
        | QuotaDimension::ConcurrentSubscriptions => MAX_CONCURRENCY_CAP,
        QuotaDimension::EventCount => MAX_EVENT_CAP,
        QuotaDimension::InputBytes
        | QuotaDimension::OutputBytes
        | QuotaDimension::RetainedAuthorityBytes => MAX_BYTE_CAP,
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_visible_ascii(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}
