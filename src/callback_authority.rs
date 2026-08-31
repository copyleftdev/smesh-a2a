//! Backend-neutral durable callback configuration and delivery authority.
//!
//! This contract intentionally exposes commands rather than transactions. Lease
//! time is database-authoritative; callers supply only bounded durations and
//! retry instants selected from persisted policy. No type can carry callback
//! authentication bytes.

#![allow(clippy::missing_errors_doc, clippy::struct_excessive_bools)]

use std::sync::Arc;

use a2a::A2AError;
use async_trait::async_trait;

use crate::OwnedTaskScope;

const MAX_ID_BYTES: usize = 128;
const MAX_URL_BYTES: usize = 2_048;
const MAX_DIGEST_BYTES: usize = 71;
const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

fn invalid(message: &'static str) -> A2AError {
    A2AError::invalid_request(message)
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.is_ascii()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}
fn valid_digest(value: &str) -> bool {
    value.len() == MAX_DIGEST_BYTES
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallbackAuditKind {
    PolicyReconciled,
    ConfigCreated,
    ConfigDeleted,
    EventEnqueued,
    DeliveryAttempted,
    Delivered,
    RetryScheduled,
    Dead,
}

impl CallbackAuditKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyReconciled => "callback_policy_reconciled",
            Self::ConfigCreated => "callback_config_created",
            Self::ConfigDeleted => "callback_config_deleted",
            Self::EventEnqueued => "callback_event_enqueued",
            Self::DeliveryAttempted => "callback_delivery_attempted",
            Self::Delivered => "callback_delivered",
            Self::RetryScheduled => "callback_retry_scheduled",
            Self::Dead => "callback_dead",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "callback_policy_reconciled" => Self::PolicyReconciled,
            "callback_config_created" => Self::ConfigCreated,
            "callback_config_deleted" => Self::ConfigDeleted,
            "callback_event_enqueued" => Self::EventEnqueued,
            "callback_delivery_attempted" => Self::DeliveryAttempted,
            "callback_delivered" => Self::Delivered,
            "callback_retry_scheduled" => Self::RetryScheduled,
            "callback_dead" => Self::Dead,
            _ => return None,
        })
    }
}

pub(crate) fn callback_audit_digest(
    kind: CallbackAuditKind,
    tenant: &str,
    task: &str,
    config: &str,
    event: &str,
    revision: i64,
    attempt: i64,
) -> String {
    let mut material = b"smesh-callback-audit/v1".to_vec();
    for value in [kind.as_str(), tenant, task, config, event] {
        material.extend_from_slice(value.len().to_string().as_bytes());
        material.push(b':');
        material.extend_from_slice(value.as_bytes());
    }
    for value in [revision, attempt] {
        let value = value.to_string();
        material.extend_from_slice(value.len().to_string().as_bytes());
        material.push(b':');
        material.extend_from_slice(value.as_bytes());
    }
    crate::content_digest(&material)
}

/// Validated opaque callback configuration identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallbackConfigId(String);
impl CallbackConfigId {
    pub fn new(value: impl Into<String>) -> Result<Self, A2AError> {
        let value = value.into();
        valid_id(&value)
            .then_some(Self(value))
            .ok_or_else(|| invalid("invalid callback config id"))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded protocol page size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigPageSize(u16);
impl ConfigPageSize {
    pub fn new(value: u16) -> Result<Self, A2AError> {
        (1..=100)
            .contains(&value)
            .then_some(Self(value))
            .ok_or_else(|| invalid("invalid callback page size"))
    }
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Database-time lease duration accepted by callback authorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseDurationMillis(i64);
impl LeaseDurationMillis {
    pub fn new(value: i64) -> Result<Self, A2AError> {
        (1_000..=300_000)
            .contains(&value)
            .then_some(Self(value))
            .ok_or_else(|| invalid("invalid callback lease duration"))
    }
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackBackend {
    SqliteConformance,
    PostgresProduction,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackCapabilities {
    backend: CallbackBackend,
    multi_replica_claims: bool,
    database_time_leases: bool,
    forced_tenant_rls: bool,
    atomic_terminal_enqueue: bool,
}
impl CallbackCapabilities {
    #[must_use]
    pub const fn sqlite_conformance() -> Self {
        Self {
            backend: CallbackBackend::SqliteConformance,
            multi_replica_claims: false,
            database_time_leases: true,
            forced_tenant_rls: false,
            atomic_terminal_enqueue: true,
        }
    }
    #[must_use]
    pub const fn postgres_production() -> Self {
        Self {
            backend: CallbackBackend::PostgresProduction,
            multi_replica_claims: true,
            database_time_leases: true,
            forced_tenant_rls: true,
            atomic_terminal_enqueue: true,
        }
    }
    #[must_use]
    pub const fn backend(self) -> CallbackBackend {
        self.backend
    }
    #[must_use]
    pub const fn multi_replica_claims(self) -> bool {
        self.multi_replica_claims
    }
    #[must_use]
    pub const fn database_time_leases(self) -> bool {
        self.database_time_leases
    }
    #[must_use]
    pub const fn forced_tenant_rls(self) -> bool {
        self.forced_tenant_rls
    }
    #[must_use]
    pub const fn atomic_terminal_enqueue(self) -> bool {
        self.atomic_terminal_enqueue
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackReadiness {
    Disabled,
    Starting,
    Ready,
    Fatal,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackConfigState {
    Active,
    Draining,
    Revoked,
    TerminalClosed,
}
impl CallbackConfigState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Revoked => "revoked",
            Self::TerminalClosed => "terminal_closed",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDeliveryState {
    Pending,
    Leased,
    Delivered,
    Retry,
    Dead,
    Canceled,
}

/// One-shot, test-only failures inside the atomic terminal callback enqueue.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackTerminalTestFault {
    BeforeEventInsert,
    BeforeDeliveryInsert,
    AfterDeliveryInsert,
    BeforeConfigTerminalClose,
    AfterCallbackRows,
}

impl CallbackTerminalTestFault {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeEventInsert => "before_event_insert",
            Self::BeforeDeliveryInsert => "before_delivery_insert",
            Self::AfterDeliveryInsert => "after_delivery_insert",
            Self::BeforeConfigTerminalClose => "before_config_terminal_close",
            Self::AfterCallbackRows => "after_callback_rows",
        }
    }
}
impl CallbackDeliveryState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Delivered => "delivered",
            Self::Retry => "retry",
            Self::Dead => "dead",
            Self::Canceled => "canceled",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDeliveryDisposition {
    Retry,
    Dead,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDeliveryCategory {
    Transport,
    Dns,
    Tls,
    Timeout,
    Http,
    Policy,
    Payload,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDeleteOutcome {
    Revoked,
    AlreadyAbsent,
    Draining,
}

/// Immutable policy identity and hard retained-work bounds persisted at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackPolicySnapshot {
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
    max_configs_per_task: u16,
    max_configs_per_tenant: u32,
    max_pending: u32,
    max_payload_bytes: u32,
    max_attempts: u16,
    max_delivery_age_ms: u64,
}
impl CallbackPolicySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: impl Into<String>,
        max_configs_per_task: u16,
        max_pending: u32,
        max_payload_bytes: u32,
        max_attempts: u16,
    ) -> Result<Self, A2AError> {
        Self::new_with_delivery_age(
            policy_id,
            policy_revision,
            policy_digest,
            max_configs_per_task,
            max_pending,
            max_payload_bytes,
            max_attempts,
            604_800_000,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_delivery_age(
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: impl Into<String>,
        max_configs_per_task: u16,
        max_pending: u32,
        max_payload_bytes: u32,
        max_attempts: u16,
        max_delivery_age_ms: u64,
    ) -> Result<Self, A2AError> {
        Self::new_with_tenant_cap(
            policy_id,
            policy_revision,
            policy_digest,
            max_configs_per_task,
            max_pending,
            max_pending,
            max_payload_bytes,
            max_attempts,
            max_delivery_age_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tenant_cap(
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: impl Into<String>,
        max_configs_per_task: u16,
        max_configs_per_tenant: u32,
        max_pending: u32,
        max_payload_bytes: u32,
        max_attempts: u16,
        max_delivery_age_ms: u64,
    ) -> Result<Self, A2AError> {
        let value = Self {
            policy_id: policy_id.into(),
            policy_revision,
            policy_digest: policy_digest.into(),
            max_configs_per_task,
            max_configs_per_tenant,
            max_pending,
            max_payload_bytes,
            max_attempts,
            max_delivery_age_ms,
        };
        if !valid_id(&value.policy_id)
            || value.policy_revision == 0
            || !valid_digest(&value.policy_digest)
            || !(1..=32).contains(&value.max_configs_per_task)
            || value.max_configs_per_tenant == 0
            || value.max_configs_per_tenant > value.max_pending
            || value.max_pending == 0
            || value.max_pending > 1_000_000
            || value.max_payload_bytes == 0
            || value.max_payload_bytes as usize > MAX_PAYLOAD_BYTES
            || !(1..=32).contains(&value.max_attempts)
            || !(1..=604_800_000).contains(&value.max_delivery_age_ms)
        {
            return Err(invalid("invalid callback policy snapshot"));
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
    #[must_use]
    pub const fn max_configs_per_task(&self) -> u16 {
        self.max_configs_per_task
    }
    #[must_use]
    pub const fn max_configs_per_tenant(&self) -> u32 {
        self.max_configs_per_tenant
    }
    #[must_use]
    pub const fn max_pending(&self) -> u32 {
        self.max_pending
    }
    #[must_use]
    pub const fn max_payload_bytes(&self) -> u32 {
        self.max_payload_bytes
    }
    #[must_use]
    pub const fn max_attempts(&self) -> u16 {
        self.max_attempts
    }
    #[must_use]
    pub const fn max_delivery_age_ms(&self) -> u64 {
        self.max_delivery_age_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigCreateCommand {
    scope: OwnedTaskScope,
    task_id: String,
    config_id: Option<CallbackConfigId>,
    enrollment_id: String,
    enrollment_generation: u64,
    canonical_url: String,
    url_digest: String,
    created_at: i64,
    authorization_audit: Option<crate::AuthorizationAuditInput>,
}
impl ConfigCreateCommand {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: OwnedTaskScope,
        task_id: impl Into<String>,
        config_id: Option<CallbackConfigId>,
        enrollment_id: impl Into<String>,
        enrollment_generation: u64,
        canonical_url: impl Into<String>,
        url_digest: impl Into<String>,
        created_at: i64,
    ) -> Result<Self, A2AError> {
        let value = Self {
            scope,
            task_id: task_id.into(),
            config_id,
            enrollment_id: enrollment_id.into(),
            enrollment_generation,
            canonical_url: canonical_url.into(),
            url_digest: url_digest.into(),
            created_at,
            authorization_audit: None,
        };
        if !valid_id(&value.task_id)
            || !valid_id(&value.enrollment_id)
            || value.enrollment_generation == 0
            || value.canonical_url.is_empty()
            || value.canonical_url.len() > MAX_URL_BYTES
            || !value.canonical_url.is_ascii()
            || !valid_digest(&value.url_digest)
            || value.created_at <= 0
        {
            return Err(invalid("invalid callback create command"));
        }
        Ok(value)
    }
    #[must_use]
    pub fn scope(&self) -> &OwnedTaskScope {
        &self.scope
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub fn config_id(&self) -> Option<&CallbackConfigId> {
        self.config_id.as_ref()
    }
    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }
    #[must_use]
    pub const fn enrollment_generation(&self) -> u64 {
        self.enrollment_generation
    }
    #[must_use]
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }
    #[must_use]
    pub fn url_digest(&self) -> &str {
        &self.url_digest
    }
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }
    pub(crate) fn with_authorization_audit(
        mut self,
        audit: crate::AuthorizationAuditInput,
    ) -> Self {
        self.authorization_audit = Some(audit);
        self
    }
    pub(crate) fn authorization_audit(&self) -> Option<&crate::AuthorizationAuditInput> {
        self.authorization_audit.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigGetCommand {
    scope: OwnedTaskScope,
    task_id: String,
    config_id: CallbackConfigId,
}
impl ConfigGetCommand {
    pub fn new(
        scope: OwnedTaskScope,
        task_id: impl Into<String>,
        config_id: CallbackConfigId,
    ) -> Result<Self, A2AError> {
        let task_id = task_id.into();
        if !valid_id(&task_id) {
            return Err(invalid("invalid callback get command"));
        }
        Ok(Self {
            scope,
            task_id,
            config_id,
        })
    }
    #[must_use]
    pub fn scope(&self) -> &OwnedTaskScope {
        &self.scope
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub fn config_id(&self) -> &CallbackConfigId {
        &self.config_id
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigListCommand {
    scope: OwnedTaskScope,
    task_id: String,
    page_size: ConfigPageSize,
    page_token: Option<String>,
}
impl ConfigListCommand {
    pub fn new(
        scope: OwnedTaskScope,
        task_id: impl Into<String>,
        page_size: ConfigPageSize,
        page_token: Option<String>,
    ) -> Result<Self, A2AError> {
        let task_id = task_id.into();
        if !valid_id(&task_id)
            || page_token
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 4096 || !v.is_ascii())
        {
            return Err(invalid("invalid callback list command"));
        }
        Ok(Self {
            scope,
            task_id,
            page_size,
            page_token,
        })
    }
    #[must_use]
    pub fn scope(&self) -> &OwnedTaskScope {
        &self.scope
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub const fn page_size(&self) -> ConfigPageSize {
        self.page_size
    }
    #[must_use]
    pub fn page_token(&self) -> Option<&str> {
        self.page_token.as_deref()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDeleteCommand {
    scope: OwnedTaskScope,
    task_id: String,
    config_id: CallbackConfigId,
    requested_at: i64,
    authorization_audit: Option<crate::AuthorizationAuditInput>,
}
impl ConfigDeleteCommand {
    pub fn new(
        scope: OwnedTaskScope,
        task_id: impl Into<String>,
        config_id: CallbackConfigId,
        requested_at: i64,
    ) -> Result<Self, A2AError> {
        let task_id = task_id.into();
        if !valid_id(&task_id) || requested_at <= 0 {
            return Err(invalid("invalid callback delete command"));
        }
        Ok(Self {
            scope,
            task_id,
            config_id,
            requested_at,
            authorization_audit: None,
        })
    }
    #[must_use]
    pub fn scope(&self) -> &OwnedTaskScope {
        &self.scope
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub fn config_id(&self) -> &CallbackConfigId {
        &self.config_id
    }
    #[must_use]
    pub const fn requested_at(&self) -> i64 {
        self.requested_at
    }
    pub(crate) fn with_authorization_audit(
        mut self,
        audit: crate::AuthorizationAuditInput,
    ) -> Self {
        self.authorization_audit = Some(audit);
        self
    }
    pub(crate) fn authorization_audit(&self) -> Option<&crate::AuthorizationAuditInput> {
        self.authorization_audit.as_ref()
    }
}

/// Public config projection. Authentication material is structurally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackConfig {
    tenant_scope: String,
    task_id: String,
    config_id: CallbackConfigId,
    enrollment_id: String,
    enrollment_generation: u64,
    canonical_url: String,
    url_digest: String,
    state: CallbackConfigState,
    created_at: i64,
}
impl CallbackConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_scope: impl Into<String>,
        task_id: impl Into<String>,
        config_id: CallbackConfigId,
        enrollment_id: impl Into<String>,
        enrollment_generation: u64,
        canonical_url: impl Into<String>,
        url_digest: impl Into<String>,
        state: CallbackConfigState,
        created_at: i64,
    ) -> Result<Self, A2AError> {
        let v = Self {
            tenant_scope: tenant_scope.into(),
            task_id: task_id.into(),
            config_id,
            enrollment_id: enrollment_id.into(),
            enrollment_generation,
            canonical_url: canonical_url.into(),
            url_digest: url_digest.into(),
            state,
            created_at,
        };
        if !valid_id(&v.tenant_scope)
            || !valid_id(&v.task_id)
            || !valid_id(&v.enrollment_id)
            || v.enrollment_generation == 0
            || v.canonical_url.is_empty()
            || v.canonical_url.len() > MAX_URL_BYTES
            || !valid_digest(&v.url_digest)
            || v.created_at <= 0
        {
            return Err(invalid("invalid callback config"));
        }
        Ok(v)
    }
    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub fn config_id(&self) -> &CallbackConfigId {
        &self.config_id
    }
    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }
    #[must_use]
    pub const fn enrollment_generation(&self) -> u64 {
        self.enrollment_generation
    }
    #[must_use]
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }
    #[must_use]
    pub fn url_digest(&self) -> &str {
        &self.url_digest
    }
    #[must_use]
    pub const fn state(&self) -> CallbackConfigState {
        self.state
    }
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackConfigPage {
    configs: Vec<CallbackConfig>,
    next_page_token: Option<String>,
}
impl CallbackConfigPage {
    pub fn new(
        configs: Vec<CallbackConfig>,
        next_page_token: Option<String>,
    ) -> Result<Self, A2AError> {
        if configs.len() > 100
            || next_page_token
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 4096 || !v.is_ascii())
        {
            return Err(invalid("invalid callback config page"));
        }
        Ok(Self {
            configs,
            next_page_token,
        })
    }
    #[must_use]
    pub fn configs(&self) -> &[CallbackConfig] {
        &self.configs
    }
    #[must_use]
    pub fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }
}

/// Secret-free internal projection of an operator enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackEnrollmentBinding {
    enrollment_id: String,
    enrollment_generation: u64,
    canonical_url: String,
    url_digest: String,
}
impl CallbackEnrollmentBinding {
    pub fn new(
        enrollment_id: impl Into<String>,
        enrollment_generation: u64,
        canonical_url: impl Into<String>,
        url_digest: impl Into<String>,
    ) -> Result<Self, A2AError> {
        let value = Self {
            enrollment_id: enrollment_id.into(),
            enrollment_generation,
            canonical_url: canonical_url.into(),
            url_digest: url_digest.into(),
        };
        if !valid_id(&value.enrollment_id)
            || value.enrollment_generation == 0
            || value.canonical_url.is_empty()
            || value.canonical_url.len() > MAX_URL_BYTES
            || !valid_digest(&value.url_digest)
        {
            return Err(invalid("invalid callback enrollment binding"));
        }
        Ok(value)
    }
    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }
    #[must_use]
    pub const fn enrollment_generation(&self) -> u64 {
        self.enrollment_generation
    }
    #[must_use]
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }
    #[must_use]
    pub fn url_digest(&self) -> &str {
        &self.url_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallbackIntent {
    pub config_id: Option<CallbackConfigId>,
    pub enrollment: CallbackEnrollmentBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryFence {
    tenant_scope: String,
    event_id: String,
    config_id: String,
    lease_owner: String,
    lease_token: String,
    lease_epoch: u64,
}
impl DeliveryFence {
    pub fn new(
        tenant_scope: impl Into<String>,
        event_id: impl Into<String>,
        config_id: impl Into<String>,
        lease_owner: impl Into<String>,
        lease_token: impl Into<String>,
        lease_epoch: u64,
    ) -> Result<Self, A2AError> {
        let v = Self {
            tenant_scope: tenant_scope.into(),
            event_id: event_id.into(),
            config_id: config_id.into(),
            lease_owner: lease_owner.into(),
            lease_token: lease_token.into(),
            lease_epoch,
        };
        if !valid_id(&v.tenant_scope)
            || !valid_id(&v.event_id)
            || !valid_id(&v.config_id)
            || !valid_id(&v.lease_owner)
            || v.lease_token.is_empty()
            || v.lease_token.len() > 128
            || !v.lease_token.is_ascii()
            || v.lease_epoch == 0
        {
            return Err(invalid("invalid callback delivery fence"));
        }
        Ok(v)
    }
    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    #[must_use]
    pub fn config_id(&self) -> &str {
        &self.config_id
    }
    #[must_use]
    pub fn lease_owner(&self) -> &str {
        &self.lease_owner
    }
    #[must_use]
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }
    #[must_use]
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryClaimCommand {
    owner: String,
    lease_duration: LeaseDurationMillis,
    batch_limit: u16,
}
impl DeliveryClaimCommand {
    pub fn new(
        owner: impl Into<String>,
        lease_duration: LeaseDurationMillis,
        batch_limit: u16,
    ) -> Result<Self, A2AError> {
        let owner = owner.into();
        if !valid_id(&owner) || !(1..=1000).contains(&batch_limit) {
            return Err(invalid("invalid callback claim command"));
        }
        Ok(Self {
            owner,
            lease_duration,
            batch_limit,
        })
    }
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    #[must_use]
    pub const fn lease_duration(&self) -> LeaseDurationMillis {
        self.lease_duration
    }
    #[must_use]
    pub const fn batch_limit(&self) -> u16 {
        self.batch_limit
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackLease {
    fence: DeliveryFence,
    task_id: String,
    config_id: String,
    canonical_url: String,
    enrollment_id: String,
    enrollment_generation: u64,
    payload: Vec<u8>,
    payload_digest: String,
    attempt: u16,
    created_at: i64,
    expires_at: i64,
    lease_expires_at: i64,
    owner_account_id: String,
    principal_scope: String,
}
impl CallbackLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fence: DeliveryFence,
        task_id: impl Into<String>,
        config_id: impl Into<String>,
        canonical_url: impl Into<String>,
        enrollment_id: impl Into<String>,
        enrollment_generation: u64,
        payload: Vec<u8>,
        payload_digest: impl Into<String>,
        attempt: u16,
        lease_expires_at: i64,
    ) -> Result<Self, A2AError> {
        let tenant = fence.tenant_scope().to_owned();
        Self::new_authoritative(
            fence,
            task_id,
            config_id,
            canonical_url,
            enrollment_id,
            enrollment_generation,
            payload,
            payload_digest,
            attempt,
            lease_expires_at,
            lease_expires_at,
            lease_expires_at,
            tenant.clone(),
            tenant,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_scoped(
        fence: DeliveryFence,
        task_id: impl Into<String>,
        config_id: impl Into<String>,
        canonical_url: impl Into<String>,
        enrollment_id: impl Into<String>,
        enrollment_generation: u64,
        payload: Vec<u8>,
        payload_digest: impl Into<String>,
        attempt: u16,
        created_at: i64,
        expires_at: i64,
        owner_account_id: impl Into<String>,
        principal_scope: impl Into<String>,
    ) -> Result<Self, A2AError> {
        Self::new_authoritative(
            fence,
            task_id,
            config_id,
            canonical_url,
            enrollment_id,
            enrollment_generation,
            payload,
            payload_digest,
            attempt,
            created_at,
            expires_at,
            expires_at,
            owner_account_id,
            principal_scope,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_authoritative(
        fence: DeliveryFence,
        task_id: impl Into<String>,
        config_id: impl Into<String>,
        canonical_url: impl Into<String>,
        enrollment_id: impl Into<String>,
        enrollment_generation: u64,
        payload: Vec<u8>,
        payload_digest: impl Into<String>,
        attempt: u16,
        created_at: i64,
        expires_at: i64,
        lease_expires_at: i64,
        owner_account_id: impl Into<String>,
        principal_scope: impl Into<String>,
    ) -> Result<Self, A2AError> {
        let v = Self {
            fence,
            task_id: task_id.into(),
            config_id: config_id.into(),
            canonical_url: canonical_url.into(),
            enrollment_id: enrollment_id.into(),
            enrollment_generation,
            payload,
            payload_digest: payload_digest.into(),
            attempt,
            created_at,
            expires_at,
            lease_expires_at,
            owner_account_id: owner_account_id.into(),
            principal_scope: principal_scope.into(),
        };
        if !valid_id(&v.task_id)
            || !valid_id(&v.config_id)
            || !valid_id(&v.enrollment_id)
            || v.enrollment_generation == 0
            || v.canonical_url.is_empty()
            || v.canonical_url.len() > MAX_URL_BYTES
            || v.payload.is_empty()
            || v.payload.len() > MAX_PAYLOAD_BYTES
            || !valid_digest(&v.payload_digest)
            || v.attempt == 0
            || v.attempt > 32
            || v.created_at <= 0
            || v.expires_at < v.created_at
            || v.lease_expires_at <= 0
            || !valid_id(&v.owner_account_id)
            || v.principal_scope.is_empty()
            || v.principal_scope.len() > 256
            || !v.principal_scope.is_ascii()
        {
            return Err(invalid("invalid callback lease"));
        }
        Ok(v)
    }
    #[must_use]
    pub fn fence(&self) -> &DeliveryFence {
        &self.fence
    }
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }
    #[must_use]
    pub fn config_id(&self) -> &str {
        &self.config_id
    }
    #[must_use]
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }
    #[must_use]
    pub fn enrollment_id(&self) -> &str {
        &self.enrollment_id
    }
    #[must_use]
    pub const fn enrollment_generation(&self) -> u64 {
        self.enrollment_generation
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    #[must_use]
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }
    #[must_use]
    pub const fn attempt(&self) -> u16 {
        self.attempt
    }
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
    #[must_use]
    pub fn owner_account_id(&self) -> &str {
        &self.owner_account_id
    }
    #[must_use]
    pub fn principal_scope(&self) -> &str {
        &self.principal_scope
    }
    #[must_use]
    pub const fn lease_expires_at(&self) -> i64 {
        self.lease_expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackFailCommand {
    fence: DeliveryFence,
    disposition: CallbackDeliveryDisposition,
    category: CallbackDeliveryCategory,
    error_digest: String,
    retry_at: Option<i64>,
}
impl CallbackFailCommand {
    pub fn new(
        fence: DeliveryFence,
        disposition: CallbackDeliveryDisposition,
        category: CallbackDeliveryCategory,
        error_digest: impl Into<String>,
        retry_at: Option<i64>,
    ) -> Result<Self, A2AError> {
        let v = Self {
            fence,
            disposition,
            category,
            error_digest: error_digest.into(),
            retry_at,
        };
        if !valid_digest(&v.error_digest)
            || matches!(v.disposition, CallbackDeliveryDisposition::Retry) != v.retry_at.is_some()
            || v.retry_at.is_some_and(|t| t <= 0)
        {
            return Err(invalid("invalid callback failure command"));
        }
        Ok(v)
    }
    #[must_use]
    pub fn fence(&self) -> &DeliveryFence {
        &self.fence
    }
    #[must_use]
    pub const fn disposition(&self) -> CallbackDeliveryDisposition {
        self.disposition
    }
    #[must_use]
    pub const fn category(&self) -> CallbackDeliveryCategory {
        self.category
    }
    #[must_use]
    pub fn error_digest(&self) -> &str {
        &self.error_digest
    }
    #[must_use]
    pub const fn retry_at(&self) -> Option<i64> {
        self.retry_at
    }
}

/// Required complete callback capability. No production method has a no-op default.
#[async_trait]
pub trait CallbackAuthority: Send + Sync {
    fn callback_capabilities(&self) -> CallbackCapabilities;
    fn callback_readiness(&self) -> CallbackReadiness;
    fn callback_policy_snapshot(&self) -> Option<Arc<CallbackPolicySnapshot>>;
    /// Read the authority's current database clock in Unix milliseconds.
    /// Implementations must fail closed when their authoritative clock cannot
    /// be read; workers must not derive post-network scheduling time from a
    /// previously claimed or renewed lease.
    async fn callback_database_time(&self) -> Result<i64, A2AError>;
    async fn resolve_callback_enrollment(
        &self,
        scope: &OwnedTaskScope,
        exact_url: &str,
    ) -> Result<Option<CallbackEnrollmentBinding>, A2AError>;
    async fn create_callback_config(
        &self,
        command: ConfigCreateCommand,
    ) -> Result<CallbackConfig, A2AError>;
    async fn get_callback_config(
        &self,
        command: ConfigGetCommand,
    ) -> Result<Option<CallbackConfig>, A2AError>;
    async fn list_callback_configs(
        &self,
        command: ConfigListCommand,
    ) -> Result<CallbackConfigPage, A2AError>;
    async fn delete_callback_config(
        &self,
        command: ConfigDeleteCommand,
    ) -> Result<CallbackDeleteOutcome, A2AError>;
    async fn claim_callback_deliveries(
        &self,
        command: DeliveryClaimCommand,
    ) -> Result<Vec<CallbackLease>, A2AError>;
    async fn renew_callback_delivery(
        &self,
        fence: &DeliveryFence,
        duration: LeaseDurationMillis,
    ) -> Result<Option<i64>, A2AError>;
    /// Revalidate the complete durable delivery fence immediately before DNS
    /// or connect. The default is source-compatible and delegates to the
    /// authority's database-time renewal, so deletion/generation races cannot
    /// rely on an in-process policy snapshot alone.
    async fn validate_callback_delivery_fence(
        &self,
        fence: &DeliveryFence,
        duration: LeaseDurationMillis,
    ) -> Result<bool, A2AError> {
        self.renew_callback_delivery(fence, duration)
            .await
            .map(|lease_until| lease_until.is_some())
    }
    async fn commit_callback_delivery(&self, fence: &DeliveryFence) -> Result<bool, A2AError>;
    async fn fail_callback_delivery(
        &self,
        command: CallbackFailCommand,
    ) -> Result<CallbackDeliveryState, A2AError>;
    async fn revoke_callback_delivery(
        &self,
        fence: &DeliveryFence,
    ) -> Result<CallbackDeliveryState, A2AError>;
}
