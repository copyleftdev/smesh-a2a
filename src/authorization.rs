//! Server-owned tenant authorization policy and immutable request context.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::auth::Principal;
use crate::{
    AuthorizationAuditInput, AuthorizationDecisionEffect, DurableAuthority, InjectedClock,
    SqliteTaskStore, content_digest,
};

tokio::task_local! {
    static AUTHORIZATION_CONTEXT: AuthorizationContext;
}

/// Return the immutable server-resolved context while authorized work runs.
#[must_use]
pub fn current_authorization_context() -> Option<AuthorizationContext> {
    AUTHORIZATION_CONTEXT.try_with(Clone::clone).ok()
}

/// Resolve and strip the sole transport tenant selector before protocol parsing.
pub async fn authorize_request(
    axum::extract::State(state): axum::extract::State<AuthorizationMiddlewareState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let values: Vec<_> = request
        .headers()
        .get_all(TENANT_SELECTOR_HEADER)
        .iter()
        .collect();
    let selector = match values.as_slice() {
        [] => None,
        [value] => match value.to_str() {
            Ok(value) if !value.contains(',') && value.len() <= 64 => Some(value.to_owned()),
            _ => return state.deny("malformed_selector").await,
        },
        _ => return state.deny("ambiguous_selector").await,
    };
    request.headers_mut().remove(TENANT_SELECTOR_HEADER);
    let Some(principal) = request.extensions().get::<Arc<Principal>>() else {
        return state.deny("missing_principal").await;
    };
    let Ok(context) = state.policy.resolve(principal, selector.as_deref()) else {
        return state.deny("selector_denied").await;
    };
    request.extensions_mut().insert(Arc::new(context.clone()));
    AUTHORIZATION_CONTEXT
        .scope(context, next.run(request))
        .await
}

/// Server-owned middleware dependencies. Production installs the durable sink;
/// isolated policy tests may omit it because they have no SQLite boundary.
#[derive(Clone)]
pub struct AuthorizationMiddlewareState {
    policy: Arc<AuthorizationPolicy>,
    audit_store: Option<Arc<dyn DurableAuthority>>,
    clock: InjectedClock,
}

impl AuthorizationMiddlewareState {
    #[must_use]
    pub fn without_audit(policy: Arc<AuthorizationPolicy>) -> Self {
        Self {
            policy,
            audit_store: None,
            clock: InjectedClock::new(0),
        }
    }

    #[must_use]
    pub fn with_sqlite(
        policy: Arc<AuthorizationPolicy>,
        audit_store: SqliteTaskStore,
        clock: InjectedClock,
    ) -> Self {
        Self::with_audit(policy, Arc::new(audit_store), clock)
    }

    #[must_use]
    pub fn with_audit(
        policy: Arc<AuthorizationPolicy>,
        audit_store: Arc<dyn DurableAuthority>,
        clock: InjectedClock,
    ) -> Self {
        Self {
            policy,
            audit_store: Some(audit_store),
            clock,
        }
    }

    async fn deny(&self, reason: &str) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        let Some(store) = self.audit_store.as_ref() else {
            return (axum::http::StatusCode::FORBIDDEN, "forbidden").into_response();
        };
        let Ok(resource_digest) = store.authorization_resource_digest(reason) else {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "forbidden").into_response();
        };
        let entropy: [u8; 32] = rand::random();
        let decision_id =
            content_digest([resource_digest.as_bytes(), &entropy].concat().as_slice());
        let audit = AuthorizationAuditInput::new(
            decision_id,
            "authorization-denial",
            "unresolved-principal",
            self.policy.policy_id(),
            self.policy.revision(),
            self.policy.digest(),
            "TenantSelectorResolve",
            AuthorizationDecisionEffect::Deny,
            reason,
            "tenant-selector",
            resource_digest,
            None,
            self.clock.now(),
        );
        let Ok(audit) = audit else {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "forbidden").into_response();
        };
        if store
            .append_denied_authorization_decision(audit)
            .await
            .is_ok()
        {
            (axum::http::StatusCode::FORBIDDEN, "forbidden").into_response()
        } else {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "forbidden").into_response()
        }
    }
}

pub const TENANT_SELECTOR_HEADER: &str = "x-smesh-tenant";
const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_TENANTS: usize = 1024;
const MAX_ACCOUNTS: usize = 4096;
const MAX_BINDINGS: usize = 8192;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("authorization policy is invalid")]
    InvalidPolicy,
    #[error("authorization denied")]
    Denied,
    #[error("authorization policy is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TenantRole {
    TenantAdmin,
    TaskOperator,
    TaskViewer,
    Auditor,
    TaskAgent,
    ServiceReader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    TaskCreate,
    TaskContinue,
    TaskGet,
    TaskList,
    TaskSubscribe,
    TaskCancel,
    HistoryRead,
    ArtifactRead,
    AuditRead,
    AuthorizationAdmin,
    PushCreate,
    PushGet,
    PushList,
    PushDelete,
    ExtendedCard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VisibilityScope {
    Own,
    Tenant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum AccountKind {
    Human,
    ServiceAccount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationContext {
    account_id: Arc<str>,
    tenant_id: Arc<str>,
    roles: Arc<[TenantRole]>,
    policy_id: Arc<str>,
    policy_revision: u64,
    policy_digest: Arc<str>,
}

impl AuthorizationContext {
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
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

    /// Check whether the fixed role matrix grants an operation.
    ///
    /// # Errors
    /// Returns [`AuthorizationError::Denied`] when no role grants the operation.
    pub fn authorize(&self, operation: Operation) -> Result<(), AuthorizationError> {
        self.visibility(operation).map(|_| ())
    }

    /// Return the narrowest effective resource visibility for an operation.
    ///
    /// # Errors
    /// Returns [`AuthorizationError::Denied`] when no role grants the operation.
    pub fn visibility(&self, operation: Operation) -> Result<VisibilityScope, AuthorizationError> {
        let mut granted = None;
        for role in self.roles.iter().copied() {
            let scope = role_grant(role, operation);
            if scope == Some(VisibilityScope::Tenant) {
                return Ok(VisibilityScope::Tenant);
            }
            if scope.is_some() {
                granted = scope;
            }
        }
        granted.ok_or(AuthorizationError::Denied)
    }
}

fn role_grant(role: TenantRole, operation: Operation) -> Option<VisibilityScope> {
    use Operation::{
        ArtifactRead, AuditRead, AuthorizationAdmin, ExtendedCard, HistoryRead, PushCreate,
        PushDelete, PushGet, PushList, TaskCancel, TaskContinue, TaskCreate, TaskGet, TaskList,
        TaskSubscribe,
    };
    use TenantRole::{Auditor, ServiceReader, TaskAgent, TaskOperator, TaskViewer, TenantAdmin};
    match (role, operation) {
        (
            TenantAdmin,
            TaskCreate | TaskContinue | TaskGet | TaskList | TaskSubscribe | TaskCancel
            | HistoryRead | ArtifactRead | AuditRead | AuthorizationAdmin | ExtendedCard,
        )
        | (
            TaskOperator,
            TaskCreate | TaskContinue | TaskGet | TaskList | TaskSubscribe | TaskCancel
            | HistoryRead | ArtifactRead | ExtendedCard,
        )
        | (
            TaskViewer | ServiceReader,
            TaskGet | TaskList | TaskSubscribe | HistoryRead | ArtifactRead | ExtendedCard,
        )
        | (Auditor, TaskGet | TaskList | HistoryRead | ArtifactRead | AuditRead | ExtendedCard) => {
            Some(VisibilityScope::Tenant)
        }
        (
            TaskAgent,
            TaskCreate | TaskContinue | TaskGet | TaskList | TaskSubscribe | TaskCancel
            | HistoryRead | ArtifactRead,
        ) => Some(VisibilityScope::Own),
        (TaskAgent, ExtendedCard) => Some(VisibilityScope::Tenant),
        (_, PushCreate | PushGet | PushList | PushDelete)
        | (
            TaskOperator | TaskViewer | Auditor | TaskAgent | ServiceReader,
            AuditRead | AuthorizationAdmin,
        )
        | (TaskViewer | Auditor | ServiceReader, TaskCreate | TaskContinue | TaskCancel)
        | (Auditor, TaskSubscribe) => None,
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyDocument {
    schema_version: String,
    policy_id: String,
    revision: u64,
    tenants: Vec<TenantDocument>,
    accounts: Vec<AccountDocument>,
    principal_bindings: Vec<BindingDocument>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantDocument {
    id: String,
    enabled: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountDocument {
    id: String,
    kind: AccountKind,
    memberships: Vec<MembershipDocument>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MembershipDocument {
    tenant_id: String,
    roles: Vec<TenantRole>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BindingDocument {
    principal: PrincipalDocument,
    account_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrincipalDocument {
    issuer: String,
    subject: String,
}

#[derive(Clone)]
struct Account {
    id: Arc<str>,
    memberships: BTreeMap<Arc<str>, Arc<[TenantRole]>>,
}

#[derive(Clone)]
pub struct AuthorizationPolicy {
    policy_id: Arc<str>,
    revision: u64,
    digest: Arc<str>,
    bindings: BTreeMap<(Arc<str>, Arc<str>), Arc<str>>,
    accounts: BTreeMap<Arc<str>, Account>,
}

impl AuthorizationPolicy {
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Validate an explicit legacy database binding against an enrolled account
    /// and enabled tenant membership in this exact policy revision.
    ///
    /// # Errors
    /// Returns [`AuthorizationError::Denied`] unless the tenant is an enabled membership of the
    /// enrolled account, or when the resulting binding violates durable identifier bounds.
    pub fn legacy_tenant_binding(
        &self,
        tenant_id: &str,
        account_id: &str,
    ) -> Result<crate::LegacyTenantBinding, AuthorizationError> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or(AuthorizationError::Denied)?;
        if !account.memberships.contains_key(tenant_id) {
            return Err(AuthorizationError::Denied);
        }
        crate::LegacyTenantBinding::new(
            tenant_id,
            account_id,
            self.policy_id.as_ref(),
            self.revision,
            self.digest.as_ref(),
        )
        .map_err(|_| AuthorizationError::InvalidPolicy)
    }

    /// Parse and completely validate a bounded strict policy document.
    ///
    /// # Errors
    /// Returns [`AuthorizationError::InvalidPolicy`] for any malformed or invalid policy.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorizationError> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(AuthorizationError::InvalidPolicy);
        }
        let document: PolicyDocument =
            serde_json::from_slice(bytes).map_err(|_| AuthorizationError::InvalidPolicy)?;
        if document.schema_version != "smesh-authz-policy/v1"
            || document.revision == 0
            || !valid_id(&document.policy_id)
            || document.tenants.is_empty()
            || document.tenants.len() > MAX_TENANTS
            || document.accounts.is_empty()
            || document.accounts.len() > MAX_ACCOUNTS
            || document.principal_bindings.is_empty()
            || document.principal_bindings.len() > MAX_BINDINGS
        {
            return Err(AuthorizationError::InvalidPolicy);
        }
        let mut tenants = BTreeMap::new();
        for tenant in &document.tenants {
            if !valid_id(&tenant.id) || tenants.insert(tenant.id.as_str(), tenant.enabled).is_some()
            {
                return Err(AuthorizationError::InvalidPolicy);
            }
        }
        let mut accounts = BTreeMap::new();
        for account in &document.accounts {
            if !valid_id(&account.id) || account.memberships.is_empty() {
                return Err(AuthorizationError::InvalidPolicy);
            }
            let mut memberships = BTreeMap::new();
            for membership in &account.memberships {
                if tenants.get(membership.tenant_id.as_str()) != Some(&true)
                    || membership.roles.is_empty()
                {
                    return Err(AuthorizationError::InvalidPolicy);
                }
                let roles: BTreeSet<_> = membership.roles.iter().copied().collect();
                if roles.len() != membership.roles.len()
                    || roles.iter().any(|role| !kind_allows(account.kind, *role))
                {
                    return Err(AuthorizationError::InvalidPolicy);
                }
                if memberships
                    .insert(
                        Arc::from(membership.tenant_id.as_str()),
                        roles.into_iter().collect::<Vec<_>>().into(),
                    )
                    .is_some()
                {
                    return Err(AuthorizationError::InvalidPolicy);
                }
            }
            let id: Arc<str> = Arc::from(account.id.as_str());
            if accounts
                .insert(id.clone(), Account { id, memberships })
                .is_some()
            {
                return Err(AuthorizationError::InvalidPolicy);
            }
        }
        let mut bindings = BTreeMap::new();
        for binding in &document.principal_bindings {
            if binding.principal.issuer.is_empty()
                || binding.principal.issuer.len() > 2048
                || binding.principal.subject.is_empty()
                || binding.principal.subject.len() > 256
                || !accounts.contains_key(binding.account_id.as_str())
            {
                return Err(AuthorizationError::InvalidPolicy);
            }
            let key = (
                Arc::from(binding.principal.issuer.as_str()),
                Arc::from(binding.principal.subject.as_str()),
            );
            if bindings
                .insert(key, Arc::from(binding.account_id.as_str()))
                .is_some()
            {
                return Err(AuthorizationError::InvalidPolicy);
            }
        }
        let canonical =
            serde_json::to_vec(&document).map_err(|_| AuthorizationError::InvalidPolicy)?;
        Ok(Self {
            policy_id: Arc::from(document.policy_id),
            revision: document.revision,
            digest: Arc::from(crate::content_digest(&canonical)),
            bindings,
            accounts,
        })
    }

    /// Load a bounded policy from a regular, non-symlink file.
    ///
    /// # Errors
    /// Returns `Unavailable` for I/O failures and `InvalidPolicy` for invalid material.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, AuthorizationError> {
        #[cfg(unix)]
        let file = std::fs::File::from(
            rustix::fs::open(
                path.as_ref(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| AuthorizationError::Unavailable)?,
        );
        #[cfg(not(unix))]
        let mut file =
            std::fs::File::open(path.as_ref()).map_err(|_| AuthorizationError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| AuthorizationError::Unavailable)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_POLICY_BYTES as u64 {
            return Err(AuthorizationError::InvalidPolicy);
        }
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| AuthorizationError::InvalidPolicy)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take((MAX_POLICY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorizationError::Unavailable)?;
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(AuthorizationError::InvalidPolicy);
        }
        Self::from_json(&bytes)
    }

    /// Resolve an authenticated identity and optional tenant selector to immutable context.
    ///
    /// # Errors
    /// Returns [`AuthorizationError::Denied`] for unenrolled, inaccessible, malformed,
    /// or ambiguous selection.
    pub fn resolve(
        &self,
        principal: &Principal,
        selector: Option<&str>,
    ) -> Result<AuthorizationContext, AuthorizationError> {
        let account_id = self
            .bindings
            .get(&(
                Arc::from(principal.issuer()),
                Arc::from(principal.subject()),
            ))
            .ok_or(AuthorizationError::Denied)?;
        let account = self
            .accounts
            .get(account_id)
            .ok_or(AuthorizationError::Denied)?;
        let (tenant_id, roles) = match selector {
            Some(value) if valid_id(value) => account
                .memberships
                .get_key_value(value)
                .ok_or(AuthorizationError::Denied)?,
            None if account.memberships.len() == 1 => account
                .memberships
                .first_key_value()
                .ok_or(AuthorizationError::Denied)?,
            Some(_) | None => return Err(AuthorizationError::Denied),
        };
        Ok(AuthorizationContext {
            account_id: account.id.clone(),
            tenant_id: tenant_id.clone(),
            roles: roles.clone(),
            policy_id: self.policy_id.clone(),
            policy_revision: self.revision,
            policy_digest: self.digest.clone(),
        })
    }
}

fn kind_allows(kind: AccountKind, role: TenantRole) -> bool {
    match kind {
        AccountKind::Human => !matches!(role, TenantRole::TaskAgent | TenantRole::ServiceReader),
        AccountKind::ServiceAccount => {
            matches!(role, TenantRole::TaskAgent | TenantRole::ServiceReader)
        }
    }
}
fn valid_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
}
