//! Strict owner-private operator plans for physical artifact maintenance.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::semicolon_if_nothing_returned
)]

use crate::{ArtifactKeyRotationPlan, ArtifactStoreError, ContentDigestV1};
use serde::Deserialize;
use std::{
    fmt,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authority {
    schema: String,
    store_id: ContentDigestV1,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    id: String,
    revision: u64,
    digest: ContentDigestV1,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignatureHook {
    command: PathBuf,
    #[serde(default)]
    args: Vec<String>,
}
impl SignatureHook {
    pub fn command(&self) -> &Path {
        &self.command
    }
    pub fn args(&self) -> &[String] {
        &self.args
    }
    fn validate(&self) -> Result<(), ArtifactStoreError> {
        if !self.command.is_absolute()
            || self.args.len() > 32
            || self.args.iter().any(|v| v.len() > 4096 || v.contains('\0'))
        {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(())
    }
}
impl fmt::Debug for SignatureHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureHook")
            .field("command", &"<redacted>")
            .field("args", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupDocument {
    schema: String,
    backup_id: String,
    source: Authority,
    artifact_policy: Policy,
    actor: String,
    reason: String,
    destination: PathBuf,
    batch_size: u16,
    lease_duration_millis: i64,
    signature_hook: Option<SignatureHook>,
}
#[derive(Clone)]
pub struct ArtifactBackupPlanFile {
    backup_id: String,
    source_schema: String,
    source_store_id: ContentDigestV1,
    policy_id: String,
    policy_revision: u64,
    policy_digest: ContentDigestV1,
    actor_digest: ContentDigestV1,
    reason_digest: ContentDigestV1,
    destination: PathBuf,
    batch_size: u16,
    lease_duration_millis: i64,
    signature_hook: Option<SignatureHook>,
}
impl ArtifactBackupPlanFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let d: BackupDocument = read_private_json(path.as_ref())?;
        if d.schema != "smesh-artifact-backup-plan/v1"
            || !valid_id(&d.backup_id)
            || !valid_schema(&d.source.schema)
            || !valid_id(&d.artifact_policy.id)
            || d.artifact_policy.revision == 0
            || d.actor.is_empty()
            || d.reason.is_empty()
            || !(1..=1000).contains(&d.batch_size)
            || !(10..=86_400_000).contains(&d.lease_duration_millis)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        validate_private_root(&d.destination, false)?;
        if let Some(h) = &d.signature_hook {
            h.validate()?;
        }
        Ok(Self {
            backup_id: d.backup_id,
            source_schema: d.source.schema,
            source_store_id: d.source.store_id,
            policy_id: d.artifact_policy.id,
            policy_revision: d.artifact_policy.revision,
            policy_digest: d.artifact_policy.digest,
            actor_digest: ContentDigestV1::of(d.actor.as_bytes()),
            reason_digest: ContentDigestV1::of(d.reason.as_bytes()),
            destination: d.destination,
            batch_size: d.batch_size,
            lease_duration_millis: d.lease_duration_millis,
            signature_hook: d.signature_hook,
        })
    }
    pub fn backup_id(&self) -> &str {
        &self.backup_id
    }
    pub fn source_schema(&self) -> &str {
        &self.source_schema
    }
    pub const fn source_store_id(&self) -> ContentDigestV1 {
        self.source_store_id
    }
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub const fn policy_digest(&self) -> ContentDigestV1 {
        self.policy_digest
    }
    pub const fn actor_digest(&self) -> ContentDigestV1 {
        self.actor_digest
    }
    pub const fn reason_digest(&self) -> ContentDigestV1 {
        self.reason_digest
    }
    pub fn destination(&self) -> &Path {
        &self.destination
    }
    pub const fn batch_size(&self) -> u16 {
        self.batch_size
    }
    pub const fn lease_duration_millis(&self) -> i64 {
        self.lease_duration_millis
    }
    pub fn signature_hook(&self) -> Option<&SignatureHook> {
        self.signature_hook.as_ref()
    }
}
impl fmt::Debug for ArtifactBackupPlanFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactBackupPlanFile")
            .field("backup_id", &self.backup_id)
            .field("source_schema", &self.source_schema)
            .field("source_store_id", &self.source_store_id)
            .field("policy_digest", &self.policy_digest)
            .field("actor", &"<redacted>")
            .field("reason", &"<redacted>")
            .field("destination", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreSource {
    backup_root: PathBuf,
    inventory: PathBuf,
    store_id: ContentDigestV1,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreTarget {
    schema: String,
    store_id: ContentDigestV1,
    root: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreDocument {
    schema: String,
    restore_id: String,
    source: RestoreSource,
    target: RestoreTarget,
    artifact_policy_digest: ContentDigestV1,
    actor: String,
    reason: String,
    batch_size: u16,
    clone_policy: bool,
    signature_hook: Option<SignatureHook>,
}
#[derive(Clone)]
pub struct ArtifactRestorePlanFile {
    restore_id: String,
    source_root: PathBuf,
    inventory: PathBuf,
    source_store_id: ContentDigestV1,
    target_schema: String,
    target_store_id: ContentDigestV1,
    target_root: PathBuf,
    policy_digest: ContentDigestV1,
    actor_digest: ContentDigestV1,
    reason_digest: ContentDigestV1,
    batch_size: u16,
    clone_policy: bool,
    signature_hook: Option<SignatureHook>,
}
impl ArtifactRestorePlanFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let d: RestoreDocument = read_private_json(path.as_ref())?;
        if d.schema != "smesh-artifact-restore-plan/v1"
            || !valid_id(&d.restore_id)
            || !valid_schema(&d.target.schema)
            || d.source.store_id == d.target.store_id
            || d.actor.is_empty()
            || d.reason.is_empty()
            || !(1..=1000).contains(&d.batch_size)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        validate_private_root(&d.source.backup_root, false)?;
        if !d.source.inventory.is_absolute()
            || !d.source.inventory.starts_with(&d.source.backup_root)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        validate_private_root(&d.target.root, true)?;
        if let Some(h) = &d.signature_hook {
            h.validate()?
        }
        Ok(Self {
            restore_id: d.restore_id,
            source_root: d.source.backup_root,
            inventory: d.source.inventory,
            source_store_id: d.source.store_id,
            target_schema: d.target.schema,
            target_store_id: d.target.store_id,
            target_root: d.target.root,
            policy_digest: d.artifact_policy_digest,
            actor_digest: ContentDigestV1::of(d.actor.as_bytes()),
            reason_digest: ContentDigestV1::of(d.reason.as_bytes()),
            batch_size: d.batch_size,
            clone_policy: d.clone_policy,
            signature_hook: d.signature_hook,
        })
    }
    pub fn restore_id(&self) -> &str {
        &self.restore_id
    }
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
    pub fn inventory(&self) -> &Path {
        &self.inventory
    }
    pub const fn source_store_id(&self) -> ContentDigestV1 {
        self.source_store_id
    }
    pub fn target_schema(&self) -> &str {
        &self.target_schema
    }
    pub const fn target_store_id(&self) -> ContentDigestV1 {
        self.target_store_id
    }
    pub fn target_root(&self) -> &Path {
        &self.target_root
    }
    pub const fn policy_digest(&self) -> ContentDigestV1 {
        self.policy_digest
    }
    pub const fn actor_digest(&self) -> ContentDigestV1 {
        self.actor_digest
    }
    pub const fn reason_digest(&self) -> ContentDigestV1 {
        self.reason_digest
    }
    pub const fn batch_size(&self) -> u16 {
        self.batch_size
    }
    pub const fn clone_policy(&self) -> bool {
        self.clone_policy
    }
    pub fn signature_hook(&self) -> Option<&SignatureHook> {
        self.signature_hook.as_ref()
    }
}
impl fmt::Debug for ArtifactRestorePlanFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactRestorePlanFile")
            .field("restore_id", &self.restore_id)
            .field("source", &"<redacted>")
            .field("target_schema", &self.target_schema)
            .field("target", &"<redacted>")
            .field("actor", &"<redacted>")
            .field("reason", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationDocument {
    schema: String,
    rotation_id: String,
    source: Authority,
    encryption_domain: String,
    old_generation: String,
    new_generation: String,
    policy: Policy,
    actor: String,
    reason: String,
    effective_at: i64,
    batch_size: u16,
    lease_duration_millis: i64,
    rollback_horizon_millis: i64,
}
pub struct ArtifactKeyRotationPlanFile {
    plan: ArtifactKeyRotationPlan,
    source_schema: String,
    source_store_id: ContentDigestV1,
    policy_id: String,
    policy_revision: u64,
    policy_digest: ContentDigestV1,
    effective_at: i64,
    lease_duration_millis: i64,
    rollback_horizon_millis: i64,
}
impl ArtifactKeyRotationPlanFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let d: RotationDocument = read_private_json(path.as_ref())?;
        if d.schema != "smesh-artifact-key-rotation-plan/v1"
            || !valid_schema(&d.source.schema)
            || !valid_id(&d.policy.id)
            || d.policy.revision == 0
            || d.effective_at < 0
            || !(10..=86_400_000).contains(&d.lease_duration_millis)
            || !(0..=31_536_000_000).contains(&d.rollback_horizon_millis)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        let plan = ArtifactKeyRotationPlan::new(
            d.rotation_id,
            d.encryption_domain,
            d.old_generation,
            d.new_generation,
            d.actor,
            d.reason,
            d.batch_size,
        )?;
        Ok(Self {
            plan,
            source_schema: d.source.schema,
            source_store_id: d.source.store_id,
            policy_id: d.policy.id,
            policy_revision: d.policy.revision,
            policy_digest: d.policy.digest,
            effective_at: d.effective_at,
            lease_duration_millis: d.lease_duration_millis,
            rollback_horizon_millis: d.rollback_horizon_millis,
        })
    }
    pub const fn plan(&self) -> &ArtifactKeyRotationPlan {
        &self.plan
    }
    pub fn source_schema(&self) -> &str {
        &self.source_schema
    }
    pub const fn source_store_id(&self) -> ContentDigestV1 {
        self.source_store_id
    }
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub const fn policy_digest(&self) -> ContentDigestV1 {
        self.policy_digest
    }
    pub const fn effective_at(&self) -> i64 {
        self.effective_at
    }
    pub const fn lease_duration_millis(&self) -> i64 {
        self.lease_duration_millis
    }
    pub const fn rollback_horizon_millis(&self) -> i64 {
        self.rollback_horizon_millis
    }
}

fn valid_id(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control)
}
fn valid_schema(v: &str) -> bool {
    !v.is_empty() && v.len() <= 63 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn validate_private_root(path: &Path, must_be_empty: bool) -> Result<(), ArtifactStoreError> {
    if !path.is_absolute() {
        return Err(ArtifactStoreError::Invalid);
    }
    let m = std::fs::symlink_metadata(path).map_err(|_| ArtifactStoreError::Unavailable)?;
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(ArtifactStoreError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if m.uid() != rustix::process::getuid().as_raw() || m.permissions().mode() & 0o077 != 0 {
            return Err(ArtifactStoreError::Invalid);
        }
    }
    if must_be_empty
        && std::fs::read_dir(path)
            .map_err(|_| ArtifactStoreError::Unavailable)?
            .next()
            .is_some()
    {
        return Err(ArtifactStoreError::Conflict);
    }
    Ok(())
}
fn read_private_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, ArtifactStoreError> {
    if !path.is_absolute() {
        return Err(ArtifactStoreError::Invalid);
    }
    #[cfg(unix)]
    let mut f = File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ArtifactStoreError::Unavailable)?,
    );
    #[cfg(not(unix))]
    let mut f = File::open(path).map_err(|_| ArtifactStoreError::Unavailable)?;
    let m = f.metadata().map_err(|_| ArtifactStoreError::Unavailable)?;
    if !m.is_file() || m.len() == 0 || m.len() > 256 * 1024 {
        return Err(ArtifactStoreError::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if m.uid() != rustix::process::getuid().as_raw() || m.permissions().mode() & 0o077 != 0 {
            return Err(ArtifactStoreError::Invalid);
        }
    }
    let mut b =
        Vec::with_capacity(usize::try_from(m.len()).map_err(|_| ArtifactStoreError::Invalid)?);
    f.read_to_end(&mut b)
        .map_err(|_| ArtifactStoreError::Unavailable)?;
    serde_json::from_slice(&b).map_err(|_| ArtifactStoreError::Invalid)
}
