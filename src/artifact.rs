//! Backend-neutral content-addressed artifact contracts and a secure POSIX blob backend.
//!
//! PostgreSQL remains the production metadata authority. This module deliberately
//! separates opaque authorization IDs and semantic plaintext digests from private
//! ciphertext placement.
#![allow(clippy::missing_errors_doc)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::SystemTime;

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;

const DIGEST_PREFIX: &str = "sha256:";
const MANIFEST_DOMAIN: &[u8] = b"smesh-artifact-manifest/v1\0";
const STORED_DOMAIN: &[u8] = b"smesh-artifact-ciphertext/v1\0";
const BACKUP_INVENTORY_DOMAIN: &[u8] = b"smesh-artifact-backup-inventory/v1\0";
pub const ARTIFACT_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 255;
const MAX_DESCRIPTION_BYTES: usize = 4096;
const MAX_ID_BYTES: usize = 256;
const MAX_DERIVED_FROM: usize = 32;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const MAX_RETENTION_MILLIS: i64 = 10 * 366 * 24 * 60 * 60 * 1_000;
const MAX_LEASE_MILLIS: i64 = 24 * 60 * 60 * 1_000;

/// Explicit, digest-bound operator authorization for the external-I/O data
/// migration. Schema migration itself never performs blob I/O.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactMigrationPlan {
    plan_id: String,
    source_schema_version: u64,
    policy_id: String,
    policy_revision: u64,
    policy_digest: ContentDigestV1,
    actor_digest: ContentDigestV1,
    reason_digest: ContentDigestV1,
    batch_size: u16,
}

impl ArtifactMigrationPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        source_schema_version: u64,
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: ContentDigestV1,
        actor: impl AsRef<[u8]>,
        reason: impl AsRef<[u8]>,
        batch_size: u16,
    ) -> Result<Self, ArtifactStoreError> {
        let plan_id = plan_id.into();
        let policy_id = policy_id.into();
        validate_identity(&plan_id)?;
        validate_identity(&policy_id)?;
        if !matches!(source_schema_version, 4 | 5)
            || policy_revision == 0
            || !(1..=1000).contains(&batch_size)
            || actor.as_ref().is_empty()
            || reason.as_ref().is_empty()
        {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            plan_id,
            source_schema_version,
            policy_id,
            policy_revision,
            policy_digest,
            actor_digest: ContentDigestV1::of(actor.as_ref()),
            reason_digest: ContentDigestV1::of(reason.as_ref()),
            batch_size,
        })
    }
    #[must_use]
    pub const fn source_schema_version(&self) -> u64 {
        self.source_schema_version
    }
    #[must_use]
    pub const fn batch_size(&self) -> u16 {
        self.batch_size
    }
    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
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
    pub const fn policy_digest(&self) -> ContentDigestV1 {
        self.policy_digest
    }
    #[must_use]
    pub const fn actor_digest(&self) -> ContentDigestV1 {
        self.actor_digest
    }
    #[must_use]
    pub const fn reason_digest(&self) -> ContentDigestV1 {
        self.reason_digest
    }
}
impl fmt::Debug for ArtifactMigrationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactMigrationPlan")
            .field("plan_id", &self.plan_id)
            .field("source_schema_version", &self.source_schema_version)
            .field("policy_id", &self.policy_id)
            .field("policy_revision", &self.policy_revision)
            .field("policy_digest", &self.policy_digest)
            .field("actor_digest", &"<redacted>")
            .field("reason_digest", &"<redacted>")
            .field("batch_size", &self.batch_size)
            .finish()
    }
}

/// Server-only key-generation transition. Operator identity and reason are
/// persisted only as irreversible digests.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactKeyRotationPlan {
    plan_id: String,
    encryption_domain: String,
    old_generation: String,
    new_generation: String,
    actor_digest: ContentDigestV1,
    reason_digest: ContentDigestV1,
    batch_size: u16,
}
impl ArtifactKeyRotationPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        encryption_domain: impl Into<String>,
        old_generation: impl Into<String>,
        new_generation: impl Into<String>,
        actor: impl AsRef<[u8]>,
        reason: impl AsRef<[u8]>,
        batch_size: u16,
    ) -> Result<Self, ArtifactStoreError> {
        let (plan_id, encryption_domain, old_generation, new_generation) = (
            plan_id.into(),
            encryption_domain.into(),
            old_generation.into(),
            new_generation.into(),
        );
        for value in [
            &plan_id,
            &encryption_domain,
            &old_generation,
            &new_generation,
        ] {
            validate_identity(value)?;
        }
        if old_generation == new_generation
            || actor.as_ref().is_empty()
            || reason.as_ref().is_empty()
            || !(1..=1000).contains(&batch_size)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            plan_id,
            encryption_domain,
            old_generation,
            new_generation,
            actor_digest: ContentDigestV1::of(actor.as_ref()),
            reason_digest: ContentDigestV1::of(reason.as_ref()),
            batch_size,
        })
    }
    #[must_use]
    pub const fn batch_size(&self) -> u16 {
        self.batch_size
    }
    #[must_use]
    pub fn old_generation(&self) -> &str {
        &self.old_generation
    }
    #[must_use]
    pub fn new_generation(&self) -> &str {
        &self.new_generation
    }
    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    #[must_use]
    pub fn encryption_domain(&self) -> &str {
        &self.encryption_domain
    }
    #[must_use]
    pub const fn actor_digest(&self) -> ContentDigestV1 {
        self.actor_digest
    }
    #[must_use]
    pub const fn reason_digest(&self) -> ContentDigestV1 {
        self.reason_digest
    }
}
impl fmt::Debug for ArtifactKeyRotationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactKeyRotationPlan")
            .field("plan_id", &self.plan_id)
            .field("encryption_domain", &self.encryption_domain)
            .field("old_generation", &self.old_generation)
            .field("new_generation", &self.new_generation)
            .field("actor_digest", &"<redacted>")
            .field("reason_digest", &"<redacted>")
            .field("batch_size", &self.batch_size)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactBackupObject {
    tenant_scope: String,
    object_id: String,
    artifact_id: String,
    content_digest: ContentDigestV1,
    ciphertext_digest: ContentDigestV1,
    ciphertext_length: u64,
    key_generation: String,
    storage_locator: String,
}
impl ArtifactBackupObject {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_scope: impl Into<String>,
        object_id: impl Into<String>,
        artifact_id: impl Into<String>,
        content_digest: &str,
        ciphertext_digest: &str,
        ciphertext_length: u64,
        key_generation: impl Into<String>,
        storage_locator: impl Into<String>,
    ) -> Result<Self, ArtifactStoreError> {
        let (tenant_scope, object_id, artifact_id, key_generation, storage_locator) = (
            tenant_scope.into(),
            object_id.into(),
            artifact_id.into(),
            key_generation.into(),
            storage_locator.into(),
        );
        for value in [&tenant_scope, &object_id, &artifact_id, &key_generation] {
            validate_identity(value)?;
        }
        let locator = safe_join(Path::new("/inventory-root"), &storage_locator)?;
        if ciphertext_length < 16
            || !storage_locator.starts_with("objects/")
            || locator == Path::new("/inventory-root")
        {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            tenant_scope,
            object_id,
            artifact_id,
            content_digest: ContentDigestV1::parse(content_digest)?,
            ciphertext_digest: ContentDigestV1::parse(ciphertext_digest)?,
            ciphertext_length,
            key_generation,
            storage_locator,
        })
    }
    #[must_use]
    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalBackupInventory<'a> {
    schema: &'static str,
    backup_id: &'a str,
    store_id: &'a str,
    snapshot_id: &'a str,
    logical_schema_version: u64,
    policy_id: &'a str,
    policy_revision: u64,
    policy_digest: ContentDigestV1,
    snapshot_at: i64,
    objects: &'a [ArtifactBackupObject],
}

/// Canonical, sorted and domain-separated inventory. It intentionally contains
/// generation identifiers but never encryption key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactBackupInventory {
    backup_id: String,
    store_id: String,
    snapshot_id: String,
    logical_schema_version: u64,
    policy_id: String,
    policy_revision: u64,
    policy_digest: ContentDigestV1,
    snapshot_at: i64,
    objects: Vec<ArtifactBackupObject>,
    canonical_json: Option<String>,
    digest: Option<ContentDigestV1>,
}
impl ArtifactBackupInventory {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backup_id: impl Into<String>,
        store_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        logical_schema_version: u64,
        policy_id: impl Into<String>,
        policy_revision: u64,
        policy_digest: ContentDigestV1,
        snapshot_at: i64,
    ) -> Result<Self, ArtifactStoreError> {
        let (backup_id, store_id, snapshot_id, policy_id) = (
            backup_id.into(),
            store_id.into(),
            snapshot_id.into(),
            policy_id.into(),
        );
        for value in [&backup_id, &store_id, &snapshot_id, &policy_id] {
            validate_identity(value)?;
        }
        if logical_schema_version == 0 || policy_revision == 0 || snapshot_at <= 0 {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            backup_id,
            store_id,
            snapshot_id,
            logical_schema_version,
            policy_id,
            policy_revision,
            policy_digest,
            snapshot_at,
            objects: vec![],
            canonical_json: None,
            digest: None,
        })
    }
    pub fn push_object(&mut self, object: ArtifactBackupObject) -> Result<(), ArtifactStoreError> {
        if self.digest.is_some()
            || self.objects.iter().any(|entry| {
                entry.tenant_scope == object.tenant_scope && entry.object_id == object.object_id
            })
        {
            return Err(ArtifactStoreError::Conflict);
        }
        self.objects.push(object);
        Ok(())
    }
    pub fn seal(mut self) -> Result<Self, ArtifactStoreError> {
        self.objects.sort_by(|a, b| {
            (&a.tenant_scope, &a.object_id, &a.artifact_id).cmp(&(
                &b.tenant_scope,
                &b.object_id,
                &b.artifact_id,
            ))
        });
        let canonical = CanonicalBackupInventory {
            schema: "smesh-artifact-backup-inventory/v1",
            backup_id: &self.backup_id,
            store_id: &self.store_id,
            snapshot_id: &self.snapshot_id,
            logical_schema_version: self.logical_schema_version,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            policy_digest: self.policy_digest,
            snapshot_at: self.snapshot_at,
            objects: &self.objects,
        };
        let json = serde_json::to_string(&canonical).map_err(|_| ArtifactStoreError::Invalid)?;
        let mut input = Vec::with_capacity(BACKUP_INVENTORY_DOMAIN.len() + json.len());
        input.extend_from_slice(BACKUP_INVENTORY_DOMAIN);
        input.extend_from_slice(json.as_bytes());
        self.digest = Some(ContentDigestV1::of(&input));
        self.canonical_json = Some(json);
        Ok(self)
    }
    #[must_use]
    pub fn objects(&self) -> &[ArtifactBackupObject] {
        &self.objects
    }
    /// Return the domain-separated digest of a sealed inventory.
    ///
    /// # Panics
    /// Panics when called before [`Self::seal`].
    #[must_use]
    pub fn digest(&self) -> ContentDigestV1 {
        self.digest.expect("sealed backup inventory")
    }
    /// Return canonical JSON for a sealed inventory.
    ///
    /// # Panics
    /// Panics when called before [`Self::seal`].
    #[must_use]
    pub fn canonical_json(&self) -> &str {
        self.canonical_json
            .as_deref()
            .expect("sealed backup inventory")
    }
    /// Bytes supplied to an external HSM/signing hook; this crate never owns a signing key.
    #[must_use]
    pub fn signature_message(&self) -> Vec<u8> {
        let mut result = BACKUP_INVENTORY_DOMAIN.to_vec();
        result.extend_from_slice(self.digest().bytes());
        result
    }
}

/// Validated production artifact-store policy. Paths are intentionally omitted
/// from `Debug` to avoid disclosing private placement and keyring locations.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactStoreConfig {
    root: PathBuf,
    keyring_path: PathBuf,
    chunk_bytes: usize,
    max_artifact_bytes: u64,
    retention_millis: i64,
    read_lease_millis: i64,
    worker_batch: u32,
}

impl ArtifactStoreConfig {
    pub fn new(
        root: impl AsRef<Path>,
        keyring_path: impl AsRef<Path>,
    ) -> Result<Self, ArtifactStoreError> {
        let root = validate_absolute_posix_path(root.as_ref())?;
        let keyring_path = validate_absolute_posix_path(keyring_path.as_ref())?;
        if root == keyring_path {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            root,
            keyring_path,
            chunk_bytes: ARTIFACT_CHUNK_BYTES,
            max_artifact_bytes: 64 * 1024 * 1024,
            retention_millis: 30 * 24 * 60 * 60 * 1_000,
            read_lease_millis: 60_000,
            worker_batch: 100,
        })
    }

    pub fn with_limits(
        mut self,
        chunk_bytes: usize,
        max_artifact_bytes: u64,
        retention_millis: i64,
        read_lease_millis: i64,
        worker_batch: u32,
    ) -> Result<Self, ArtifactStoreError> {
        if chunk_bytes != ARTIFACT_CHUNK_BYTES
            || max_artifact_bytes < chunk_bytes as u64
            || max_artifact_bytes > MAX_ARTIFACT_BYTES
            || !(1..=MAX_RETENTION_MILLIS).contains(&retention_millis)
            || !(1..=MAX_LEASE_MILLIS).contains(&read_lease_millis)
            || !(1..=1000).contains(&worker_batch)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        self.chunk_bytes = chunk_bytes;
        self.max_artifact_bytes = max_artifact_bytes;
        self.retention_millis = retention_millis;
        self.read_lease_millis = read_lease_millis;
        self.worker_batch = worker_batch;
        Ok(self)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    #[must_use]
    pub fn keyring_path(&self) -> &Path {
        &self.keyring_path
    }
    #[must_use]
    pub const fn max_artifact_bytes(&self) -> u64 {
        self.max_artifact_bytes
    }
    #[must_use]
    pub const fn retention_millis(&self) -> i64 {
        self.retention_millis
    }
    #[must_use]
    pub const fn read_lease_millis(&self) -> i64 {
        self.read_lease_millis
    }
    #[must_use]
    pub const fn worker_batch(&self) -> u32 {
        self.worker_batch
    }
}

impl fmt::Debug for ArtifactStoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactStoreConfig")
            .field("root", &"<redacted>")
            .field("keyring_path", &"<redacted>")
            .field("chunk_bytes", &self.chunk_bytes)
            .field("max_artifact_bytes", &self.max_artifact_bytes)
            .field("retention_millis", &self.retention_millis)
            .field("read_lease_millis", &self.read_lease_millis)
            .field("worker_batch", &self.worker_batch)
            .finish()
    }
}

fn validate_absolute_posix_path(path: &Path) -> Result<PathBuf, ArtifactStoreError> {
    use std::path::Component;
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(path.to_path_buf())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactStoreError {
    #[error("artifact input is invalid")]
    Invalid,
    #[error("artifact authorization denied")]
    Denied,
    #[error("artifact storage is unavailable")]
    Unavailable,
    #[error("artifact integrity verification failed")]
    Integrity,
    #[error("artifact conflicts with immutable state")]
    Conflict,
    #[error("artifact content is retained")]
    Retained,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentDigestV1([u8; 32]);

impl ContentDigestV1 {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn parse(value: &str) -> Result<Self, ArtifactStoreError> {
        if value.len() != 71 || !value.starts_with(DIGEST_PREFIX) {
            return Err(ArtifactStoreError::Invalid);
        }
        let hex = &value[7..];
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ArtifactStoreError::Invalid);
        }
        let mut out = [0_u8; 32];
        for (index, pair) in hex.as_bytes().chunks(2).enumerate() {
            out[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(out))
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn nibble(value: u8) -> Result<u8, ArtifactStoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ArtifactStoreError::Invalid),
    }
}

impl fmt::Display for ContentDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(DIGEST_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl fmt::Debug for ContentDigestV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for ContentDigestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactClassification {
    Public,
    Internal,
    Confidential,
    Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptionDomain(String);
impl EncryptionDomain {
    pub fn new(value: impl Into<String>) -> Result<Self, ArtifactStoreError> {
        let value = value.into();
        validate_identity(&value)?;
        Ok(Self(value))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactProducer {
    tenant: String,
    owner: String,
    task: String,
    context: String,
    message: String,
    dispatch: String,
}
impl ArtifactProducer {
    pub fn new(
        tenant: impl Into<String>,
        owner: impl Into<String>,
        task: impl Into<String>,
        context: impl Into<String>,
        message: impl Into<String>,
        dispatch: impl Into<String>,
    ) -> Result<Self, ArtifactStoreError> {
        let value = Self {
            tenant: tenant.into(),
            owner: owner.into(),
            task: task.into(),
            context: context.into(),
            message: message.into(),
            dispatch: dispatch.into(),
        };
        for field in [
            &value.tenant,
            &value.owner,
            &value.task,
            &value.context,
            &value.message,
            &value.dispatch,
        ] {
            validate_identity(field)?;
        }
        Ok(value)
    }
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }
    #[must_use]
    pub fn task(&self) -> &str {
        &self.task
    }
    #[must_use]
    pub fn context(&self) -> &str {
        &self.context
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub fn dispatch(&self) -> &str {
        &self.dispatch
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedRelation {
    Transformation,
    Summary,
    Extraction,
    Redaction,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedFrom {
    relation: DerivedRelation,
    artifact_id: String,
}
impl DerivedFrom {
    pub fn new(
        relation: DerivedRelation,
        artifact_id: impl Into<String>,
    ) -> Result<Self, ArtifactStoreError> {
        let artifact_id = artifact_id.into();
        validate_identity(&artifact_id)?;
        Ok(Self {
            relation,
            artifact_id,
        })
    }
    #[must_use]
    pub const fn relation(&self) -> DerivedRelation {
        self.relation
    }
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactPolicySnapshot {
    policy_id: String,
    revision: u64,
    digest: ContentDigestV1,
    created_at: i64,
    retain_until: i64,
}
impl ArtifactPolicySnapshot {
    pub fn new(
        policy_id: impl Into<String>,
        revision: u64,
        digest: ContentDigestV1,
        created_at: i64,
        retain_until: i64,
    ) -> Result<Self, ArtifactStoreError> {
        let policy_id = policy_id.into();
        validate_identity(&policy_id)?;
        if revision == 0 || retain_until < created_at {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            policy_id,
            revision,
            digest,
            created_at,
            retain_until,
        })
    }
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub const fn digest(&self) -> ContentDigestV1 {
        self.digest
    }
    #[must_use]
    pub const fn created_at(&self) -> i64 {
        self.created_at
    }
    #[must_use]
    pub const fn retain_until(&self) -> i64 {
        self.retain_until
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactChunkV1 {
    ordinal: u32,
    offset: u64,
    length: u64,
    digest: ContentDigestV1,
}
impl ArtifactChunkV1 {
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }
    #[must_use]
    pub const fn digest(&self) -> ContentDigestV1 {
        self.digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalManifestV1<'a> {
    schema: &'static str,
    artifact_id: &'a str,
    name: &'a str,
    description: &'a Option<String>,
    media_type: &'a str,
    classification: ArtifactClassification,
    encryption_domain: &'a EncryptionDomain,
    producer: &'a ArtifactProducer,
    derived_from: &'a [DerivedFrom],
    policy: &'a ArtifactPolicySnapshot,
    content_digest: ContentDigestV1,
    plaintext_length: u64,
    chunks: &'a [ArtifactChunkV1],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactManifestV1 {
    artifact_id: String,
    name: String,
    description: Option<String>,
    media_type: String,
    classification: ArtifactClassification,
    encryption_domain: EncryptionDomain,
    key_generation: String,
    producer: ArtifactProducer,
    derived_from: Vec<DerivedFrom>,
    policy: ArtifactPolicySnapshot,
    content_digest: ContentDigestV1,
    plaintext_length: u64,
    chunks: Vec<ArtifactChunkV1>,
    canonical_json: String,
    manifest_digest: ContentDigestV1,
}
impl ArtifactManifestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_id: impl Into<String>,
        name: impl Into<String>,
        description: Option<String>,
        media_type: impl Into<String>,
        classification: ArtifactClassification,
        encryption_domain: EncryptionDomain,
        key_generation: impl Into<String>,
        producer: ArtifactProducer,
        mut derived_from: Vec<DerivedFrom>,
        policy: ArtifactPolicySnapshot,
        _created_at: i64,
        plaintext: &[u8],
    ) -> Result<Self, ArtifactStoreError> {
        let artifact_id = artifact_id.into();
        let name = name.into();
        let media_type = normalize_media_type(&media_type.into())?;
        let key_generation = key_generation.into();
        validate_identity(&artifact_id)?;
        validate_visible(&name, MAX_NAME_BYTES)?;
        validate_identity(&key_generation)?;
        if let Some(value) = &description {
            validate_visible(value, MAX_DESCRIPTION_BYTES)?;
        }
        if producer.tenant
            != encryption_domain
                .as_str()
                .split('/')
                .next()
                .unwrap_or_default()
        {
            return Err(ArtifactStoreError::Invalid);
        }
        if derived_from.len() > MAX_DERIVED_FROM {
            return Err(ArtifactStoreError::Invalid);
        }
        derived_from.sort();
        if derived_from.windows(2).any(|pair| pair[0] == pair[1])
            || derived_from
                .iter()
                .any(|edge| edge.artifact_id == artifact_id)
        {
            return Err(ArtifactStoreError::Invalid);
        }
        let content_digest = ContentDigestV1::of(plaintext);
        let plaintext_length =
            u64::try_from(plaintext.len()).map_err(|_| ArtifactStoreError::Invalid)?;
        let chunks = plaintext
            .chunks(ARTIFACT_CHUNK_BYTES)
            .enumerate()
            .map(|(ordinal, bytes)| {
                Ok(ArtifactChunkV1 {
                    ordinal: u32::try_from(ordinal).map_err(|_| ArtifactStoreError::Invalid)?,
                    offset: u64::try_from(ordinal)
                        .map_err(|_| ArtifactStoreError::Invalid)?
                        .checked_mul(ARTIFACT_CHUNK_BYTES as u64)
                        .ok_or(ArtifactStoreError::Invalid)?,
                    length: bytes.len() as u64,
                    digest: ContentDigestV1::of(bytes),
                })
            })
            .collect::<Result<Vec<_>, ArtifactStoreError>>()?;
        let mut result = Self {
            artifact_id,
            name,
            description,
            media_type,
            classification,
            encryption_domain,
            key_generation,
            producer,
            derived_from,
            policy,
            content_digest,
            plaintext_length,
            chunks,
            canonical_json: String::new(),
            manifest_digest: ContentDigestV1([0; 32]),
        };
        result.canonical_json =
            serde_json::to_string(&result.canonical()).map_err(|_| ArtifactStoreError::Invalid)?;
        let mut input = Vec::with_capacity(MANIFEST_DOMAIN.len() + result.canonical_json.len());
        input.extend_from_slice(MANIFEST_DOMAIN);
        input.extend_from_slice(result.canonical_json.as_bytes());
        result.manifest_digest = ContentDigestV1::of(&input);
        Ok(result)
    }
    fn canonical(&self) -> CanonicalManifestV1<'_> {
        CanonicalManifestV1 {
            schema: "smesh-artifact-manifest/v1",
            artifact_id: &self.artifact_id,
            name: &self.name,
            description: &self.description,
            media_type: &self.media_type,
            classification: self.classification,
            encryption_domain: &self.encryption_domain,
            producer: &self.producer,
            derived_from: &self.derived_from,
            policy: &self.policy,
            content_digest: self.content_digest,
            plaintext_length: self.plaintext_length,
            chunks: &self.chunks,
        }
    }
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
    #[must_use]
    pub fn key_generation(&self) -> &str {
        &self.key_generation
    }
    #[must_use]
    pub fn policy(&self) -> &ArtifactPolicySnapshot {
        &self.policy
    }
    #[must_use]
    pub fn chunks(&self) -> &[ArtifactChunkV1] {
        &self.chunks
    }
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigestV1 {
        self.content_digest
    }
    #[must_use]
    pub const fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }
    #[must_use]
    pub fn canonical_json(&self) -> &str {
        &self.canonical_json
    }
    #[must_use]
    pub const fn manifest_digest(&self) -> ContentDigestV1 {
        self.manifest_digest
    }
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    #[must_use]
    pub fn producer(&self) -> &ArtifactProducer {
        &self.producer
    }
    #[must_use]
    pub const fn classification(&self) -> ArtifactClassification {
        self.classification
    }
    #[must_use]
    pub fn encryption_domain(&self) -> &EncryptionDomain {
        &self.encryption_domain
    }
    #[must_use]
    pub fn derived_from(&self) -> &[DerivedFrom] {
        &self.derived_from
    }

    /// Build the public A2A presentation. It contains only immutable manifest
    /// facts and an authenticated relative resolver relation; never content,
    /// tenant/owner identity, key generation, domain, or backend placement.
    #[must_use]
    pub fn to_a2a_projection(&self) -> a2a::Artifact {
        let resolver = format!("/artifacts/v1/{}", self.artifact_id);
        let part = a2a::Part::data(serde_json::json!({
            "schema": "smesh-artifact-part/v1",
            "artifactId": self.artifact_id,
            "mediaType": self.media_type,
            "sizeBytes": self.plaintext_length,
            "contentDigest": self.content_digest.to_string(),
            "resolver": { "href": resolver, "authenticated": true, "methods": ["GET", "HEAD"] }
        }))
        .with_media_type("application/vnd.smesh.artifact-manifest+json");
        let mut metadata = HashMap::new();
        metadata.insert(
            "smeshArtifact".to_owned(),
            serde_json::json!({
                "schema": "smesh-artifact-projection/v1",
                "manifestDigest": self.manifest_digest.to_string(),
                "contentDigest": self.content_digest.to_string(),
                "sizeBytes": self.plaintext_length,
                "mediaType": self.media_type,
                "resolver": resolver
            }),
        );
        a2a::Artifact {
            artifact_id: self.artifact_id.clone(),
            name: Some(self.name.clone()),
            description: self.description.clone(),
            parts: vec![part],
            metadata: Some(metadata),
            extensions: Some(vec![
                "https://smesh.dev/extensions/artifact-manifest/v1".to_owned(),
            ]),
        }
    }
}

fn normalize_media_type(value: &str) -> Result<String, ArtifactStoreError> {
    let parsed: mime::Mime = value.parse().map_err(|_| ArtifactStoreError::Invalid)?;
    let normalized = parsed.to_string().to_ascii_lowercase();
    if normalized.len() > 255 || normalized.contains('\n') || normalized.contains('\r') {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(normalized)
}
fn validate_identity(value: &str) -> Result<(), ArtifactStoreError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(())
}
fn validate_visible(value: &str, max: usize) -> Result<(), ArtifactStoreError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(())
}

pub trait ArtifactKeyring: Send + Sync {
    fn active_generation(&self) -> String;
    fn key(&self, generation: &str) -> Result<[u8; 32], ArtifactStoreError>;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JsonKeyringDocument {
    active_generation: String,
    generations: BTreeMap<String, String>,
}

/// Strict owner-private JSON keyring. Rotation changes only the active
/// generation; old generations remain available for authenticated reads.
pub struct JsonArtifactKeyring {
    active_generation: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl JsonArtifactKeyring {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let path = path.as_ref();
        validate_absolute_posix_path(path)?;
        #[cfg(unix)]
        let mut file = File::from(
            rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?,
        );
        #[cfg(not(unix))]
        let mut file = File::open(path).map_err(|_| ArtifactStoreError::Unavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 256 * 1024 {
            return Err(ArtifactStoreError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            if metadata.uid() != rustix::process::getuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(ArtifactStoreError::Invalid);
            }
        }
        let capacity = usize::try_from(metadata.len()).map_err(|_| ArtifactStoreError::Invalid)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let document: JsonKeyringDocument =
            serde_json::from_slice(&bytes).map_err(|_| ArtifactStoreError::Invalid)?;
        validate_identity(&document.active_generation)?;
        if document.generations.is_empty() || document.generations.len() > 64 {
            return Err(ArtifactStoreError::Invalid);
        }
        let mut keys = BTreeMap::new();
        for (generation, encoded) in document.generations {
            validate_identity(&generation)?;
            let raw = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| ArtifactStoreError::Invalid)?;
            let key: [u8; 32] = raw.try_into().map_err(|_| ArtifactStoreError::Invalid)?;
            keys.insert(generation, key);
        }
        if !keys.contains_key(&document.active_generation) {
            return Err(ArtifactStoreError::Invalid);
        }
        Ok(Self {
            active_generation: document.active_generation,
            keys,
        })
    }

    #[must_use]
    pub fn active_generation(&self) -> &str {
        &self.active_generation
    }
}
impl ArtifactKeyring for JsonArtifactKeyring {
    fn active_generation(&self) -> String {
        self.active_generation.clone()
    }
    fn key(&self, generation: &str) -> Result<[u8; 32], ArtifactStoreError> {
        self.keys
            .get(generation)
            .copied()
            .ok_or(ArtifactStoreError::Unavailable)
    }
}
impl fmt::Debug for JsonArtifactKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonArtifactKeyring")
            .field("active_generation", &self.active_generation)
            .field("keys", &"<redacted>")
            .finish()
    }
}

/// Atomically published strict keyring snapshot. Failed reloads preserve the
/// previous coherent generation and never expose partially parsed material.
pub struct ReloadingArtifactKeyring {
    path: PathBuf,
    current: arc_swap::ArcSwap<JsonArtifactKeyring>,
}
impl ReloadingArtifactKeyring {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let path = validate_absolute_posix_path(path.as_ref())?;
        let current = Arc::new(JsonArtifactKeyring::open(&path)?);
        Ok(Self {
            path,
            current: arc_swap::ArcSwap::from(current),
        })
    }
    pub fn reload(&self) -> Result<(), ArtifactStoreError> {
        self.reload_if(|_| Ok(()))
    }
    pub fn reload_if(
        &self,
        validate: impl FnOnce(&dyn ArtifactKeyring) -> Result<(), ArtifactStoreError>,
    ) -> Result<(), ArtifactStoreError> {
        let replacement = Arc::new(JsonArtifactKeyring::open(&self.path)?);
        validate(replacement.as_ref())?;
        self.current.store(replacement);
        Ok(())
    }
}
impl ArtifactKeyring for ReloadingArtifactKeyring {
    fn active_generation(&self) -> String {
        self.current.load().active_generation.clone()
    }
    fn key(&self, generation: &str) -> Result<[u8; 32], ArtifactStoreError> {
        self.current.load().key(generation)
    }
}
impl fmt::Debug for ReloadingArtifactKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadingArtifactKeyring")
            .field("path", &"<redacted>")
            .field("active_generation", &self.active_generation())
            .field("keys", &"<redacted>")
            .finish()
    }
}

pub struct InMemoryKeyring {
    active_generation: String,
    keys: BTreeMap<String, [u8; 32]>,
}
impl InMemoryKeyring {
    pub fn new(generation: impl Into<String>, key: [u8; 32]) -> Result<Self, ArtifactStoreError> {
        let generation = generation.into();
        validate_identity(&generation)?;
        let mut keys = BTreeMap::new();
        keys.insert(generation.clone(), key);
        Ok(Self {
            active_generation: generation,
            keys,
        })
    }
}
impl ArtifactKeyring for InMemoryKeyring {
    fn active_generation(&self) -> String {
        self.active_generation.clone()
    }
    fn key(&self, generation: &str) -> Result<[u8; 32], ArtifactStoreError> {
        self.keys
            .get(generation)
            .copied()
            .ok_or(ArtifactStoreError::Unavailable)
    }
}
impl fmt::Debug for InMemoryKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InMemoryKeyring([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedArtifact {
    stage_name: String,
    shard: String,
    final_name: String,
    nonce: [u8; 12],
    ciphertext_digest: ContentDigestV1,
    ciphertext_length: u64,
    key_generation: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredArtifact {
    relative_path: String,
    nonce: [u8; 12],
    ciphertext_digest: ContentDigestV1,
    ciphertext_length: u64,
    key_generation: String,
}
pub(crate) struct ReencryptedArtifact {
    pub locator: String,
    pub stage_locator: String,
    pub nonce: [u8; 12],
    pub ciphertext_digest: String,
    pub ciphertext_length: u64,
}

pub(crate) fn reencryption_aad_seal(
    resolution: &crate::ArtifactReadLease,
    new_generation: &str,
) -> String {
    crate::content_digest(&reencryption_aad(resolution, new_generation))
}

fn reencryption_aad(resolution: &crate::ArtifactReadLease, new_generation: &str) -> Vec<u8> {
    format!(
        "smesh-artifact-aead/v1\0{}\0{}\0{}\0{}\0{}\0{}",
        resolution.tenant_scope,
        resolution.encryption_domain,
        resolution.classification,
        resolution.content_digest,
        resolution.plaintext_length,
        new_generation
    )
    .into_bytes()
}

pub struct PosixArtifactBlobStore {
    root: PathBuf,
    root_fd: OwnedFd,
    stage_fd: OwnedFd,
    objects_fd: OwnedFd,
    keyring: Arc<dyn ArtifactKeyring>,
    max_artifact_bytes: u64,
    lookups: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StageOrphanCleanup {
    pub deleted: usize,
    pub refunded_bytes: u64,
}

impl PosixArtifactBlobStore {
    pub fn open(
        root: impl AsRef<Path>,
        keyring: Arc<dyn ArtifactKeyring>,
    ) -> Result<Self, ArtifactStoreError> {
        Self::open_with_limit(root, keyring, MAX_ARTIFACT_BYTES)
    }

    /// Open the blob root with the validated production size policy.
    pub fn open_config(
        config: &ArtifactStoreConfig,
        keyring: Arc<dyn ArtifactKeyring>,
    ) -> Result<Self, ArtifactStoreError> {
        Self::open_with_limit(config.root(), keyring, config.max_artifact_bytes())
    }

    fn open_with_limit(
        root: impl AsRef<Path>,
        keyring: Arc<dyn ArtifactKeyring>,
        max_artifact_bytes: u64,
    ) -> Result<Self, ArtifactStoreError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ArtifactStoreError::Invalid);
        }
        let root_fd = rustix::fs::open(
            root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ArtifactStoreError::Unavailable)?;
        validate_private_dir_fd(&root_fd)?;
        let stage_fd = ensure_private_dir_at(&root_fd, "stage")?;
        let objects_fd = ensure_private_dir_at(&root_fd, "objects")?;
        rustix::fs::fsync(&root_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        Ok(Self {
            root: root.to_owned(),
            root_fd,
            stage_fd,
            objects_fd,
            keyring,
            max_artifact_bytes,
            lookups: AtomicUsize::new(0),
        })
    }
    pub(crate) fn active_key_generation(&self) -> String {
        self.keyring.active_generation()
    }

    pub(crate) fn root_path(&self) -> &Path {
        &self.root
    }

    fn validate_fixed_dirs(&self) -> Result<(), ArtifactStoreError> {
        validate_dir_binding(&self.root_fd, "stage", &self.stage_fd)?;
        validate_dir_binding(&self.root_fd, "objects", &self.objects_fd)
    }

    fn open_object_file(&self, locator: &str) -> Result<File, ArtifactStoreError> {
        self.validate_fixed_dirs()?;
        let (shard, name) = object_locator_parts(locator)?;
        let shard_fd = open_private_dir_at(&self.objects_fd, shard)?;
        open_regular_file_at(&shard_fd, name)
    }

    fn read_object_bytes(
        &self,
        locator: &str,
        expected: u64,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        let mut file = self.open_object_file(locator)?;
        let metadata = file
            .metadata()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if metadata.len() != expected || expected > self.max_artifact_bytes.saturating_add(16) {
            return Err(ArtifactStoreError::Integrity);
        }
        let capacity = usize::try_from(expected).map_err(|_| ArtifactStoreError::Integrity)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if bytes.len() as u64 != expected {
            return Err(ArtifactStoreError::Integrity);
        }
        Ok(bytes)
    }

    fn promote_stage_locator(
        &self,
        stage_locator: &str,
        object_locator: &str,
        existing_ok: bool,
    ) -> Result<(), ArtifactStoreError> {
        self.validate_fixed_dirs()?;
        let stage_name = stage_locator_name(stage_locator)?;
        let (shard, final_name) = object_locator_parts(object_locator)?;
        let shard_fd = open_private_dir_at(&self.objects_fd, shard)?;
        match rustix::fs::linkat(
            &self.stage_fd,
            stage_name,
            &shard_fd,
            final_name,
            rustix::fs::AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) if existing_ok => {}
            Err(rustix::io::Errno::EXIST) => return Err(ArtifactStoreError::Conflict),
            Err(_) => return Err(ArtifactStoreError::Unavailable),
        }
        match rustix::fs::unlinkat(&self.stage_fd, stage_name, rustix::fs::AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(ArtifactStoreError::Unavailable),
        }
        rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable)
    }

    /// Verify a production resolution completely, then atomically copy its
    /// immutable ciphertext into a private backup CAS without following links.
    pub(crate) fn backup_verified(
        &self,
        resolution: &crate::ArtifactReadLease,
        backup_root: &Path,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        let plaintext = self.read_resolution(resolution)?;
        let bytes =
            self.read_object_bytes(&resolution.backend_locator, resolution.ciphertext_length)?;
        if stored_digest(&bytes).to_string() != resolution.ciphertext_digest {
            return Err(ArtifactStoreError::Integrity);
        }
        let backup_fd = rustix::fs::open(
            backup_root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| ArtifactStoreError::Unavailable)?;
        validate_private_dir_fd(&backup_fd)?;
        let objects_fd = ensure_private_dir_at(&backup_fd, "objects")?;
        let (shard, name) = object_locator_parts(&resolution.backend_locator)?;
        let shard_fd = ensure_private_dir_at(&objects_fd, shard)?;
        if let Ok(mut existing) = open_regular_file_at(&shard_fd, name) {
            let mut old = Vec::new();
            existing
                .read_to_end(&mut old)
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            return if old == bytes {
                Ok(plaintext)
            } else {
                Err(ArtifactStoreError::Conflict)
            };
        }
        let temporary = format!(".backup-{:032x}.tmp", rand::random::<u128>());
        let mut file = create_private_file_at(&shard_fd, &temporary)?;
        file.write_all(&bytes)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        file.sync_all()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::linkat(
            &shard_fd,
            temporary.as_str(),
            &shard_fd,
            name,
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                ArtifactStoreError::Conflict
            } else {
                ArtifactStoreError::Unavailable
            }
        })?;
        rustix::fs::unlinkat(&shard_fd, temporary.as_str(), rustix::fs::AtFlags::empty())
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&objects_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&backup_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        Ok(plaintext)
    }

    pub(crate) fn reencrypt_verified(
        &self,
        resolution: &crate::ArtifactReadLease,
        new_generation: &str,
    ) -> Result<ReencryptedArtifact, ArtifactStoreError> {
        validate_identity(new_generation)?;
        let plaintext = self.read_resolution(resolution)?;
        let key = self.keyring.key(new_generation)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| ArtifactStoreError::Unavailable)?;
        let nonce: [u8; 12] = rand::random();
        let aad = reencryption_aad(resolution, new_generation);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let generation = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
        self.validate_fixed_dirs()?;
        let shard = &crate::content_digest(
            format!("{}\0{}", resolution.tenant_scope, resolution.content_digest).as_bytes(),
        )[7..9];
        let shard_fd = ensure_private_dir_at(&self.objects_fd, shard)?;
        let locator = format!("objects/{shard}/{generation}");
        let stage_name = format!("{generation}.tmp");
        let mut file = create_private_file_at(&self.stage_fd, &stage_name)?;
        file.write_all(&ciphertext)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        file.sync_all()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        Ok(ReencryptedArtifact {
            locator,
            stage_locator: format!("stage/{stage_name}"),
            nonce,
            ciphertext_digest: stored_digest(&ciphertext).to_string(),
            ciphertext_length: ciphertext.len() as u64,
        })
    }

    pub(crate) fn promote_reencrypted(
        &self,
        staged: &ReencryptedArtifact,
    ) -> Result<(), ArtifactStoreError> {
        // A crash may occur after link+unlink but before the promoted state is
        // acknowledged. Authenticate the registered final object first so the
        // exact same ciphertext resumes without requiring the vanished stage.
        if let Ok(bytes) = self.read_object_bytes(&staged.locator, staged.ciphertext_length) {
            if stored_digest(&bytes).to_string() != staged.ciphertext_digest {
                return Err(ArtifactStoreError::Integrity);
            }
            let stage_name = stage_locator_name(&staged.stage_locator)?;
            match rustix::fs::unlinkat(&self.stage_fd, stage_name, rustix::fs::AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(ArtifactStoreError::Unavailable),
            }
            rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
            return Ok(());
        }
        self.promote_stage_locator(&staged.stage_locator, &staged.locator, true)?;
        let bytes = self.read_object_bytes(&staged.locator, staged.ciphertext_length)?;
        if bytes.len() as u64 != staged.ciphertext_length
            || stored_digest(&bytes).to_string() != staged.ciphertext_digest
        {
            return Err(ArtifactStoreError::Integrity);
        }
        Ok(())
    }

    /// Authenticate the exact promoted replacement before any durable metadata
    /// can name it as authoritative.
    pub(crate) fn verify_reencrypted(
        &self,
        resolution: &crate::ArtifactReadLease,
        new_generation: &str,
        promoted: &ReencryptedArtifact,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        validate_identity(new_generation)?;
        verify_resolution_manifest(resolution)?;
        let ciphertext = self.read_object_bytes(&promoted.locator, promoted.ciphertext_length)?;
        if stored_digest(&ciphertext).to_string() != promoted.ciphertext_digest {
            return Err(ArtifactStoreError::Integrity);
        }
        let key = self.keyring.key(new_generation)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| ArtifactStoreError::Unavailable)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&promoted.nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &reencryption_aad(resolution, new_generation),
                },
            )
            .map_err(|_| ArtifactStoreError::Integrity)?;
        if plaintext.len() as u64 != resolution.plaintext_length
            || ContentDigestV1::of(&plaintext).to_string() != resolution.content_digest
        {
            return Err(ArtifactStoreError::Integrity);
        }
        Ok(plaintext)
    }

    pub(crate) fn stage_registration(
        &self,
        mut registration: crate::ArtifactStageRegistration,
        plaintext: &[u8],
    ) -> Result<crate::ArtifactStageRegistration, ArtifactStoreError> {
        if plaintext.len() as u64 > self.max_artifact_bytes
            || registration.plaintext_length != plaintext.len() as u64
            || ContentDigestV1::parse(&registration.content_digest)?
                != ContentDigestV1::of(plaintext)
            || !registration
                .encryption_domain
                .starts_with(&format!("{}/", registration.tenant_scope))
            || registration.receiver_lease_epoch == 0
            || registration.receiver_lease_token.is_empty()
        {
            return Err(ArtifactStoreError::Invalid);
        }
        let key = self.keyring.key(&registration.key_generation)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| ArtifactStoreError::Unavailable)?;
        let nonce: [u8; 12] = rand::random();
        let aad = registration_aad(&registration);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let mut scope = Sha256::new();
        scope.update(registration.tenant_scope.as_bytes());
        scope.update([0]);
        scope.update(registration.encryption_domain.as_bytes());
        scope.update([0]);
        scope.update(registration.classification.as_bytes());
        scope.update([0]);
        scope.update(registration.content_digest.as_bytes());
        let scope = URL_SAFE_NO_PAD.encode(scope.finalize());
        self.validate_fixed_dirs()?;
        let shard = scope[..2].to_owned();
        let shard_fd = ensure_private_dir_at(&self.objects_fd, &shard)?;
        let generation = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
        registration.stage_locator = format!("stage/{generation}.tmp");
        registration.final_locator = format!("objects/{shard}/{generation}");
        let mut file = create_private_file_at(&self.stage_fd, &format!("{generation}.tmp"))?;
        file.write_all(&ciphertext)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        file.sync_all()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        registration.nonce = nonce;
        registration.ciphertext_digest = stored_digest(&ciphertext).to_string();
        registration.ciphertext_length = ciphertext.len() as u64;
        Ok(registration)
    }

    pub(crate) fn delete_locator(&self, locator: &str) -> Result<(), ArtifactStoreError> {
        self.validate_fixed_dirs()?;
        let (shard, name) = object_locator_parts(locator)?;
        let shard_fd = open_private_dir_at(&self.objects_fd, shard)?;
        match rustix::fs::unlinkat(&shard_fd, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(_) => Err(ArtifactStoreError::Unavailable),
        }
    }

    pub(crate) fn stage_orphan_candidates(
        &self,
        older_than: SystemTime,
        batch: usize,
    ) -> Result<Vec<(String, u64)>, ArtifactStoreError> {
        if !(1..=1000).contains(&batch) {
            return Err(ArtifactStoreError::Invalid);
        }
        self.validate_fixed_dirs()?;
        let mut candidates = scan_stage_candidates(&self.stage_fd, older_than)?;
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates.truncate(batch);
        Ok(candidates)
    }

    pub(crate) fn delete_stage_orphan(&self, locator: &str) -> Result<bool, ArtifactStoreError> {
        self.validate_fixed_dirs()?;
        let name = stage_locator_name(locator)?;
        let stat =
            match rustix::fs::statat(&self.stage_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                Ok(value) => value,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(_) => return Err(ArtifactStoreError::Unavailable),
            };
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() != 0o600
            || stat.st_uid != rustix::process::getuid().as_raw()
        {
            return Err(ArtifactStoreError::Invalid);
        }
        rustix::fs::unlinkat(&self.stage_fd, name, rustix::fs::AtFlags::empty())
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        Ok(true)
    }

    /// Delete a bounded set of old, unreferenced server-generated stage files.
    pub fn cleanup_stage_orphans(
        &self,
        live_stage_locators: &BTreeSet<String>,
        older_than: SystemTime,
        batch: usize,
    ) -> Result<StageOrphanCleanup, ArtifactStoreError> {
        if !(1..=1000).contains(&batch) {
            return Err(ArtifactStoreError::Invalid);
        }
        self.validate_fixed_dirs()?;
        let mut candidates = scan_stage_candidates(&self.stage_fd, older_than)?;
        candidates.retain(|(locator, _)| !live_stage_locators.contains(locator));
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let mut result = StageOrphanCleanup::default();
        for (locator, bytes) in candidates.into_iter().take(batch) {
            let name = stage_locator_name(&locator)?;
            match rustix::fs::unlinkat(&self.stage_fd, name, rustix::fs::AtFlags::empty()) {
                Ok(()) => {
                    result.deleted += 1;
                    result.refunded_bytes = result
                        .refunded_bytes
                        .checked_add(bytes)
                        .ok_or(ArtifactStoreError::Unavailable)?;
                }
                Err(rustix::io::Errno::NOENT) => {}
                Err(_) => return Err(ArtifactStoreError::Unavailable),
            }
        }
        if result.deleted != 0 {
            rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        }
        Ok(result)
    }

    pub(crate) fn promote_claim(
        &self,
        claim: &crate::ArtifactPromotionClaim,
    ) -> Result<(), ArtifactStoreError> {
        self.promote_stage_locator(&claim.stage_locator, &claim.final_locator, true)?;
        let bytes = self.read_object_bytes(&claim.final_locator, claim.ciphertext_length)?;
        if bytes.len() as u64 != claim.ciphertext_length
            || stored_digest(&bytes).to_string() != claim.ciphertext_digest
        {
            return Err(ArtifactStoreError::Integrity);
        }
        Ok(())
    }

    pub(crate) fn read_resolution(
        &self,
        resolution: &crate::ArtifactReadLease,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        verify_resolution_manifest(resolution)?;
        let ciphertext =
            self.read_object_bytes(&resolution.backend_locator, resolution.ciphertext_length)?;
        if ciphertext.len() as u64 != resolution.ciphertext_length
            || stored_digest(&ciphertext).to_string() != resolution.ciphertext_digest
        {
            return Err(ArtifactStoreError::Integrity);
        }
        let key = self.keyring.key(&resolution.key_generation)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| ArtifactStoreError::Unavailable)?;
        let aad = resolution_aad(resolution);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&resolution.nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArtifactStoreError::Integrity)?;
        if plaintext.len() as u64 != resolution.plaintext_length
            || ContentDigestV1::of(&plaintext).to_string() != resolution.content_digest
        {
            return Err(ArtifactStoreError::Integrity);
        }
        Ok(plaintext)
    }

    pub fn stage(
        &self,
        manifest: &ArtifactManifestV1,
        plaintext: &[u8],
    ) -> Result<StagedArtifact, ArtifactStoreError> {
        if plaintext.len() as u64 > self.max_artifact_bytes {
            return Err(ArtifactStoreError::Invalid);
        }
        verify_plaintext(manifest, plaintext)?;
        let key = self.keyring.key(&manifest.key_generation)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| ArtifactStoreError::Unavailable)?;
        let nonce: [u8; 12] = rand::random();
        let aad = aad(manifest);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        self.validate_fixed_dirs()?;
        let scope = scope_key(manifest);
        let shard = scope[..2].to_owned();
        let shard_fd = ensure_private_dir_at(&self.objects_fd, &shard)?;
        let generation = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
        let stage_name = format!("{generation}.tmp");
        let mut file = create_private_file_at(&self.stage_fd, &stage_name)?;
        file.write_all(&ciphertext)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        file.sync_all()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        Ok(StagedArtifact {
            stage_name,
            shard,
            final_name: generation,
            nonce,
            ciphertext_digest: stored_digest(&ciphertext),
            ciphertext_length: ciphertext.len() as u64,
            key_generation: manifest.key_generation.clone(),
        })
    }
    pub fn promote(&self, staged: StagedArtifact) -> Result<StoredArtifact, ArtifactStoreError> {
        self.validate_fixed_dirs()?;
        let shard_fd = ensure_private_dir_at(&self.objects_fd, &staged.shard)?;
        rustix::fs::linkat(
            &self.stage_fd,
            staged.stage_name.as_str(),
            &shard_fd,
            staged.final_name.as_str(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::EXIST {
                ArtifactStoreError::Conflict
            } else {
                ArtifactStoreError::Unavailable
            }
        })?;
        rustix::fs::unlinkat(
            &self.stage_fd,
            staged.stage_name.as_str(),
            rustix::fs::AtFlags::empty(),
        )
        .map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&self.stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        rustix::fs::fsync(&shard_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
        let relative_path = format!("objects/{}/{}", staged.shard, staged.final_name);
        Ok(StoredArtifact {
            relative_path,
            nonce: staged.nonce,
            ciphertext_digest: staged.ciphertext_digest,
            ciphertext_length: staged.ciphertext_length,
            key_generation: staged.key_generation,
        })
    }
    pub fn read_verified(
        &self,
        manifest: &ArtifactManifestV1,
        object: &StoredArtifact,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        if object.key_generation != manifest.key_generation {
            return Err(ArtifactStoreError::Integrity);
        }
        let mut file = self.open_object_file(&object.relative_path)?;
        let metadata = file
            .metadata()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if !metadata.is_file() || metadata.len() != object.ciphertext_length {
            return Err(ArtifactStoreError::Integrity);
        }
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| ArtifactStoreError::Integrity)?;
        let mut ciphertext = Vec::with_capacity(capacity);
        file.read_to_end(&mut ciphertext)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if stored_digest(&ciphertext)
            .0
            .ct_eq(&object.ciphertext_digest.0)
            .unwrap_u8()
            != 1
        {
            return Err(ArtifactStoreError::Integrity);
        }
        let key = self.keyring.key(&object.key_generation)?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| ArtifactStoreError::Unavailable)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&object.nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(manifest),
                },
            )
            .map_err(|_| ArtifactStoreError::Integrity)?;
        verify_plaintext(manifest, &plaintext)?;
        Ok(plaintext)
    }
    fn delete(&self, object: &StoredArtifact) -> Result<(), ArtifactStoreError> {
        self.delete_locator(&object.relative_path)
    }
    #[doc(hidden)]
    #[must_use]
    pub fn debug_object_path(&self, object: &StoredArtifact) -> PathBuf {
        self.root.join(&object.relative_path)
    }
    #[must_use]
    pub fn lookup_count(&self) -> usize {
        self.lookups.load(Ordering::Relaxed)
    }
}

fn validate_private_dir_fd(fd: &OwnedFd) -> Result<(), ArtifactStoreError> {
    let stat = rustix::fs::fstat(fd).map_err(|_| ArtifactStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() & 0o077 != 0
        || stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(())
}

fn open_private_dir_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, ArtifactStoreError> {
    let fd = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ArtifactStoreError::Unavailable)?;
    validate_private_dir_fd(&fd)?;
    Ok(fd)
}

fn ensure_private_dir_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, ArtifactStoreError> {
    match rustix::fs::mkdirat(
        parent,
        name,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(ArtifactStoreError::Unavailable),
    }
    open_private_dir_at(parent, name)
}

fn validate_dir_binding(
    parent: &OwnedFd,
    name: &str,
    held: &OwnedFd,
) -> Result<(), ArtifactStoreError> {
    let current = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ArtifactStoreError::Unavailable)?;
    let expected = rustix::fs::fstat(held).map_err(|_| ArtifactStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(current.st_mode) != rustix::fs::FileType::Directory
        || current.st_dev != expected.st_dev
        || current.st_ino != expected.st_ino
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(())
}

fn create_private_file_at(parent: &OwnedFd, name: &str) -> Result<File, ArtifactStoreError> {
    let fd = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(|_| ArtifactStoreError::Unavailable)?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| ArtifactStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() != 0o600
        || stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(File::from(fd))
}

fn open_regular_file_at(parent: &OwnedFd, name: &str) -> Result<File, ArtifactStoreError> {
    let fd = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ArtifactStoreError::Unavailable)?;
    let stat = rustix::fs::fstat(&fd).map_err(|_| ArtifactStoreError::Unavailable)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() != 0o600
        || stat.st_uid != rustix::process::getuid().as_raw()
    {
        return Err(ArtifactStoreError::Integrity);
    }
    Ok(File::from(fd))
}

fn scan_stage_candidates(
    stage_fd: &OwnedFd,
    older_than: SystemTime,
) -> Result<Vec<(String, u64)>, ArtifactStoreError> {
    let mut directory =
        rustix::fs::Dir::read_from(stage_fd).map_err(|_| ArtifactStoreError::Unavailable)?;
    let mut candidates = Vec::new();
    for entry in &mut directory {
        let entry = entry.map_err(|_| ArtifactStoreError::Unavailable)?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if stage_locator_name(&format!("stage/{name}")).is_err() {
            continue;
        }
        let stat = match rustix::fs::statat(stage_fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(value) => value,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(_) => return Err(ArtifactStoreError::Unavailable),
        };
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || rustix::fs::Mode::from_raw_mode(stat.st_mode).bits() != 0o600
            || stat.st_uid != rustix::process::getuid().as_raw()
            || stat.st_mtime < 0
        {
            continue;
        }
        let modified = SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::new(
                u64::try_from(stat.st_mtime).map_err(|_| ArtifactStoreError::Unavailable)?,
                u32::try_from(stat.st_mtime_nsec).map_err(|_| ArtifactStoreError::Unavailable)?,
            ))
            .ok_or(ArtifactStoreError::Unavailable)?;
        if modified < older_than {
            candidates.push((
                format!("stage/{name}"),
                u64::try_from(stat.st_size).map_err(|_| ArtifactStoreError::Unavailable)?,
            ));
        }
    }
    Ok(candidates)
}

#[allow(clippy::case_sensitive_file_extension_comparisons)] // Canonical locator grammar rejects `.TMP`.
fn stage_locator_name(locator: &str) -> Result<&str, ArtifactStoreError> {
    let mut parts = locator.split('/');
    let (Some("stage"), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ArtifactStoreError::Invalid);
    };
    if name.len() != 36
        || !name.ends_with(".tmp")
        || !name[..32]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(name)
}

fn object_locator_parts(locator: &str) -> Result<(&str, &str), ArtifactStoreError> {
    let mut parts = locator.split('/');
    let (Some("objects"), Some(shard), Some(name), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ArtifactStoreError::Invalid);
    };
    if shard.len() != 2
        || name.is_empty()
        || name.len() > 255
        || !shard
            .bytes()
            .chain(name.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok((shard, name))
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, ArtifactStoreError> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(root.join(relative))
}
fn scope_key(manifest: &ArtifactManifestV1) -> String {
    let mut hash = Sha256::new();
    hash.update(manifest.producer.tenant.as_bytes());
    hash.update([0]);
    hash.update(manifest.encryption_domain.0.as_bytes());
    hash.update([0]);
    hash.update(format!("{:?}", manifest.classification).as_bytes());
    hash.update(manifest.content_digest.0);
    URL_SAFE_NO_PAD.encode(hash.finalize())
}
fn registration_aad(value: &crate::ArtifactStageRegistration) -> Vec<u8> {
    format!(
        "smesh-artifact-aead/v1\0{}\0{}\0{}\0{}\0{}\0{}",
        value.tenant_scope,
        value.encryption_domain,
        value.classification,
        value.content_digest,
        value.plaintext_length,
        value.key_generation
    )
    .into_bytes()
}

fn resolution_aad(value: &crate::ArtifactReadLease) -> Vec<u8> {
    format!(
        "smesh-artifact-aead/v1\0{}\0{}\0{}\0{}\0{}\0{}",
        value.tenant_scope,
        value.encryption_domain,
        value.classification,
        value.content_digest,
        value.plaintext_length,
        value.key_generation
    )
    .into_bytes()
}

fn verify_resolution_manifest(value: &crate::ArtifactReadLease) -> Result<(), ArtifactStoreError> {
    let canonical: serde_json::Value = serde_json::from_str(&value.canonical_manifest_json)
        .map_err(|_| ArtifactStoreError::Integrity)?;
    let mut digest_input =
        Vec::with_capacity(MANIFEST_DOMAIN.len() + value.canonical_manifest_json.len());
    digest_input.extend_from_slice(MANIFEST_DOMAIN);
    digest_input.extend_from_slice(value.canonical_manifest_json.as_bytes());
    let expected_manifest = ContentDigestV1::of(&digest_input);
    let stored_manifest = ContentDigestV1::parse(&value.manifest_digest)
        .map_err(|_| ArtifactStoreError::Integrity)?;
    let expected_content =
        ContentDigestV1::parse(&value.content_digest).map_err(|_| ArtifactStoreError::Integrity)?;
    let canonical_content = canonical
        .get("contentDigest")
        .and_then(serde_json::Value::as_str)
        .and_then(|digest| ContentDigestV1::parse(digest).ok())
        .ok_or(ArtifactStoreError::Integrity)?;
    if expected_manifest
        .bytes()
        .ct_eq(stored_manifest.bytes())
        .unwrap_u8()
        != 1
        || expected_content
            .bytes()
            .ct_eq(canonical_content.bytes())
            .unwrap_u8()
            != 1
        || canonical.get("schema").and_then(serde_json::Value::as_str)
            != Some("smesh-artifact-manifest/v1")
        || canonical
            .get("artifactId")
            .and_then(serde_json::Value::as_str)
            != Some(value.artifact_id.as_str())
        || canonical
            .get("mediaType")
            .and_then(serde_json::Value::as_str)
            != Some(value.media_type.as_str())
        || canonical
            .get("plaintextLength")
            .and_then(serde_json::Value::as_u64)
            != Some(value.plaintext_length)
        || canonical
            .get("encryptionDomain")
            .and_then(serde_json::Value::as_str)
            != Some(value.encryption_domain.as_str())
        || canonical
            .get("classification")
            .and_then(serde_json::Value::as_str)
            != Some(value.classification.as_str())
    {
        return Err(ArtifactStoreError::Integrity);
    }
    Ok(())
}

fn classification_name(classification: ArtifactClassification) -> &'static str {
    match classification {
        ArtifactClassification::Public => "public",
        ArtifactClassification::Internal => "internal",
        ArtifactClassification::Confidential => "confidential",
        ArtifactClassification::Secret => "secret",
    }
}

fn aad(manifest: &ArtifactManifestV1) -> Vec<u8> {
    format!(
        "smesh-artifact-aead/v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        manifest.producer.tenant,
        manifest.producer.owner,
        manifest.encryption_domain.0,
        classification_name(manifest.classification),
        manifest.content_digest,
        manifest.plaintext_length,
        manifest.key_generation
    )
    .into_bytes()
}
fn stored_digest(bytes: &[u8]) -> ContentDigestV1 {
    let mut hash = Sha256::new();
    hash.update(STORED_DOMAIN);
    hash.update(bytes);
    ContentDigestV1(hash.finalize().into())
}
fn verify_plaintext(manifest: &ArtifactManifestV1, bytes: &[u8]) -> Result<(), ArtifactStoreError> {
    if bytes.len() as u64 != manifest.plaintext_length
        || ContentDigestV1::of(bytes)
            .0
            .ct_eq(&manifest.content_digest.0)
            .unwrap_u8()
            != 1
    {
        Err(ArtifactStoreError::Integrity)
    } else {
        Ok(())
    }
}

#[derive(Clone)]
struct CatalogEntry {
    manifest: ArtifactManifestV1,
    object: StoredArtifact,
    reference_live: bool,
    tombstoned: bool,
    holds: BTreeSet<String>,
    leases: BTreeMap<String, i64>,
    deletion_fence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionDecision {
    Live,
    Held,
    Deleted,
}
#[derive(Default)]
struct CatalogState {
    entries: BTreeMap<(String, String), CatalogEntry>,
}
pub struct ArtifactCatalog {
    store: Arc<PosixArtifactBlobStore>,
    state: Mutex<CatalogState>,
}
impl ArtifactCatalog {
    #[must_use]
    pub fn new(store: Arc<PosixArtifactBlobStore>) -> Self {
        Self {
            store,
            state: Mutex::new(CatalogState::default()),
        }
    }

    /// Count distinct physical generations tracked by this catalog.
    #[must_use]
    pub fn physical_object_count(&self) -> usize {
        self.state.lock().map_or(0, |state| {
            state
                .entries
                .values()
                .map(|entry| entry.object.relative_path.as_str())
                .collect::<BTreeSet<_>>()
                .len()
        })
    }
    pub fn publish(
        &self,
        manifest: ArtifactManifestV1,
        bytes: &[u8],
    ) -> Result<(), ArtifactStoreError> {
        verify_plaintext(&manifest, bytes)?;
        let key = (
            manifest.producer.tenant.clone(),
            manifest.artifact_id.clone(),
        );
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        if let Some(existing) = state.entries.get(&key) {
            return if existing.manifest.manifest_digest == manifest.manifest_digest {
                Ok(())
            } else {
                Err(ArtifactStoreError::Conflict)
            };
        }
        for edge in &manifest.derived_from {
            let parent = state
                .entries
                .get(&(manifest.producer.tenant.clone(), edge.artifact_id.clone()))
                .ok_or(ArtifactStoreError::Denied)?;
            if parent.tombstoned
                || parent.manifest.classification > manifest.classification
                || parent.manifest.encryption_domain != manifest.encryption_domain
            {
                return Err(ArtifactStoreError::Denied);
            }
        }
        let object = if let Some(existing) = state.entries.values().find(|entry| {
            !entry.tombstoned
                && entry.manifest.producer.tenant == manifest.producer.tenant
                && entry.manifest.producer.owner == manifest.producer.owner
                && entry.manifest.content_digest == manifest.content_digest
                && entry.manifest.classification == manifest.classification
                && entry.manifest.encryption_domain == manifest.encryption_domain
                && entry.manifest.key_generation == manifest.key_generation
        }) {
            existing.object.clone()
        } else {
            let staged = self.store.stage(&manifest, bytes)?;
            self.store.promote(staged)?
        };
        state.entries.insert(
            key,
            CatalogEntry {
                manifest,
                object,
                reference_live: true,
                tombstoned: false,
                holds: BTreeSet::new(),
                leases: BTreeMap::new(),
                deletion_fence: 0,
            },
        );
        Ok(())
    }
    pub fn resolve(
        &self,
        tenant: &str,
        owner: &str,
        task: &str,
        artifact_id: &str,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        let (manifest, object) = {
            let state = self
                .state
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let entry = state
                .entries
                .get(&(tenant.to_owned(), artifact_id.to_owned()))
                .filter(|entry| {
                    !entry.tombstoned
                        && entry.reference_live
                        && entry.manifest.producer.owner == owner
                        && entry.manifest.producer.task == task
                })
                .ok_or(ArtifactStoreError::Denied)?;
            (entry.manifest.clone(), entry.object.clone())
        };
        self.store.read_verified(&manifest, &object)
    }
    pub fn acquire_read_lease(
        &self,
        tenant: &str,
        owner: &str,
        task: &str,
        artifact_id: &str,
        now: i64,
        ttl: i64,
    ) -> Result<String, ArtifactStoreError> {
        if ttl <= 0 {
            return Err(ArtifactStoreError::Invalid);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let entry = authorized_entry_mut(&mut state, tenant, owner, task, artifact_id)?;
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
        entry.leases.insert(
            token.clone(),
            now.checked_add(ttl).ok_or(ArtifactStoreError::Invalid)?,
        );
        Ok(token)
    }
    pub fn release_read_lease(&self, token: &str) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        for entry in state.entries.values_mut() {
            if entry.leases.remove(token).is_some() {
                return Ok(());
            }
        }
        Err(ArtifactStoreError::Denied)
    }
    pub fn place_legal_hold(
        &self,
        tenant: &str,
        artifact_id: &str,
        hold: &str,
    ) -> Result<(), ArtifactStoreError> {
        validate_identity(hold)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let entry = state
            .entries
            .get_mut(&(tenant.to_owned(), artifact_id.to_owned()))
            .ok_or(ArtifactStoreError::Denied)?;
        entry.holds.insert(hold.to_owned());
        Ok(())
    }
    pub fn release_legal_hold(
        &self,
        tenant: &str,
        artifact_id: &str,
        hold: &str,
    ) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let entry = state
            .entries
            .get_mut(&(tenant.to_owned(), artifact_id.to_owned()))
            .ok_or(ArtifactStoreError::Denied)?;
        if entry.holds.remove(hold) {
            Ok(())
        } else {
            Err(ArtifactStoreError::Denied)
        }
    }
    pub fn release_reference(
        &self,
        tenant: &str,
        task: &str,
        artifact_id: &str,
    ) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let entry = state
            .entries
            .get_mut(&(tenant.to_owned(), artifact_id.to_owned()))
            .filter(|entry| entry.manifest.producer.task == task)
            .ok_or(ArtifactStoreError::Denied)?;
        entry.reference_live = false;
        Ok(())
    }
    pub fn gc(
        &self,
        artifact_id: &str,
        now: i64,
        batch: usize,
    ) -> Result<RetentionDecision, ArtifactStoreError> {
        if !(1..=1000).contains(&batch) {
            return Err(ArtifactStoreError::Invalid);
        }
        let (key, object, fence) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            let (key, entry) = state
                .entries
                .iter_mut()
                .find(|((_, id), _)| id == artifact_id)
                .ok_or(ArtifactStoreError::Denied)?;
            entry.leases.retain(|_, expiry| *expiry > now);
            if !entry.holds.is_empty() {
                return Ok(RetentionDecision::Held);
            }
            if entry.reference_live
                || !entry.leases.is_empty()
                || now < entry.manifest.policy.retain_until
            {
                return Ok(RetentionDecision::Live);
            }
            entry.tombstoned = true;
            entry.deletion_fence = entry
                .deletion_fence
                .checked_add(1)
                .ok_or(ArtifactStoreError::Unavailable)?;
            (key.clone(), entry.object.clone(), entry.deletion_fence)
        };
        let shared = {
            let state = self
                .state
                .lock()
                .map_err(|_| ArtifactStoreError::Unavailable)?;
            state.entries.iter().any(|(other_key, entry)| {
                other_key != &key
                    && !entry.tombstoned
                    && entry.object.relative_path == object.relative_path
            })
        };
        if !shared {
            self.store.delete(&object)?;
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let entry = state
            .entries
            .get(&key)
            .ok_or(ArtifactStoreError::Conflict)?;
        if !entry.tombstoned || entry.deletion_fence != fence {
            return Err(ArtifactStoreError::Conflict);
        }
        state.entries.remove(&key);
        Ok(RetentionDecision::Deleted)
    }
}
fn authorized_entry_mut<'a>(
    state: &'a mut CatalogState,
    tenant: &str,
    owner: &str,
    task: &str,
    artifact_id: &str,
) -> Result<&'a mut CatalogEntry, ArtifactStoreError> {
    state
        .entries
        .get_mut(&(tenant.to_owned(), artifact_id.to_owned()))
        .filter(|entry| {
            !entry.tombstoned
                && entry.reference_live
                && entry.manifest.producer.owner == owner
                && entry.manifest.producer.task == task
        })
        .ok_or(ArtifactStoreError::Denied)
}
