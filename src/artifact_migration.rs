//! Canonical discovery and projection for populated inline A2A artifacts.
//!
//! URL parts are recorded only as inert source metadata while inline byte parts
//! are migrated. No code in this module performs network I/O.
#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    ArtifactMigrationPlan, ArtifactStoreError, ContentDigestV1, artifact::validate_artifact_id,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InlineArtifactKind {
    Text,
    Raw,
    Data,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineArtifactPart {
    pub kind: InlineArtifactKind,
    pub bytes: Vec<u8>,
    pub media_type: Option<String>,
    pub filename: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineArtifact {
    pub artifact_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub parts: Vec<InlineArtifactPart>,
    pub inert_urls: Vec<String>,
}

impl InlineArtifact {
    /// Canonical plaintext. A single part preserves its exact protocol bytes;
    /// multipart artifacts use a deterministic, self-describing JSON envelope.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactStoreError> {
        if self.parts.len() == 1 && self.inert_urls.is_empty() {
            return Ok(self.parts[0].bytes.clone());
        }
        let parts = self
            .parts
            .iter()
            .map(|part| {
                serde_json::json!({
                    "kind": match part.kind { InlineArtifactKind::Text => "text", InlineArtifactKind::Raw => "raw", InlineArtifactKind::Data => "data" },
                    "mediaType": part.media_type,
                    "filename": part.filename,
                    "bytesBase64": STANDARD.encode(&part.bytes),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({
            "schema": "smesh-inline-artifact-envelope/v1",
            "parts": parts,
            "inertUrls": self.inert_urls,
        }))
        .map_err(|_| ArtifactStoreError::Invalid)
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        if self.parts.len() == 1 && self.inert_urls.is_empty() {
            self.parts[0]
                .media_type
                .as_deref()
                .unwrap_or(match self.parts[0].kind {
                    InlineArtifactKind::Text => "text/plain; charset=utf-8",
                    InlineArtifactKind::Raw => "application/octet-stream",
                    InlineArtifactKind::Data => "application/json",
                })
        } else {
            "application/vnd.smesh.inline-artifact+json"
        }
    }

    #[must_use]
    pub fn manifest_projection(
        &self,
        content_digest: &str,
        size_bytes: u64,
        manifest_digest: &str,
    ) -> Value {
        let media_type = self.media_type();
        let resolver = format!("/artifacts/v1/{}", self.artifact_id);
        let mut artifact = Map::new();
        artifact.insert(
            "artifactId".to_owned(),
            Value::String(self.artifact_id.clone()),
        );
        if let Some(name) = &self.name {
            artifact.insert("name".to_owned(), Value::String(name.clone()));
        }
        if let Some(description) = &self.description {
            artifact.insert("description".to_owned(), Value::String(description.clone()));
        }
        artifact.insert(
            "parts".to_owned(),
            serde_json::json!([{
                "data": {
                    "schema": "smesh-artifact-part/v1",
                    "artifactId": self.artifact_id,
                    "mediaType": media_type,
                    "sizeBytes": size_bytes,
                    "contentDigest": content_digest,
                    "resolver": {"href": resolver, "authenticated": true, "methods": ["GET", "HEAD"]}
                },
                "mediaType": "application/vnd.smesh.artifact-manifest+json"
            }]),
        );
        artifact.insert(
            "metadata".to_owned(),
            serde_json::json!({"smeshArtifact": {
                "schema": "smesh-artifact-projection/v1",
                "manifestDigest": manifest_digest,
                "contentDigest": content_digest,
                "sizeBytes": size_bytes,
                "mediaType": media_type,
                "resolver": resolver
            }}),
        );
        artifact.insert(
            "extensions".to_owned(),
            serde_json::json!(["https://smesh.dev/extensions/artifact-manifest/v1"]),
        );
        Value::Object(artifact)
    }

    pub fn rewrite_all(
        &self,
        value: &mut Value,
        projection: &Value,
    ) -> Result<usize, ArtifactStoreError> {
        fn visit(value: &mut Value, artifact_id: &str, projection: &Value, changed: &mut usize) {
            match value {
                Value::Object(map) => {
                    let matches = map.get("artifactId").and_then(Value::as_str)
                        == Some(artifact_id)
                        && map.get("parts").is_some_and(Value::is_array);
                    if matches {
                        *value = projection.clone();
                        *changed += 1;
                    } else {
                        for child in map.values_mut() {
                            visit(child, artifact_id, projection, changed);
                        }
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        visit(child, artifact_id, projection, changed);
                    }
                }
                _ => {}
            }
        }
        let mut changed = 0;
        visit(value, &self.artifact_id, projection, &mut changed);
        if changed == 0 {
            return Err(ArtifactStoreError::Conflict);
        }
        Ok(changed)
    }
}

pub fn extract_inline_artifacts(value: &Value) -> Result<Vec<InlineArtifact>, ArtifactStoreError> {
    fn walk(value: &Value, found: &mut Vec<InlineArtifact>) -> Result<(), ArtifactStoreError> {
        match value {
            Value::Object(map) => {
                if let (Some(artifact_id), Some(Value::Array(parts))) = (
                    map.get("artifactId").and_then(Value::as_str),
                    map.get("parts"),
                ) {
                    if map
                        .get("metadata")
                        .and_then(|value| value.get("smeshArtifact"))
                        .and_then(|value| value.get("schema"))
                        .and_then(Value::as_str)
                        == Some("smesh-artifact-projection/v1")
                    {
                        return Ok(());
                    }
                    let mut inline = Vec::new();
                    let mut urls = Vec::new();
                    for part in parts {
                        let object = part.as_object().ok_or(ArtifactStoreError::Invalid)?;
                        let present = ["text", "raw", "data", "url"]
                            .into_iter()
                            .filter(|key| object.contains_key(*key))
                            .collect::<Vec<_>>();
                        if present.len() != 1 {
                            return Err(ArtifactStoreError::Invalid);
                        }
                        let media_type = object
                            .get("mediaType")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        let filename = object
                            .get("filename")
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        match present[0] {
                            "text" => inline.push(InlineArtifactPart {
                                kind: InlineArtifactKind::Text,
                                bytes: object
                                    .get("text")
                                    .and_then(Value::as_str)
                                    .ok_or(ArtifactStoreError::Invalid)?
                                    .as_bytes()
                                    .to_vec(),
                                media_type,
                                filename,
                            }),
                            "raw" => inline.push(InlineArtifactPart {
                                kind: InlineArtifactKind::Raw,
                                bytes: STANDARD
                                    .decode(
                                        object
                                            .get("raw")
                                            .and_then(Value::as_str)
                                            .ok_or(ArtifactStoreError::Invalid)?,
                                    )
                                    .map_err(|_| ArtifactStoreError::Invalid)?,
                                media_type,
                                filename,
                            }),
                            "data" => inline.push(InlineArtifactPart {
                                kind: InlineArtifactKind::Data,
                                bytes: canonical_json_bytes(
                                    object.get("data").ok_or(ArtifactStoreError::Invalid)?,
                                )?,
                                media_type,
                                filename,
                            }),
                            "url" => urls.push(
                                object
                                    .get("url")
                                    .and_then(Value::as_str)
                                    .ok_or(ArtifactStoreError::Invalid)?
                                    .to_owned(),
                            ),
                            _ => unreachable!(),
                        }
                    }
                    if !inline.is_empty() {
                        validate_artifact_id(artifact_id)?;
                        found.push(InlineArtifact {
                            artifact_id: artifact_id.to_owned(),
                            name: map.get("name").and_then(Value::as_str).map(str::to_owned),
                            description: map
                                .get("description")
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                            parts: inline,
                            inert_urls: urls,
                        });
                        return Ok(());
                    }
                }
                for child in map.values() {
                    walk(child, found)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child, found)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut found = Vec::new();
    walk(value, &mut found)?;
    Ok(found)
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ArtifactStoreError> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|key| (key.clone(), sorted(&map[key])))
                        .collect(),
                )
            }
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).map_err(|_| ArtifactStoreError::Invalid)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanDocument {
    schema: String,
    plan_id: String,
    source: PlanSource,
    source_schema_version: u64,
    policy: PlanPolicy,
    actor: String,
    reason: String,
    batch_size: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanSource {
    schema: String,
    store_id: ContentDigestV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanPolicy {
    id: String,
    revision: u64,
    digest: ContentDigestV1,
}

#[derive(Clone)]
pub struct ArtifactMigrationPlanFile {
    plan: ArtifactMigrationPlan,
    source_schema: String,
    source_store_id: ContentDigestV1,
}

impl ArtifactMigrationPlanFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let path = path.as_ref();
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
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 {
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
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len()).map_err(|_| ArtifactStoreError::Invalid)?,
        );
        file.read_to_end(&mut bytes)
            .map_err(|_| ArtifactStoreError::Unavailable)?;
        let document: PlanDocument =
            serde_json::from_slice(&bytes).map_err(|_| ArtifactStoreError::Invalid)?;
        if document.schema != "smesh-artifact-migration-plan/v1"
            || document.source.schema.is_empty()
            || document.source.schema.len() > 63
            || !document
                .source
                .schema
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ArtifactStoreError::Invalid);
        }
        let plan = ArtifactMigrationPlan::new(
            document.plan_id,
            document.source_schema_version,
            document.policy.id,
            document.policy.revision,
            document.policy.digest,
            document.actor,
            document.reason,
            document.batch_size,
        )?;
        Ok(Self {
            plan,
            source_schema: document.source.schema,
            source_store_id: document.source.store_id,
        })
    }

    #[must_use]
    pub const fn plan(&self) -> &ArtifactMigrationPlan {
        &self.plan
    }
    #[must_use]
    pub fn source_schema(&self) -> &str {
        &self.source_schema
    }
    #[must_use]
    pub const fn source_store_id(&self) -> ContentDigestV1 {
        self.source_store_id
    }
}
