//! Bounded, fail-closed classification and redaction before public trace persistence.
#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeSet;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ArtifactClassification, ProjectionReceipt};

const PUBLIC_MANIFEST_SCHEMA: &str = "trace-privacy-public-manifest/1";
const RESTRICTED_MANIFEST_SCHEMA: &str = "trace-privacy-restricted-manifest/1";

const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_DEPTH: usize = 64;
const MAX_POINTER_WORK_BYTES: usize = MAX_TOTAL_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Pii,
    Phi,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionAction {
    Keep,
    Placeholder,
    StableHandle,
    Drop,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionRule {
    pub pointer: String,
    pub class: DataClass,
    pub action: RedactionAction,
    #[serde(default)]
    pub stable_identifier: bool,
    pub fictional_provenance: Option<String>,
}

impl fmt::Debug for RedactionRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionRule")
            .field("pointer", &"<redacted>")
            .field("class", &self.class)
            .field("action", &self.action)
            .field("stable_identifier", &self.stable_identifier)
            .field(
                "fictional_provenance",
                &self.fictional_provenance.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyPolicy {
    policy_id: String,
    policy_revision: u64,
    key_generation: String,
    rules: Vec<RedactionRule>,
}

impl fmt::Debug for PrivacyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivacyPolicy")
            .field("policy_id", &"<redacted>")
            .field("policy_revision", &self.policy_revision)
            .field("key_generation", &"<redacted>")
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UncheckedPrivacyPolicy {
    policy_id: String,
    policy_revision: u64,
    key_generation: String,
    rules: Vec<RedactionRule>,
}

impl<'de> Deserialize<'de> for PrivacyPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let unchecked = UncheckedPrivacyPolicy::deserialize(deserializer)?;
        Self::new_versioned(
            unchecked.policy_id,
            unchecked.policy_revision,
            unchecked.key_generation,
            unchecked.rules,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PrivacyError {
    #[error("privacy policy is malformed or contains unknown fields")]
    MalformedPolicy,
    #[error("privacy policy contains a duplicate JSON pointer")]
    DuplicateRule,
    #[error("privacy policy contains overlapping JSON pointers")]
    OverlappingRule,
    #[error("privacy policy contains an invalid RFC 6901 pointer")]
    InvalidPointer,
    #[error("classification and action pair is unsupported")]
    UnsupportedClassAction,
    #[error("privacy policy rule did not match the source")]
    UnmatchedRule,
    #[error("trace source contains an unclassified value")]
    UnclassifiedValue,
    #[error("trace input is malformed")]
    MalformedInput,
    #[error("trace privacy bound exceeded")]
    LimitExceeded,
    #[error("semantic scanner found sensitive content")]
    SensitiveContent,
    #[error("stable handles require a nonempty string identifier")]
    InvalidStableIdentifier,
    #[error("trace privacy manifest verification failed")]
    VerificationFailed,
}

impl PrivacyPolicy {
    pub fn new_versioned(
        policy_id: impl Into<String>,
        policy_revision: u64,
        key_generation: impl Into<String>,
        mut rules: Vec<RedactionRule>,
    ) -> Result<Self, PrivacyError> {
        let policy_id = policy_id.into();
        let key_generation = key_generation.into();
        if rules.len() > MAX_RECORDS {
            return Err(PrivacyError::LimitExceeded);
        }
        if !valid_public_label(&policy_id)
            || policy_revision == 0
            || !valid_public_label(&key_generation)
            || sensitive_text(&policy_id)
            || sensitive_text(&key_generation)
        {
            return Err(PrivacyError::MalformedPolicy);
        }
        let policy_bytes = rules.iter().try_fold(
            policy_id.len().saturating_add(key_generation.len()),
            |total, rule| {
                total
                    .checked_add(
                        rule.pointer
                            .len()
                            .checked_mul(6)
                            .ok_or(PrivacyError::LimitExceeded)?,
                    )
                    .and_then(|value| {
                        value.checked_add(
                            rule.fictional_provenance
                                .as_ref()
                                .map_or(0, String::len)
                                .checked_mul(6)?,
                        )
                    })
                    .and_then(|value| value.checked_add(128))
                    .ok_or(PrivacyError::LimitExceeded)
            },
        )?;
        if policy_bytes > MAX_TOTAL_BYTES {
            return Err(PrivacyError::LimitExceeded);
        }
        let mut pointers = BTreeSet::new();
        for rule in &rules {
            if rule.pointer.len() > MAX_LINE_BYTES
                || rule
                    .fictional_provenance
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_LINE_BYTES)
            {
                return Err(PrivacyError::LimitExceeded);
            }
            if rule
                .fictional_provenance
                .as_ref()
                .is_some_and(|value| !valid_public_label(value) || sensitive_text(value))
            {
                return Err(PrivacyError::MalformedPolicy);
            }
            validate_pointer(&rule.pointer)?;
            if !pointers.insert(rule.pointer.clone()) {
                return Err(PrivacyError::DuplicateRule);
            }
            validate_pair(rule)?;
        }
        rules.sort_by(|left, right| left.pointer.cmp(&right.pointer));
        if contains_unsafe_overlaps(&rules) {
            return Err(PrivacyError::OverlappingRule);
        }
        Ok(Self {
            policy_id,
            policy_revision,
            key_generation,
            rules,
        })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, PrivacyError> {
        if bytes.len() > MAX_TOTAL_BYTES {
            return Err(PrivacyError::LimitExceeded);
        }
        let decoded: Self =
            serde_json::from_slice(bytes).map_err(|_| PrivacyError::MalformedPolicy)?;
        Self::new_versioned(
            decoded.policy_id,
            decoded.policy_revision,
            decoded.key_generation,
            decoded.rules,
        )
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
    pub fn key_generation(&self) -> &str {
        &self.key_generation
    }

    #[must_use]
    pub fn rules(&self) -> &[RedactionRule] {
        &self.rules
    }
}

fn contains_unsafe_overlaps(rules: &[RedactionRule]) -> bool {
    rules.iter().any(|rule| {
        rule.pointer
            .char_indices()
            .skip(1)
            .filter_map(|(index, character)| (character == '/').then_some(index))
            .chain((!rule.pointer.is_empty()).then_some(0))
            .filter_map(|index| {
                rules
                    .binary_search_by(|candidate| {
                        candidate.pointer.as_str().cmp(&rule.pointer[..index])
                    })
                    .ok()
                    .map(|rule_index| &rules[rule_index])
            })
            .any(|ancestor| ancestor.action != RedactionAction::Keep)
    })
}

fn valid_public_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn validate_pair(rule: &RedactionRule) -> Result<(), PrivacyError> {
    let allowed = match (rule.class, rule.action) {
        (DataClass::Public, RedactionAction::Keep) => rule
            .fictional_provenance
            .as_ref()
            .is_some_and(|v| !v.is_empty()),
        (
            DataClass::Internal | DataClass::Confidential | DataClass::Pii | DataClass::Phi,
            RedactionAction::Placeholder,
        ) => !rule.stable_identifier && rule.fictional_provenance.is_none(),
        (
            DataClass::Internal | DataClass::Confidential | DataClass::Pii | DataClass::Phi,
            RedactionAction::StableHandle,
        ) => rule.stable_identifier && rule.fictional_provenance.is_none(),
        (DataClass::Secret, RedactionAction::Drop) => {
            !rule.stable_identifier && rule.fictional_provenance.is_none()
        }
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(PrivacyError::UnsupportedClassAction)
    }
}

fn validate_pointer(pointer: &str) -> Result<(), PrivacyError> {
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err(PrivacyError::InvalidPointer);
    }
    let bytes = pointer.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                return Err(PrivacyError::InvalidPointer);
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RunHmacKey([u8; 32]);

impl RunHmacKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RunHmacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RunHmacKey(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionLogEntry {
    pub record_index: u64,
    pub pointer: String,
    pub class: DataClass,
    pub action: RedactionAction,
}

impl fmt::Debug for RedactionLogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionLogEntry")
            .field("record_index", &self.record_index)
            .field("pointer", &"<redacted>")
            .field("class", &self.class)
            .field("action", &self.action)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SanitizedTrace {
    pub public_bytes: Vec<u8>,
    pub action_log: Vec<RedactionLogEntry>,
    pub action_log_bytes: Vec<u8>,
    pub public_manifest: PublicTraceManifest,
    pub restricted_manifest: RestrictedTraceManifest,
}

impl fmt::Debug for SanitizedTrace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanitizedTrace")
            .field("public_bytes_len", &self.public_bytes.len())
            .field("action_count", &self.action_log.len())
            .field("action_log_bytes_len", &self.action_log_bytes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceArtifactProvenance {
    pub producer: String,
    pub policy_id: String,
    pub origin: TraceArtifactOrigin,
    pub fictional_sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceArtifactOrigin {
    Fictional,
    Sanitized,
    Mixed,
    RestrictedSource,
    ConfidentialAudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceArtifactBinding {
    pub classification: ArtifactClassification,
    pub provenance: TraceArtifactProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicProjectionReceipt {
    pub projector_id: String,
    pub projector_version: String,
    pub receipt_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicTraceManifest {
    pub schema_version: String,
    pub run_id: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub key_generation: String,
    pub artifact: TraceArtifactBinding,
    pub policy_commitment: String,
    pub output_digest: String,
    pub action_log_commitment: String,
    pub projection_receipts: Vec<PublicProjectionReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RestrictedStoragePolicy {
    pub public_export_forbidden: bool,
    pub authenticated_encryption_required: bool,
    pub authorization_required: bool,
    pub audit_required: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestrictedTraceManifest {
    pub schema_version: String,
    pub run_id: String,
    pub policy_id: String,
    pub policy_revision: u64,
    pub key_generation: String,
    pub artifact: TraceArtifactBinding,
    pub source_artifact: TraceArtifactBinding,
    pub action_log_artifact: TraceArtifactBinding,
    pub policy_digest: String,
    pub source_digest: String,
    pub action_log_digest: String,
    pub public_manifest_digest: String,
    pub projection_receipts: Vec<ProjectionReceipt>,
    pub storage_policy: RestrictedStoragePolicy,
}

impl fmt::Debug for RestrictedTraceManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedTraceManifest")
            .field("schema_version", &self.schema_version)
            .field("artifact_classification", &self.artifact.classification)
            .field(
                "source_artifact_classification",
                &self.source_artifact.classification,
            )
            .field(
                "action_log_artifact_classification",
                &self.action_log_artifact.classification,
            )
            .finish_non_exhaustive()
    }
}

pub fn sanitize_public_trace(
    source: &[u8],
    run_id: &str,
    key: RunHmacKey,
    policy: &PrivacyPolicy,
) -> Result<SanitizedTrace, PrivacyError> {
    sanitize_public_trace_with_receipts(source, run_id, key, policy, Vec::new())
}

#[allow(clippy::needless_pass_by_value)] // ownership guarantees prompt zeroization after the call
pub fn sanitize_public_trace_with_receipts(
    source: &[u8],
    run_id: &str,
    key: RunHmacKey,
    policy: &PrivacyPolicy,
    mut receipts: Vec<ProjectionReceipt>,
) -> Result<SanitizedTrace, PrivacyError> {
    if !valid_public_label(run_id) || sensitive_text(run_id) {
        return Err(PrivacyError::MalformedInput);
    }
    validate_projection_receipts(&mut receipts)?;
    let (mut records, jsonl) = parse_records(source)?;
    let action_count = policy
        .rules
        .len()
        .checked_mul(records.len())
        .ok_or(PrivacyError::LimitExceeded)?;
    let action_bytes_per_record = policy.rules.iter().try_fold(2_usize, |total, rule| {
        let pointer_bytes =
            serde_json::to_vec(&rule.pointer).map_err(|_| PrivacyError::LimitExceeded)?;
        total
            .checked_add(pointer_bytes.len())
            .and_then(|value| value.checked_add(96))
            .ok_or(PrivacyError::LimitExceeded)
    })?;
    if action_count > MAX_TOTAL_BYTES / 64
        || action_bytes_per_record
            .checked_mul(records.len())
            .is_none_or(|bytes| bytes > MAX_TOTAL_BYTES)
    {
        return Err(PrivacyError::LimitExceeded);
    }
    let decoded_rules: Vec<Vec<String>> = policy
        .rules
        .iter()
        .map(|rule| decode_pointer(&rule.pointer))
        .collect();
    let mut log = Vec::with_capacity(action_count);
    for (record_index, value) in records.iter_mut().enumerate() {
        ensure_fully_classified(value, policy)?;
        for (rule, tokens) in policy.rules.iter().zip(&decoded_rules) {
            apply_rule(value, tokens, rule, run_id, policy, &key)?;
            log.push(RedactionLogEntry {
                record_index: record_index as u64,
                pointer: rule.pointer.clone(),
                class: rule.class,
                action: rule.action,
            });
        }
    }
    let public_bytes = serialize_records(&records, jsonl)?;
    let action_log_bytes = serde_json::to_vec(&log).map_err(|_| PrivacyError::LimitExceeded)?;
    if public_bytes.len() > MAX_TOTAL_BYTES || action_log_bytes.len() > MAX_TOTAL_BYTES {
        return Err(PrivacyError::LimitExceeded);
    }
    scan_public_trace(&public_bytes)?;
    let public_manifest = make_public_manifest(
        run_id,
        policy,
        &public_bytes,
        &action_log_bytes,
        &receipts,
        &key,
    )?;
    let restricted_manifest = make_restricted_manifest(
        run_id,
        policy,
        source,
        &action_log_bytes,
        &public_manifest,
        receipts,
    )?;
    Ok(SanitizedTrace {
        public_bytes,
        action_log: log,
        action_log_bytes,
        public_manifest,
        restricted_manifest,
    })
}

/// Replays the complete privacy projection from restricted source bytes and
/// compares every public byte, action, digest, classification, and manifest.
#[allow(clippy::needless_pass_by_value)] // ownership guarantees key zeroization
pub fn verify_sanitized_trace(
    sanitized: &SanitizedTrace,
    source: &[u8],
    expected_run_id: &str,
    key: RunHmacKey,
    policy: &PrivacyPolicy,
    expected_receipts: Vec<ProjectionReceipt>,
) -> Result<(), PrivacyError> {
    let expected = sanitize_public_trace_with_receipts(
        source,
        expected_run_id,
        key,
        policy,
        expected_receipts,
    )?;
    if *sanitized == expected {
        Ok(())
    } else {
        Err(PrivacyError::VerificationFailed)
    }
}

fn parse_records(bytes: &[u8]) -> Result<(Vec<Value>, bool), PrivacyError> {
    if bytes.is_empty() || bytes.len() > MAX_TOTAL_BYTES {
        return Err(PrivacyError::LimitExceeded);
    }
    let jsonl = bytes.contains(&b'\n');
    let (body, record_count) = if jsonl {
        if !bytes.ends_with(b"\n") {
            return Err(PrivacyError::MalformedInput);
        }
        let body = &bytes[..bytes.len() - 1];
        if body.is_empty() {
            return Err(PrivacyError::MalformedInput);
        }
        let mut record_count = 0_usize;
        for line in body.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                return Err(PrivacyError::MalformedInput);
            }
            record_count = record_count
                .checked_add(1)
                .ok_or(PrivacyError::LimitExceeded)?;
            if record_count > MAX_RECORDS || line.len() > MAX_LINE_BYTES {
                return Err(PrivacyError::LimitExceeded);
            }
        }
        (body, record_count)
    } else {
        if bytes.len() > MAX_LINE_BYTES {
            return Err(PrivacyError::LimitExceeded);
        }
        (bytes, 1)
    };
    let mut records = Vec::with_capacity(record_count);
    let mut decoded_nodes = 0_usize;
    let mut pointer_work = 0_usize;
    let mut parse_line = |line: &[u8]| -> Result<(), PrivacyError> {
        let value = serde_json::from_slice::<UniqueValue>(line)
            .map_err(|_| PrivacyError::MalformedInput)?
            .0;
        if !value.is_object() {
            return Err(PrivacyError::MalformedInput);
        }
        let remaining_pointer_work = MAX_POINTER_WORK_BYTES
            .checked_sub(pointer_work)
            .ok_or(PrivacyError::LimitExceeded)?;
        let (record_nodes, record_pointer_work) =
            validate_tree_bounds(&value, remaining_pointer_work)?;
        decoded_nodes = decoded_nodes
            .checked_add(record_nodes)
            .ok_or(PrivacyError::LimitExceeded)?;
        pointer_work = pointer_work
            .checked_add(record_pointer_work)
            .ok_or(PrivacyError::LimitExceeded)?;
        if decoded_nodes > MAX_RECORDS || pointer_work > MAX_POINTER_WORK_BYTES {
            return Err(PrivacyError::LimitExceeded);
        }
        records.push(value);
        Ok(())
    };
    if jsonl {
        for line in body.split(|byte| *byte == b'\n') {
            parse_line(line)?;
        }
    } else {
        parse_line(body)?;
    }
    Ok((records, jsonl))
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            let value = object.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}

fn serialize_records(records: &[Value], jsonl: bool) -> Result<Vec<u8>, PrivacyError> {
    if !jsonl {
        return serde_json::to_vec(&records[0]).map_err(|_| PrivacyError::LimitExceeded);
    }
    let mut output = Vec::new();
    for record in records {
        let line = serde_json::to_vec(record).map_err(|_| PrivacyError::LimitExceeded)?;
        if line.len() > MAX_LINE_BYTES
            || output.len().saturating_add(line.len() + 1) > MAX_TOTAL_BYTES
        {
            return Err(PrivacyError::LimitExceeded);
        }
        output.extend_from_slice(&line);
        output.push(b'\n');
    }
    Ok(output)
}

fn ensure_fully_classified(root: &Value, policy: &PrivacyPolicy) -> Result<(), PrivacyError> {
    let mut stack = vec![(root, String::new(), false)];
    while let Some((value, pointer, object_member)) = stack.pop() {
        let matching_rule = policy
            .rules
            .binary_search_by(|rule| rule.pointer.as_str().cmp(pointer.as_str()))
            .ok()
            .map(|index| &policy.rules[index]);
        if object_member && matching_rule.is_none() {
            return Err(PrivacyError::UnclassifiedValue);
        }
        if matching_rule.is_some_and(|rule| rule.action != RedactionAction::Keep) {
            continue;
        }
        let terminal = match value {
            Value::Object(map) if !map.is_empty() => {
                for (key, child) in map {
                    stack.push((
                        child,
                        format!("{pointer}/{}", encode_pointer_token(key)),
                        true,
                    ));
                }
                false
            }
            Value::Array(values) if !values.is_empty() => {
                for (index, child) in values.iter().enumerate() {
                    stack.push((child, format!("{pointer}/{index}"), false));
                }
                false
            }
            _ => true,
        };
        if terminal && matching_rule.is_none() {
            return Err(PrivacyError::UnclassifiedValue);
        }
    }
    Ok(())
}

fn encode_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn make_public_manifest(
    run_id: &str,
    policy: &PrivacyPolicy,
    public: &[u8],
    log: &[u8],
    projection_receipts: &[ProjectionReceipt],
    key: &RunHmacKey,
) -> Result<PublicTraceManifest, PrivacyError> {
    let mut sources: Vec<String> = policy
        .rules
        .iter()
        .filter_map(|rule| rule.fictional_provenance.clone())
        .collect();
    sources.sort();
    sources.dedup();
    let public_rules = policy
        .rules
        .iter()
        .filter(|rule| rule.class == DataClass::Public)
        .count();
    let origin = if public_rules == policy.rules.len() {
        TraceArtifactOrigin::Fictional
    } else if public_rules == 0 {
        TraceArtifactOrigin::Sanitized
    } else {
        TraceArtifactOrigin::Mixed
    };
    Ok(PublicTraceManifest {
        schema_version: PUBLIC_MANIFEST_SCHEMA.into(),
        run_id: run_id.into(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        key_generation: policy.key_generation.clone(),
        artifact: TraceArtifactBinding {
            classification: ArtifactClassification::Public,
            provenance: TraceArtifactProvenance {
                producer: "trace-privacy/redactor-v1".into(),
                policy_id: policy.policy_id.clone(),
                origin,
                fictional_sources: sources,
            },
        },
        policy_commitment: policy_commitment(run_id, policy, key)?,
        output_digest: privacy_digest("public-output", &[public]),
        action_log_commitment: privacy_commitment(
            key,
            "action-log",
            &[
                run_id.as_bytes(),
                policy.policy_id.as_bytes(),
                &policy.policy_revision.to_be_bytes(),
                policy.key_generation.as_bytes(),
                log,
            ],
        ),
        projection_receipts: projection_receipts
            .iter()
            .map(|receipt| public_projection_receipt(run_id, policy, receipt, key))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn public_projection_receipt(
    run_id: &str,
    policy: &PrivacyPolicy,
    receipt: &ProjectionReceipt,
    key: &RunHmacKey,
) -> Result<PublicProjectionReceipt, PrivacyError> {
    let bytes = serde_json::to_vec(receipt).map_err(|_| PrivacyError::LimitExceeded)?;
    Ok(PublicProjectionReceipt {
        projector_id: receipt.projector_id.clone(),
        projector_version: receipt.projector_version.clone(),
        receipt_commitment: privacy_commitment(
            key,
            "projection-receipt",
            &[
                run_id.as_bytes(),
                policy.policy_id.as_bytes(),
                &policy.policy_revision.to_be_bytes(),
                policy.key_generation.as_bytes(),
                &bytes,
            ],
        ),
    })
}

fn make_restricted_manifest(
    run_id: &str,
    policy: &PrivacyPolicy,
    source: &[u8],
    log: &[u8],
    public: &PublicTraceManifest,
    projection_receipts: Vec<ProjectionReceipt>,
) -> Result<RestrictedTraceManifest, PrivacyError> {
    let public_bytes = serde_json::to_vec(public).map_err(|_| PrivacyError::LimitExceeded)?;
    Ok(RestrictedTraceManifest {
        schema_version: RESTRICTED_MANIFEST_SCHEMA.into(),
        run_id: run_id.into(),
        policy_id: policy.policy_id.clone(),
        policy_revision: policy.policy_revision,
        key_generation: policy.key_generation.clone(),
        artifact: TraceArtifactBinding {
            classification: ArtifactClassification::Confidential,
            provenance: TraceArtifactProvenance {
                producer: "trace-privacy/restricted-audit-v1".into(),
                policy_id: policy.policy_id.clone(),
                origin: TraceArtifactOrigin::ConfidentialAudit,
                fictional_sources: Vec::new(),
            },
        },
        source_artifact: TraceArtifactBinding {
            classification: ArtifactClassification::Secret,
            provenance: TraceArtifactProvenance {
                producer: "trace-privacy/restricted-source-v1".into(),
                policy_id: policy.policy_id.clone(),
                origin: TraceArtifactOrigin::RestrictedSource,
                fictional_sources: Vec::new(),
            },
        },
        action_log_artifact: TraceArtifactBinding {
            classification: ArtifactClassification::Confidential,
            provenance: TraceArtifactProvenance {
                producer: "trace-privacy/action-log-v1".into(),
                policy_id: policy.policy_id.clone(),
                origin: TraceArtifactOrigin::ConfidentialAudit,
                fictional_sources: Vec::new(),
            },
        },
        policy_digest: policy_digest(policy)?,
        source_digest: privacy_digest("restricted-source", &[source]),
        action_log_digest: privacy_digest("action-log", &[log]),
        public_manifest_digest: privacy_digest("public-manifest", &[&public_bytes]),
        projection_receipts,
        storage_policy: RestrictedStoragePolicy {
            public_export_forbidden: true,
            authenticated_encryption_required: true,
            authorization_required: true,
            audit_required: true,
        },
    })
}

fn validate_projection_receipts(receipts: &mut Vec<ProjectionReceipt>) -> Result<(), PrivacyError> {
    if receipts.len() > 128 {
        return Err(PrivacyError::LimitExceeded);
    }
    receipts.sort_by(|left, right| {
        (&left.projector_id, &left.projector_version)
            .cmp(&(&right.projector_id, &right.projector_version))
    });
    let mut seen = BTreeSet::new();
    for receipt in receipts {
        if !valid_public_label(&receipt.projector_id)
            || !valid_public_label(&receipt.projector_version)
            || sensitive_text(&receipt.projector_id)
            || sensitive_text(&receipt.projector_version)
            || !valid_digest(&receipt.input_digest)
            || !valid_digest(&receipt.output_digest)
            || !seen.insert((
                receipt.projector_id.clone(),
                receipt.projector_version.clone(),
            ))
        {
            return Err(PrivacyError::MalformedInput);
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn policy_digest(policy: &PrivacyPolicy) -> Result<String, PrivacyError> {
    let bytes = serde_json::to_vec(policy).map_err(|_| PrivacyError::LimitExceeded)?;
    Ok(privacy_digest("policy", &[&bytes]))
}

fn policy_commitment(
    run_id: &str,
    policy: &PrivacyPolicy,
    key: &RunHmacKey,
) -> Result<String, PrivacyError> {
    let bytes = serde_json::to_vec(policy).map_err(|_| PrivacyError::LimitExceeded)?;
    Ok(privacy_commitment(
        key,
        "policy",
        &[run_id.as_bytes(), &bytes],
    ))
}

fn privacy_commitment(key: &RunHmacKey, label: &str, parts: &[&[u8]]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("fixed HMAC key length");
    mac.update(b"SMESH-A2A\0trace-privacy-commitment\0v1\0");
    mac.update(&(label.len() as u64).to_be_bytes());
    mac.update(label.as_bytes());
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    format!(
        "hmac-sha256:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn privacy_digest(label: &str, parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"SMESH-A2A\0trace-privacy\0v1\0");
    hash.update((label.len() as u64).to_be_bytes());
    hash.update(label.as_bytes());
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    format!("sha256:{:x}", hash.finalize())
}

/// Scans decoded JSON semantics, rather than raw escape spellings, for content
/// forbidden from a public trace.
pub fn scan_public_trace(bytes: &[u8]) -> Result<(), PrivacyError> {
    let (records, _) = parse_records(bytes)?;
    let mut stack: Vec<&Value> = records.iter().collect();
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    let semantic_key: String = key
                        .chars()
                        .filter(char::is_ascii_alphanumeric)
                        .flat_map(char::to_lowercase)
                        .collect();
                    if !is_redacted_field_name(key)
                        && (sensitive_text(key) || sensitive_key_name(&semantic_key))
                    {
                        return Err(PrivacyError::SensitiveContent);
                    }
                    if matches!(
                        semantic_key.as_str(),
                        "patientid" | "mrn" | "insuranceid" | "insurancememberid" | "memberid"
                    ) && !value.as_str().is_some_and(|text| {
                        is_stable_handle(text) || is_redaction_placeholder(text)
                    }) {
                        return Err(PrivacyError::SensitiveContent);
                    }
                    if matches!(
                        semantic_key.as_str(),
                        "patientname" | "clinicalnotes" | "diagnosis" | "condition"
                    ) && !value.as_str().is_some_and(is_redaction_placeholder)
                    {
                        return Err(PrivacyError::SensitiveContent);
                    }
                    stack.push(value);
                }
            }
            Value::Array(values) => stack.extend(values),
            Value::String(text) if sensitive_text(text) => {
                return Err(PrivacyError::SensitiveContent);
            }
            _ => {}
        }
    }
    Ok(())
}

fn sensitive_key_name(key: &str) -> bool {
    [
        "password",
        "passwd",
        "secret",
        "apikey",
        "accesstoken",
        "refreshtoken",
        "sessiontoken",
        "authorization",
        "privatekey",
        "cookie",
        "token",
        "credential",
        "passphrase",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn is_stable_handle(text: &str) -> bool {
    text.strip_prefix("hmac-sha256:")
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .is_some_and(|digest| digest.len() == 32)
}

fn is_redacted_field_name(text: &str) -> bool {
    text.strip_prefix("redacted-field-")
        .is_some_and(is_stable_handle)
}

fn is_redaction_placeholder(text: &str) -> bool {
    matches!(
        text,
        "[REDACTED:INTERNAL]" | "[REDACTED:CONFIDENTIAL]" | "[REDACTED:PII]" | "[REDACTED:PHI]"
    )
}

fn sensitive_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if (lower.contains("-----begin ") && lower.contains("private key-----"))
        || lower.contains("-----begin openssh private key-----")
    {
        return true;
    }
    if contains_bearer_credential(text) {
        return true;
    }
    if contains_jwt(text)
        || contains_secret_token(text)
        || looks_like_email(text)
        || contains_ssn(text.as_bytes())
    {
        return true;
    }
    [
        "patient:",
        "patient id:",
        "patient name:",
        "mrn:",
        "mrn ",
        "insurance:",
        "insurance policy:",
    ]
    .iter()
    .any(|marker| {
        lower
            .find(marker)
            .is_some_and(|position| lower[position + marker.len()..].trim().len() >= 2)
    })
}

fn contains_secret_token(text: &str) -> bool {
    text.split(|character: char| {
        !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-')
    })
    .any(|token| {
        (token.len() == 20
            && (token.starts_with("AKIA") || token.starts_with("ASIA"))
            && token
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit()))
            || github_token(token)
            || api_secret_token(token)
    })
}

fn contains_bearer_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.match_indices("bearer").any(|(position, _)| {
        let previous_is_boundary =
            position == 0 || !lower.as_bytes()[position - 1].is_ascii_alphanumeric();
        if !previous_is_boundary {
            return false;
        }
        let remainder = &text[position + "bearer".len()..];
        let Some(separator) = remainder.chars().next() else {
            return false;
        };
        if !separator.is_whitespace() && !matches!(separator, ':' | '=') {
            return false;
        }
        let candidate = remainder.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, ':' | '=')
        });
        let token_length = candidate
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(byte))
            .count();
        let token = &candidate[..token_length];
        !token.is_empty() && !matches!(token.to_ascii_lowercase().as_str(), "of" | "the")
    })
}

fn github_token(token: &str) -> bool {
    let prefix_length = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .find_map(|prefix| token.starts_with(prefix).then_some(prefix.len()))
        .or_else(|| {
            token
                .starts_with("github_pat_")
                .then_some("github_pat_".len())
        });
    prefix_length.is_some_and(|length| {
        token.len().saturating_sub(length) >= 20
            && token[length..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn api_secret_token(token: &str) -> bool {
    let modern_prefix_length = ["sk-proj-", "sk-svcacct-"]
        .iter()
        .find_map(|prefix| token.starts_with(prefix).then_some(prefix.len()));
    modern_prefix_length.map_or_else(
        || {
            token.starts_with("sk-")
                && token.len() >= 23
                && token[3..].bytes().all(|byte| byte.is_ascii_alphanumeric())
        },
        |length| {
            token.len().saturating_sub(length) >= 20
                && token[length..]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        },
    )
}

fn looks_like_jwt(value: &str) -> bool {
    let token = value.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric()
            && character != '-'
            && character != '_'
            && character != '.'
    });
    let parts: Vec<_> = token.split('.').collect();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts.iter().all(|part| {
            part.len() >= 3
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

fn contains_jwt(text: &str) -> bool {
    text.split(|character: char| {
        !character.is_ascii_alphanumeric()
            && character != '-'
            && character != '_'
            && character != '.'
    })
    .any(looks_like_jwt)
}

fn looks_like_email(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace() || matches!(character, '<' | '>' | '(' | ')' | ',' | ';')
    })
    .any(|word| {
        let Some((local, domain)) = word.rsplit_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain
                .split_once('.')
                .is_some_and(|(name, suffix)| !name.is_empty() && suffix.len() >= 2)
    })
}

fn contains_ssn(bytes: &[u8]) -> bool {
    bytes.windows(11).any(|candidate| {
        candidate[3] == b'-'
            && candidate[6] == b'-'
            && candidate
                .iter()
                .enumerate()
                .all(|(index, byte)| matches!(index, 3 | 6) || byte.is_ascii_digit())
    })
}

fn validate_tree_bounds(
    root: &Value,
    max_pointer_work: usize,
) -> Result<(usize, usize), PrivacyError> {
    let mut stack = vec![(root, 1_usize, 0_usize)];
    let mut records = 0_usize;
    let mut pointer_work = 0_usize;
    while let Some((value, depth, pointer_len)) = stack.pop() {
        records = records.checked_add(1).ok_or(PrivacyError::LimitExceeded)?;
        if records > MAX_RECORDS || depth > MAX_DEPTH {
            return Err(PrivacyError::LimitExceeded);
        }
        match value {
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    let child_pointer_len = pointer_len
                        .checked_add(1)
                        .and_then(|length| length.checked_add(decimal_len(index)))
                        .ok_or(PrivacyError::LimitExceeded)?;
                    pointer_work = pointer_work
                        .checked_add(child_pointer_len)
                        .ok_or(PrivacyError::LimitExceeded)?;
                    if pointer_work > max_pointer_work {
                        return Err(PrivacyError::LimitExceeded);
                    }
                    stack.push((value, depth + 1, child_pointer_len));
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    let escaped_key_len = key
                        .len()
                        .checked_add(
                            key.bytes()
                                .filter(|byte| matches!(byte, b'~' | b'/'))
                                .count(),
                        )
                        .ok_or(PrivacyError::LimitExceeded)?;
                    let child_pointer_len = pointer_len
                        .checked_add(1)
                        .and_then(|length| length.checked_add(escaped_key_len))
                        .ok_or(PrivacyError::LimitExceeded)?;
                    pointer_work = pointer_work
                        .checked_add(child_pointer_len)
                        .ok_or(PrivacyError::LimitExceeded)?;
                    if pointer_work > max_pointer_work {
                        return Err(PrivacyError::LimitExceeded);
                    }
                    stack.push((value, depth + 1, child_pointer_len));
                }
            }
            _ => {}
        }
    }
    Ok((records, pointer_work))
}

fn decimal_len(mut value: usize) -> usize {
    let mut length = 1;
    while value >= 10 {
        value /= 10;
        length += 1;
    }
    length
}

fn decode_pointer(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return Vec::new();
    }
    pointer[1..]
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn apply_rule(
    root: &mut Value,
    tokens: &[String],
    rule: &RedactionRule,
    run_id: &str,
    policy: &PrivacyPolicy,
    key: &RunHmacKey,
) -> Result<(), PrivacyError> {
    if tokens.is_empty() {
        return apply_at_value(root, rule, run_id, policy, key);
    }
    let (last, parents) = tokens.split_last().expect("nonempty checked");
    let mut current = root;
    for token in parents {
        current = match current {
            Value::Object(map) => map.get_mut(token),
            Value::Array(values) => {
                parse_array_index(token).and_then(|index| values.get_mut(index))
            }
            _ => None,
        }
        .ok_or(PrivacyError::UnmatchedRule)?;
    }
    match current {
        Value::Object(map) => {
            if rule.action == RedactionAction::Drop {
                map.remove(last).ok_or(PrivacyError::UnmatchedRule)?;
                Ok(())
            } else if rule.action == RedactionAction::Keep {
                apply_at_value(
                    map.get_mut(last).ok_or(PrivacyError::UnmatchedRule)?,
                    rule,
                    run_id,
                    policy,
                    key,
                )
            } else {
                let mut value = map.remove(last).ok_or(PrivacyError::UnmatchedRule)?;
                apply_at_value(&mut value, rule, run_id, policy, key)?;
                let public_key = redacted_field_name(&rule.pointer, run_id, policy, key);
                if map.insert(public_key, value).is_some() {
                    return Err(PrivacyError::MalformedInput);
                }
                Ok(())
            }
        }
        Value::Array(values) => {
            let target = parse_array_index(last)
                .and_then(|index| values.get_mut(index))
                .ok_or(PrivacyError::UnmatchedRule)?;
            if rule.action == RedactionAction::Drop {
                *target = Value::Null;
                Ok(())
            } else {
                apply_at_value(target, rule, run_id, policy, key)
            }
        }
        _ => Err(PrivacyError::UnmatchedRule),
    }
}

fn parse_array_index(token: &str) -> Option<usize> {
    if token == "0" || (!token.starts_with('0') && token.bytes().all(|byte| byte.is_ascii_digit()))
    {
        token.parse().ok()
    } else {
        None
    }
}

fn apply_at_value(
    value: &mut Value,
    rule: &RedactionRule,
    run_id: &str,
    policy: &PrivacyPolicy,
    key: &RunHmacKey,
) -> Result<(), PrivacyError> {
    match rule.action {
        RedactionAction::Keep => Ok(()),
        RedactionAction::Placeholder => {
            *value = Value::String(format!(
                "[REDACTED:{}]",
                match rule.class {
                    DataClass::Internal => "INTERNAL",
                    DataClass::Confidential => "CONFIDENTIAL",
                    DataClass::Pii => "PII",
                    DataClass::Phi => "PHI",
                    _ => return Err(PrivacyError::UnsupportedClassAction),
                }
            ));
            Ok(())
        }
        RedactionAction::Drop => {
            *value = Value::Null;
            Ok(())
        }
        RedactionAction::StableHandle => {
            let identifier = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or(PrivacyError::InvalidStableIdentifier)?;
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key.0).expect("SHA-256 accepts this key size");
            mac.update(b"SMESH-A2A\0trace-privacy-handle\0v1\0");
            update_framed(&mut mac, run_id.as_bytes());
            update_framed(&mut mac, policy.policy_id.as_bytes());
            update_framed(&mut mac, &policy.policy_revision.to_be_bytes());
            update_framed(&mut mac, policy.key_generation.as_bytes());
            update_framed(&mut mac, identifier.as_bytes());
            let digest = mac.finalize().into_bytes();
            *value = Value::String(format!("hmac-sha256:{}", URL_SAFE_NO_PAD.encode(digest)));
            Ok(())
        }
    }
}

fn redacted_field_name(
    pointer: &str,
    run_id: &str,
    policy: &PrivacyPolicy,
    key: &RunHmacKey,
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("SHA-256 accepts this key size");
    mac.update(b"SMESH-A2A\0trace-privacy-field\0v1\0");
    update_framed(&mut mac, run_id.as_bytes());
    update_framed(&mut mac, policy.policy_id.as_bytes());
    update_framed(&mut mac, &policy.policy_revision.to_be_bytes());
    update_framed(&mut mac, policy.key_generation.as_bytes());
    update_framed(&mut mac, pointer.as_bytes());
    format!(
        "redacted-field-hmac-sha256:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn update_framed(mac: &mut Hmac<Sha256>, part: &[u8]) {
    mac.update(&(part.len() as u64).to_be_bytes());
    mac.update(part);
}
