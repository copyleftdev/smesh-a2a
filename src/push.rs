//! Secure, operator-enrolled A2A callback policy and wire primitives.
//!
//! This module deliberately does not use the vendored in-memory push store or
//! sender. Destinations are immutable operator enrollments, caller credentials
//! are not represented, and each network attempt must resolve and pin afresh.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]

use std::{
    collections::HashSet,
    fmt,
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use base64::Engine as _;
use futures::StreamExt as _;
use hmac::{Hmac, Mac as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
#[cfg(debug_assertions)]
use std::collections::BTreeMap;
use subtle::ConstantTimeEq as _;
use thiserror::Error;

const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_URL_BYTES: usize = 2_048;
const MAX_PATH_BYTES: usize = 1_024;
const MAX_SECRET_BYTES: usize = 4_096;
const MIN_SECRET_BYTES: usize = 32;

/// Resolve the canonical production configuration variable and its explicitly
/// deprecated alias. Supplying both is ambiguous and therefore fails closed.
pub fn resolve_push_config_path(
    canonical: Option<std::ffi::OsString>,
    deprecated_policy_alias: Option<std::ffi::OsString>,
) -> Result<Option<std::ffi::OsString>, PushSecurityError> {
    if canonical.as_ref().is_some_and(|path| path.is_empty())
        || deprecated_policy_alias
            .as_ref()
            .is_some_and(|path| path.is_empty())
        || (canonical.is_some() && deprecated_policy_alias.is_some())
    {
        return Err(PushSecurityError::InvalidPolicy);
    }
    Ok(canonical.or(deprecated_policy_alias))
}

type HmacSha256 = Hmac<Sha256>;

/// Closed callback policy validation error. It intentionally carries no path,
/// URL, address, DNS answer, or secret material.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PushSecurityError {
    #[error("callback policy is invalid")]
    InvalidPolicy,
    #[error("callback enrollment is not authorized")]
    EnrollmentDenied,
    #[error("callback destination is invalid")]
    InvalidDestination,
    #[error("callback secret material is invalid")]
    InvalidSecret,
    #[error("callback DNS result is unsafe")]
    UnsafeDns,
    #[error("callback DNS lookup is unavailable")]
    DnsUnavailable,
}

/// Exact canonical HTTPS callback URI.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalCallbackUrl {
    canonical: String,
    host: String,
    port: u16,
    path: String,
}

impl fmt::Debug for CanonicalCallbackUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalCallbackUrl([redacted])")
    }
}

impl CanonicalCallbackUrl {
    /// Parse an already-canonical HTTPS DNS URI with an explicit port.
    pub fn parse(input: &str) -> Result<Self, PushSecurityError> {
        if input.is_empty()
            || input.len() > MAX_URL_BYTES
            || !input.is_ascii()
            || input
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\\')
            || input.contains('%')
        {
            return Err(PushSecurityError::InvalidDestination);
        }
        let parsed = url::Url::parse(input).map_err(|_| PushSecurityError::InvalidDestination)?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(PushSecurityError::InvalidDestination);
        }
        let host = parsed
            .host_str()
            .ok_or(PushSecurityError::InvalidDestination)?;
        if host.is_empty()
            || host.len() > 253
            || host.ends_with('.')
            || host.contains('*')
            || host != host.to_ascii_lowercase()
            || host.parse::<IpAddr>().is_ok()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(PushSecurityError::InvalidDestination);
        }
        let authority_end = input["https://".len()..]
            .find('/')
            .map(|offset| offset + "https://".len())
            .ok_or(PushSecurityError::InvalidDestination)?;
        let authority = &input["https://".len()..authority_end];
        let port_text = authority
            .strip_prefix(host)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .ok_or(PushSecurityError::InvalidDestination)?;
        let port = port_text
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(PushSecurityError::InvalidDestination)?;
        let path = parsed.path();
        if path.is_empty()
            || path.len() > MAX_PATH_BYTES
            || !path.starts_with('/')
            || path.starts_with("//")
            || path
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return Err(PushSecurityError::InvalidDestination);
        }
        let canonical = format!("https://{host}:{port}{path}");
        if canonical != input {
            return Err(PushSecurityError::InvalidDestination);
        }
        Ok(Self {
            canonical,
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Return whether an address is safe as an Internet callback destination.
///
/// The allow side is deliberately narrow. IPv4 exclusions cover IANA special
/// purpose ranges. IPv6 must be native global unicast in `2000::/3`, excluding
/// protocol assignments, documentation, benchmarking, 6to4, and mapped IPv4.
#[must_use]
pub fn is_public_callback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            is_public_v6(ip)
        }
    }
}

fn v4_in(ip: Ipv4Addr, base: [u8; 4], prefix: u32) -> bool {
    let value = u32::from(ip);
    let base = u32::from(Ipv4Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    value & mask == base & mask
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let blocked = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 31, 196, 0], 24),
        ([192, 52, 193, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([192, 175, 48, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    !blocked
        .iter()
        .any(|(base, prefix)| v4_in(ip, *base, *prefix))
}

fn v6_in(ip: Ipv6Addr, base: Ipv6Addr, prefix: u32) -> bool {
    let value = u128::from(ip);
    let base = u128::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    value & mask == base & mask
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if !v6_in(ip, Ipv6Addr::from(0x2000_u128 << 112), 3) {
        return false;
    }
    let blocked = [
        (Ipv6Addr::from(0x2001_u128 << 112), 23),
        ("2001:2::".parse().expect("static IPv6"), 48),
        ("2001:db8::".parse().expect("static IPv6"), 32),
        ("2002::".parse().expect("static IPv6"), 16),
        ("3fff::".parse().expect("static IPv6"), 20),
    ];
    !blocked
        .iter()
        .any(|(base, prefix)| v6_in(ip, *base, *prefix))
}

/// Validate a fresh resolver snapshot. A single unsafe answer rejects all.
pub fn validate_dns_answers(
    answers: &[IpAddr],
    max_answers: usize,
) -> Result<Vec<IpAddr>, PushSecurityError> {
    if answers.is_empty()
        || answers.len() > max_answers
        || max_answers == 0
        || answers
            .iter()
            .any(|address| !is_public_callback_ip(*address))
    {
        return Err(PushSecurityError::UnsafeDns);
    }
    let mut unique = Vec::with_capacity(answers.len());
    for answer in answers {
        let normalized = match answer {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(*answer, IpAddr::V4),
            IpAddr::V4(_) => *answer,
        };
        if !unique.contains(&normalized) {
            unique.push(normalized);
        }
    }
    Ok(unique)
}

/// Server-managed HMAC-SHA256 callback signer.
pub struct CallbackSigner(Vec<u8>);

impl fmt::Debug for CallbackSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallbackSigner([redacted])")
    }
}

impl CallbackSigner {
    pub fn new(secret: &[u8]) -> Result<Self, PushSecurityError> {
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len()) {
            return Err(PushSecurityError::InvalidSecret);
        }
        Ok(Self(secret.to_vec()))
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn sign(
        &self,
        target: &str,
        endpoint_id: &str,
        event_id: &str,
        timestamp: u64,
        attempt: u32,
        key_generation: &str,
        body: &[u8],
    ) -> String {
        let input = signing_input(
            target,
            endpoint_id,
            event_id,
            timestamp,
            attempt,
            key_generation,
            body,
        );
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(&input);
        format!(
            "v1,hmac-sha256={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn verify(
        &self,
        target: &str,
        endpoint_id: &str,
        event_id: &str,
        timestamp: u64,
        attempt: u32,
        key_generation: &str,
        body: &[u8],
        candidate: &str,
    ) -> bool {
        let expected = self.sign(
            target,
            endpoint_id,
            event_id,
            timestamp,
            attempt,
            key_generation,
            body,
        );
        expected.as_bytes().ct_eq(candidate.as_bytes()).into()
    }
}

fn push_len(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn signing_input(
    target: &str,
    endpoint_id: &str,
    event_id: &str,
    timestamp: u64,
    attempt: u32,
    key_generation: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut input = b"smesh-callback-signature/v1".to_vec();
    for value in [
        b"POST".as_slice(),
        target.as_bytes(),
        endpoint_id.as_bytes(),
        event_id.as_bytes(),
    ] {
        push_len(&mut input, value);
    }
    input.extend_from_slice(&timestamp.to_be_bytes());
    input.extend_from_slice(&attempt.to_be_bytes());
    push_len(&mut input, key_generation.as_bytes());
    input.extend_from_slice(&Sha256::digest(body));
    input
}

/// Exact request-body SHA-256 in RFC 9530 dictionary form.
#[must_use]
pub fn content_digest_header(body: &[u8]) -> String {
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    )
}

/// Resolver owned by the callback subsystem. It is called for every attempt;
/// implementations must not treat cached results as authorization.
#[async_trait::async_trait]
pub trait CallbackResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, PushSecurityError>;
}

/// Fresh operating-system resolver. Every call starts a new lookup; its
/// answers are authorized only by the transport's per-attempt validation.
#[derive(Debug, Default)]
pub struct SystemCallbackResolver;

impl SystemCallbackResolver {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl CallbackResolver for SystemCallbackResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, PushSecurityError> {
        tokio::net::lookup_host((host, 0))
            .await
            .map(|answers| answers.map(|answer| answer.ip()).collect())
            .map_err(|_| PushSecurityError::DnsUnavailable)
    }
}

#[cfg(debug_assertions)]
#[derive(Debug)]
struct StaticTestCallbackResolver(BTreeMap<String, Vec<IpAddr>>);

#[cfg(debug_assertions)]
#[async_trait::async_trait]
impl CallbackResolver for StaticTestCallbackResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, PushSecurityError> {
        self.0
            .get(host)
            .cloned()
            .ok_or(PushSecurityError::DnsUnavailable)
    }
}

/// Closed wire failure categories with no raw error or destination fields.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CallbackTransportError {
    #[error("callback DNS result is unsafe")]
    DnsUnsafe,
    #[error("callback DNS lookup is unavailable")]
    DnsUnavailable,
    #[error("callback TLS validation failed")]
    Tls,
    #[error("callback transport configuration is invalid")]
    Configuration,
    #[error("callback connection failed")]
    Connect,
    #[error("callback attempt timed out")]
    Timeout,
    #[error("callback connection was reset")]
    Reset,
    #[error("callback response exceeded its bound")]
    ResponseTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackResponse {
    status: u16,
    disposition: DeliveryDisposition,
    retry_after_seconds: Option<u64>,
}

impl CallbackResponse {
    #[must_use]
    pub const fn status(self) -> u16 {
        self.status
    }
    #[must_use]
    pub const fn disposition(self) -> DeliveryDisposition {
        self.disposition
    }
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

/// A secure attempt transport. It creates a fresh no-proxy/no-redirect client
/// pinned to the validated address for every request.
pub struct SecureCallbackTransport {
    resolver: Arc<dyn CallbackResolver>,
    max_answers: usize,
    dns_timeout: Duration,
    connect_timeout: Duration,
    request_timeout: Duration,
    test_loopback_pinning: bool,
    #[cfg(debug_assertions)]
    test_connector_map: BTreeMap<IpAddr, IpAddr>,
    #[cfg(debug_assertions)]
    test_requested_pins: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    #[cfg(debug_assertions)]
    test_pin_barriers: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
}

impl fmt::Debug for SecureCallbackTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureCallbackTransport")
            .field("max_answers", &self.max_answers)
            .field("dns_timeout", &self.dns_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl SecureCallbackTransport {
    pub fn new<R>(resolver: Arc<R>, max_answers: usize) -> Result<Self, PushSecurityError>
    where
        R: CallbackResolver + 'static,
    {
        if !(1..=32).contains(&max_answers) {
            return Err(PushSecurityError::InvalidPolicy);
        }
        Ok(Self {
            resolver,
            max_answers,
            dns_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_secs(10),
            test_loopback_pinning: false,
            #[cfg(debug_assertions)]
            test_connector_map: BTreeMap::new(),
            #[cfg(debug_assertions)]
            test_requested_pins: Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(debug_assertions)]
            test_pin_barriers: None,
        })
    }

    pub fn from_policy_system(policy: &PushPolicy) -> Result<Self, PushSecurityError> {
        if std::env::var_os("SMESH_TEST_PUSH_DNS_MAP_PATH").is_some() {
            #[cfg(not(debug_assertions))]
            return Err(PushSecurityError::InvalidPolicy);
            #[cfg(debug_assertions)]
            {
                let explicit =
                    std::env::var("SMESH_TEST_PUSH_DNS_MAP_ENABLE").as_deref() == Ok("1");
                let path = PathBuf::from(
                    std::env::var_os("SMESH_TEST_PUSH_DNS_MAP_PATH")
                        .ok_or(PushSecurityError::InvalidPolicy)?,
                );
                return Self::from_policy_test_dns_map(policy, &path, explicit);
            }
        }
        Ok(Self {
            resolver: Arc::new(SystemCallbackResolver::new()),
            max_answers: usize::from(policy.max_dns_answers),
            dns_timeout: Duration::from_millis(policy.dns_timeout_ms),
            connect_timeout: Duration::from_millis(policy.connect_timeout_ms),
            request_timeout: Duration::from_millis(policy.request_timeout_ms),
            test_loopback_pinning: false,
            #[cfg(debug_assertions)]
            test_connector_map: BTreeMap::new(),
            #[cfg(debug_assertions)]
            test_requested_pins: Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(debug_assertions)]
            test_pin_barriers: None,
        })
    }

    /// Debug-only, explicitly gated static resolver used by production-process
    /// tests. Only literal loopback answers are accepted; the canonical DNS
    /// hostname remains the HTTP authority and TLS SNI/name-verification input.
    #[cfg(debug_assertions)]
    pub fn from_policy_test_dns_map(
        policy: &PushPolicy,
        path: &Path,
        explicitly_enabled: bool,
    ) -> Result<Self, PushSecurityError> {
        if !explicitly_enabled {
            return Err(PushSecurityError::InvalidPolicy);
        }
        let bytes = read_private_file(path, 64 * 1024)?;
        let raw: BTreeMap<String, Vec<String>> =
            serde_json::from_slice(&bytes).map_err(|_| PushSecurityError::InvalidPolicy)?;
        if raw.is_empty() || raw.len() > 32 {
            return Err(PushSecurityError::InvalidPolicy);
        }
        let mut parsed = BTreeMap::new();
        for (host, answers) in raw {
            let canonical = CanonicalCallbackUrl::parse(&format!("https://{host}:443/test"))?;
            if canonical.host() != host || answers.is_empty() || answers.len() > 8 {
                return Err(PushSecurityError::InvalidPolicy);
            }
            let addresses = answers
                .into_iter()
                .map(|value| value.parse::<IpAddr>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| PushSecurityError::InvalidPolicy)?;
            if addresses.iter().any(|address| !address.is_loopback()) {
                return Err(PushSecurityError::InvalidPolicy);
            }
            parsed.insert(host, addresses);
        }
        Ok(Self {
            resolver: Arc::new(StaticTestCallbackResolver(parsed)),
            max_answers: usize::from(policy.max_dns_answers),
            dns_timeout: Duration::from_millis(policy.dns_timeout_ms),
            connect_timeout: Duration::from_millis(policy.connect_timeout_ms),
            request_timeout: Duration::from_millis(policy.request_timeout_ms),
            test_loopback_pinning: true,
            test_connector_map: BTreeMap::new(),
            test_requested_pins: Arc::new(std::sync::Mutex::new(Vec::new())),
            test_pin_barriers: None,
        })
    }

    /// Debug-only connector seam. Resolver answers still pass the complete
    /// production public-address policy; only the resulting validated socket
    /// is mapped to a loopback fixture. The originally authorized pin is
    /// recorded for deterministic rebinding evidence.
    #[cfg(debug_assertions)]
    pub fn new_test_mapped<R>(
        resolver: Arc<R>,
        max_answers: usize,
        connector_map: BTreeMap<IpAddr, IpAddr>,
        pin_barriers: Option<(Arc<tokio::sync::Barrier>, Arc<tokio::sync::Barrier>)>,
        explicitly_enabled: bool,
    ) -> Result<Self, PushSecurityError>
    where
        R: CallbackResolver + 'static,
    {
        if !explicitly_enabled
            || connector_map.is_empty()
            || connector_map.iter().any(|(source, destination)| {
                !is_public_callback_ip(*source) || !destination.is_loopback()
            })
        {
            return Err(PushSecurityError::InvalidPolicy);
        }
        let mut transport = Self::new(resolver, max_answers)?;
        transport.test_connector_map = connector_map;
        transport.test_pin_barriers = pin_barriers;
        Ok(transport)
    }

    #[cfg(debug_assertions)]
    #[must_use]
    pub fn test_requested_pins(&self) -> Vec<SocketAddr> {
        self.test_requested_pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn connector_socket(&self, pinned: SocketAddr) -> SocketAddr {
        #[cfg(debug_assertions)]
        {
            if let Some(mapped) = self.test_connector_map.get(&pinned.ip()) {
                self.test_requested_pins
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(pinned);
                if let Some((validated, release)) = &self.test_pin_barriers {
                    validated.wait().await;
                    release.wait().await;
                }
                return SocketAddr::new(*mapped, pinned.port());
            }
        }
        pinned
    }

    /// Resolve and validate a fresh snapshot, returning the exact socket that
    /// must be pinned by this attempt.
    pub async fn resolve_attempt(
        &self,
        target: &CanonicalCallbackUrl,
    ) -> Result<SocketAddr, PushSecurityError> {
        let answers = tokio::time::timeout(self.dns_timeout, self.resolver.resolve(target.host()))
            .await
            .map_err(|_| PushSecurityError::DnsUnavailable)??;
        let validated = if self.test_loopback_pinning
            && !answers.is_empty()
            && answers.len() <= self.max_answers
            && answers.iter().all(IpAddr::is_loopback)
        {
            answers
        } else {
            validate_dns_answers(&answers, self.max_answers)?
        };
        Ok(SocketAddr::new(validated[0], target.port()))
    }

    /// Send exact immutable callback bytes. Authentication is attached only
    /// after fresh DNS validation and pin construction. The response body is
    /// intentionally ignored.
    #[allow(clippy::too_many_arguments)]
    pub async fn send(
        &self,
        target: &CanonicalCallbackUrl,
        endpoint_id: &str,
        event_id: &str,
        timestamp: u64,
        attempt: u32,
        key_generation: &str,
        signer: &CallbackSigner,
        body: &[u8],
    ) -> Result<DeliveryDisposition, PushSecurityError> {
        if body.len() > 256 * 1024 || attempt == 0 {
            return Err(PushSecurityError::InvalidPolicy);
        }
        let pinned = self.resolve_attempt(target).await?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .http1_only()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .resolve(target.host(), pinned)
            .build()
            .map_err(|_| PushSecurityError::InvalidPolicy)?;
        let signature = signer.sign(
            target.as_str(),
            endpoint_id,
            event_id,
            timestamp,
            attempt,
            key_generation,
            body,
        );
        let response = client
            .post(target.as_str())
            .header("Content-Type", "application/a2a+json")
            .header("Content-Digest", content_digest_header(body))
            .header("X-Smesh-Callback-Version", "1")
            .header("X-Smesh-Callback-Event-Id", event_id)
            .header("X-Smesh-Callback-Endpoint-Id", endpoint_id)
            .header("X-Smesh-Callback-Timestamp", timestamp)
            .header("X-Smesh-Callback-Attempt", attempt)
            .header("X-Smesh-Callback-Key-Generation", key_generation)
            .header("X-Smesh-Callback-Signature", signature)
            .header("Idempotency-Key", event_id)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| PushSecurityError::UnsafeDns)?;
        Ok(classify_status(response.status().as_u16()))
    }

    /// Complete secure attempt using enrollment-specific trust and optional
    /// paired mTLS identity loaded from the same validated file bytes.
    pub async fn send_enrollment(
        &self,
        enrollment: &PushEnrollment,
        event_id: &str,
        timestamp: u64,
        attempt: u32,
        body: &[u8],
        max_response_bytes: usize,
    ) -> Result<CallbackResponse, CallbackTransportError> {
        if body.is_empty() || body.len() > 256 * 1024 || attempt == 0 || max_response_bytes == 0 {
            return Err(CallbackTransportError::Configuration);
        }
        let target = enrollment.url();
        // Parse every credential and trust input before DNS. Besides failing
        // startup validation, attempts may run after operator rotation, so the
        // same no-follow/private/bounded checks are repeated at the wire seam.
        // Invalid local material must never trigger resolver or network I/O.
        let signer = enrollment
            .load_signer()
            .map_err(|_| CallbackTransportError::Configuration)?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .http1_only()
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout);
        if let Some(path) = enrollment.ca_file() {
            let bytes = read_private_file(path, 256 * 1024)
                .map_err(|_| CallbackTransportError::Configuration)?;
            let certificates = parse_certificates(&bytes)
                .map_err(|_| CallbackTransportError::Configuration)?
                .into_iter()
                .map(|der| {
                    reqwest::Certificate::from_der(&der)
                        .map_err(|_| CallbackTransportError::Configuration)
                })
                .collect::<Result<Vec<_>, _>>()?;
            // A configured callback CA is an exclusive enrollment trust domain:
            // do not merge native/built-in roots with these explicitly parsed
            // roots. Without `ca_file`, reqwest retains its documented native
            // root behavior.
            builder = builder.tls_certs_only(certificates);
        }
        if let Some((cert_path, key_path)) = enrollment.mtls_files() {
            let mut bytes = read_private_file(cert_path, 256 * 1024)
                .map_err(|_| CallbackTransportError::Configuration)?;
            let key_bytes = read_private_file(key_path, 64 * 1024)
                .map_err(|_| CallbackTransportError::Configuration)?;
            validate_identity_material(&bytes, &key_bytes)
                .map_err(|_| CallbackTransportError::Configuration)?;
            bytes.extend_from_slice(&key_bytes);
            let identity = reqwest::Identity::from_pem(&bytes)
                .map_err(|_| CallbackTransportError::Configuration)?;
            builder = builder.identity(identity);
        }
        let pinned = self
            .resolve_attempt(target)
            .await
            .map_err(|error| match error {
                PushSecurityError::UnsafeDns => CallbackTransportError::DnsUnsafe,
                PushSecurityError::DnsUnavailable => CallbackTransportError::DnsUnavailable,
                _ => CallbackTransportError::Configuration,
            })?;
        let connector_socket = self.connector_socket(pinned).await;
        builder = builder.resolve(target.host(), connector_socket);
        let client = builder
            .build()
            .map_err(|_| CallbackTransportError::Configuration)?;
        let signature = signer.sign(
            target.as_str(),
            enrollment.endpoint_id(),
            event_id,
            timestamp,
            attempt,
            enrollment.key_generation(),
            body,
        );
        let response = client
            .post(target.as_str())
            .header("Content-Type", "application/a2a+json")
            .header("Content-Digest", content_digest_header(body))
            .header("X-Smesh-Callback-Version", "1")
            .header("X-Smesh-Callback-Event-Id", event_id)
            .header("X-Smesh-Callback-Endpoint-Id", enrollment.endpoint_id())
            .header("X-Smesh-Callback-Timestamp", timestamp)
            .header("X-Smesh-Callback-Attempt", attempt)
            .header(
                "X-Smesh-Callback-Key-Generation",
                enrollment.key_generation(),
            )
            .header("X-Smesh-Callback-Signature", signature)
            .header("Idempotency-Key", event_id)
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| {
                let classified = classify_reqwest_error(error);
                // A required client identity rejected by the peer can surface
                // through hyper as an untyped pre-response reset after the
                // client handshake completes. With configured mTLS material,
                // that pre-header failure is an authentication failure, not a
                // retryable application connection reset.
                if classified == CallbackTransportError::Reset && enrollment.mtls_files().is_some()
                {
                    CallbackTransportError::Tls
                } else {
                    classified
                }
            })?;
        let header_bytes =
            response
                .headers()
                .iter()
                .try_fold(0_usize, |total, (name, value)| {
                    total
                        .checked_add(name.as_str().len())
                        .and_then(|value_total| value_total.checked_add(value.as_bytes().len()))
                        .filter(|value_total| *value_total <= max_response_bytes)
                        .ok_or(CallbackTransportError::ResponseTooLarge)
                })?;
        let status = response.status().as_u16();
        let retry_values: Vec<&reqwest::header::HeaderValue> = response
            .headers()
            .get_all(reqwest::header::RETRY_AFTER)
            .iter()
            .collect();
        let retry_after = if retry_values.iter().all(|value| value.to_str().is_ok()) {
            let values: Vec<&str> = retry_values
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            // Parse only transport syntax here. The worker, after obtaining a
            // fresh authority clock, clamps this untrusted delay to the
            // immutable retry policy and event expiry.
            retry_after_seconds(status, &values, 0, u64::MAX / 1_000)
        } else {
            None
        };
        let mut received = header_bytes;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(classify_reqwest_error)?;
            received = received
                .checked_add(chunk.len())
                .filter(|size| *size <= max_response_bytes)
                .ok_or(CallbackTransportError::ResponseTooLarge)?;
        }
        Ok(CallbackResponse {
            status,
            disposition: classify_status(status),
            retry_after_seconds: retry_after,
        })
    }
}

fn classify_reqwest_error(error: reqwest::Error) -> CallbackTransportError {
    if error.is_timeout() {
        CallbackTransportError::Timeout
    } else if error_chain_contains_rustls(&error) {
        CallbackTransportError::Tls
    } else if error.is_connect() {
        CallbackTransportError::Connect
    } else {
        CallbackTransportError::Reset
    }
}

fn error_chain_contains_rustls(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(source) = current {
        if source.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        // reqwest/hyper's connector wrapper does not preserve rustls::Error as
        // a typed source on every backend. Inspect each private source only for
        // closed TLS classification; none of this text is retained or exposed.
        let classification = source.to_string().to_ascii_lowercase();
        if classification.contains("certificate")
            || classification.contains("tls alert")
            || classification.contains("unknown issuer")
            || classification.contains("not valid for name")
        {
            return true;
        }
        current = source.source();
    }
    false
}

/// Shared live truth used by card/readiness builders. Fatal worker state is
/// sticky for the lifetime of the gateway generation.
#[derive(Debug, Default)]
pub struct PushReadiness {
    ready: AtomicBool,
    fatal: AtomicBool,
    expected_workers: AtomicU16,
    ready_workers: AtomicU16,
}

impl PushReadiness {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            expected_workers: AtomicU16::new(1),
            ready_workers: AtomicU16::new(0),
        }
    }

    /// Construct readiness for a fixed non-zero worker generation.
    #[must_use]
    pub const fn for_workers(worker_count: u16) -> Option<Self> {
        if worker_count == 0 {
            return None;
        }
        Some(Self {
            ready: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            expected_workers: AtomicU16::new(worker_count),
            ready_workers: AtomicU16::new(0),
        })
    }

    pub fn mark_ready(&self) {
        if !self.fatal.load(Ordering::Acquire) {
            self.ready_workers.store(
                self.expected_workers.load(Ordering::Acquire),
                Ordering::Release,
            );
            self.ready.store(true, Ordering::Release);
        }
    }

    /// Record one worker's first successful authority claim cycle. Duplicate
    /// calls saturate and cannot make a partial generation ready.
    pub fn mark_worker_ready(&self) {
        if self.fatal.load(Ordering::Acquire) {
            return;
        }
        let expected = self.expected_workers.load(Ordering::Acquire);
        let prior = self
            .ready_workers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1).min(expected))
            })
            .unwrap_or(expected);
        if prior.saturating_add(1) >= expected && !self.fatal.load(Ordering::Acquire) {
            self.ready.store(true, Ordering::Release);
        }
    }

    pub(crate) fn configure_workers(&self, worker_count: u16) -> bool {
        if worker_count == 0
            || self.ready.load(Ordering::Acquire)
            || self.fatal.load(Ordering::Acquire)
            || self.ready_workers.load(Ordering::Acquire) != 0
        {
            return false;
        }
        self.expected_workers.store(worker_count, Ordering::Release);
        true
    }

    pub fn mark_fatal(&self) {
        self.fatal.store(true, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire) && !self.fatal.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn is_fatal(&self) -> bool {
        self.fatal.load(Ordering::Acquire)
    }
}

/// Stable domain-separated terminal callback identity.
#[must_use]
pub fn delivery_event_id(
    tenant: &str,
    task_id: &str,
    event_sequence: u64,
    task_revision: u64,
    config_id: &str,
    config_generation: u64,
) -> String {
    let mut input = b"smesh-callback/v1".to_vec();
    for value in [tenant.as_bytes(), task_id.as_bytes(), config_id.as_bytes()] {
        push_len(&mut input, value);
    }
    input.extend_from_slice(&event_sequence.to_be_bytes());
    input.extend_from_slice(&task_revision.to_be_bytes());
    input.extend_from_slice(&config_generation.to_be_bytes());
    let digest = Sha256::digest(input);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

/// Immutable retry bounds captured with a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u16,
    base_ms: u64,
    max_ms: u64,
    max_age_ms: u64,
}

impl RetryPolicy {
    pub fn new(
        max_attempts: u16,
        base_ms: u64,
        max_ms: u64,
        max_age_ms: u64,
    ) -> Result<Self, PushSecurityError> {
        if max_attempts == 0
            || max_attempts > 32
            || base_ms == 0
            || max_ms < base_ms
            || max_age_ms < max_ms
        {
            return Err(PushSecurityError::InvalidPolicy);
        }
        Ok(Self {
            max_attempts,
            base_ms,
            max_ms,
            max_age_ms,
        })
    }

    #[must_use]
    pub const fn can_attempt(&self, attempt: u16, age_ms: u64) -> bool {
        attempt > 0 && attempt <= self.max_attempts && age_ms < self.max_age_ms
    }

    /// Select a retry delay and clamp both peer-requested values and jitter to
    /// the immutable policy interval. This keeps transport syntax parsing from
    /// becoming scheduling authority.
    #[must_use]
    pub fn clamp_delay_ms(
        &self,
        requested_ms: Option<u64>,
        attempt: u16,
        sample: u64,
    ) -> Option<u64> {
        let selected = requested_ms.or_else(|| self.full_jitter_ms(attempt, sample))?;
        Some(selected.clamp(self.base_ms, self.max_ms))
    }

    /// Deterministic full-jitter transform over an injected random sample.
    #[must_use]
    pub fn full_jitter_ms(&self, attempt: u16, sample: u64) -> Option<u64> {
        if !self.can_attempt(attempt, 0) {
            return None;
        }
        let exponent = u32::from(attempt.saturating_sub(1)).min(63);
        let ceiling = self
            .base_ms
            .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX))
            .min(self.max_ms);
        Some(sample % ceiling.saturating_add(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Delivered,
    Retry,
    Permanent,
}

#[must_use]
pub fn classify_status(status: u16) -> DeliveryDisposition {
    if (200..=299).contains(&status) {
        DeliveryDisposition::Delivered
    } else if matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504) {
        DeliveryDisposition::Retry
    } else {
        DeliveryDisposition::Permanent
    }
}

/// Parse one Retry-After value for the only statuses allowed to control
/// scheduling. Both delta-seconds and IMF-fixdate are accepted. Invalid,
/// duplicate, past, negative, and overflowing values fall back to jitter.
#[must_use]
pub fn retry_after_seconds(
    status: u16,
    values: &[&str],
    minimum: u64,
    maximum: u64,
) -> Option<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    retry_after_seconds_at(status, values, now, minimum, maximum)
}

/// Deterministic Retry-After parser with an injected Unix timestamp.
#[must_use]
pub fn retry_after_seconds_at(
    status: u16,
    values: &[&str],
    now_epoch_seconds: u64,
    minimum: u64,
    maximum: u64,
) -> Option<u64> {
    if !matches!(status, 429 | 503) || values.len() != 1 || minimum > maximum {
        return None;
    }
    let seconds = if let Ok(delta) = values[0].parse::<u64>() {
        delta
    } else {
        let deadline = httpdate::parse_http_date(values[0]).ok()?;
        let deadline_epoch = deadline
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        deadline_epoch
            .checked_sub(now_epoch_seconds)
            .filter(|delta| *delta > 0)?
    };
    Some(seconds.clamp(minimum, maximum))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    schema: String,
    enabled: bool,
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
    max_pending: u32,
    max_configs_per_task: u16,
    max_configs_per_tenant: u32,
    worker_count: u16,
    claim_batch: u16,
    claim_lease_ms: u64,
    dns_timeout_ms: u64,
    max_dns_answers: u16,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
    max_response_bytes: u32,
    max_attempts: u16,
    base_retry_ms: u64,
    max_retry_ms: u64,
    max_delivery_age_ms: u64,
    enrollments: Vec<RawEnrollment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnrollment {
    tenant: String,
    endpoint_id: String,
    url: String,
    event: String,
    auth: String,
    key_generation: String,
    secret_file: PathBuf,
    #[serde(default)]
    ca_file: Option<PathBuf>,
    #[serde(default)]
    mtls_cert_file: Option<PathBuf>,
    #[serde(default)]
    mtls_key_file: Option<PathBuf>,
}

#[derive(Clone)]
pub struct PushEnrollment {
    tenant: String,
    endpoint_id: String,
    url: CanonicalCallbackUrl,
    key_generation: String,
    secret_file: PathBuf,
    ca_file: Option<PathBuf>,
    mtls_cert_file: Option<PathBuf>,
    mtls_key_file: Option<PathBuf>,
}

impl fmt::Debug for PushEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PushEnrollment")
            .field("tenant", &"[redacted]")
            .field("endpoint_id", &self.endpoint_id)
            .field("url", &"[redacted]")
            .field("key_generation", &self.key_generation)
            .field("secret_file", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PushEnrollment {
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    #[must_use]
    pub fn endpoint_id(&self) -> &str {
        &self.endpoint_id
    }
    #[must_use]
    pub fn url(&self) -> &CanonicalCallbackUrl {
        &self.url
    }
    #[must_use]
    pub fn key_generation(&self) -> &str {
        &self.key_generation
    }
    #[must_use]
    pub fn secret_file(&self) -> &Path {
        &self.secret_file
    }
    #[must_use]
    pub fn ca_file(&self) -> Option<&Path> {
        self.ca_file.as_deref()
    }
    #[must_use]
    pub fn mtls_files(&self) -> Option<(&Path, &Path)> {
        self.mtls_cert_file
            .as_deref()
            .zip(self.mtls_key_file.as_deref())
    }
    /// Load the operator-managed HMAC secret from a no-follow, owner-private file.
    pub fn load_signer(&self) -> Result<CallbackSigner, PushSecurityError> {
        CallbackSigner::new(&read_private_file(&self.secret_file, MAX_SECRET_BYTES)?)
    }
}

#[derive(Clone)]
pub struct PushPolicy {
    enabled: bool,
    policy_id: String,
    policy_revision: u64,
    policy_digest: String,
    max_pending: u32,
    max_configs_per_task: u16,
    max_configs_per_tenant: u32,
    worker_count: u16,
    claim_batch: u16,
    claim_lease_ms: u64,
    dns_timeout_ms: u64,
    max_dns_answers: u16,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
    max_response_bytes: u32,
    max_attempts: u16,
    base_retry_ms: u64,
    max_retry_ms: u64,
    max_delivery_age_ms: u64,
    enrollments: Vec<PushEnrollment>,
}

impl fmt::Debug for PushPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PushPolicy")
            .field("enabled", &self.enabled)
            .field("policy_id", &self.policy_id)
            .field("policy_revision", &self.policy_revision)
            .field("policy_digest", &self.policy_digest)
            .field("max_pending", &self.max_pending)
            .field("max_configs_per_task", &self.max_configs_per_task)
            .field("max_configs_per_tenant", &self.max_configs_per_tenant)
            .field("claim_batch", &self.claim_batch)
            .field("max_attempts", &self.max_attempts)
            .field("enrollment_count", &self.enrollments.len())
            .finish()
    }
}

impl PushPolicy {
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, PushSecurityError> {
        if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
            return Err(PushSecurityError::InvalidPolicy);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| PushSecurityError::InvalidPolicy)?;
        let raw: RawPolicy = toml::from_str(text).map_err(|_| PushSecurityError::InvalidPolicy)?;
        validate_raw_policy(raw)
    }

    pub fn load(path: &Path) -> Result<Self, PushSecurityError> {
        let bytes = read_private_file(path, MAX_POLICY_BYTES)?;
        let policy = Self::parse_bytes(&bytes)?;
        policy.validate_material()?;
        Ok(policy)
    }

    /// Validate every configured secret/root/identity without DNS or network I/O.
    pub fn validate_material(&self) -> Result<(), PushSecurityError> {
        for enrollment in &self.enrollments {
            let _signer = enrollment.load_signer()?;
            if let Some(path) = enrollment.ca_file() {
                let bytes = read_private_file(path, MAX_POLICY_BYTES)?;
                parse_certificates(&bytes)?;
            }
            if let Some((cert_path, key_path)) = enrollment.mtls_files() {
                let cert_bytes = read_private_file(cert_path, MAX_POLICY_BYTES)?;
                let key_bytes = read_private_file(key_path, 64 * 1024)?;
                validate_identity_material(&cert_bytes, &key_bytes)?;
                let mut combined = cert_bytes;
                combined.extend_from_slice(&key_bytes);
                reqwest::Identity::from_pem(&combined)
                    .map_err(|_| PushSecurityError::InvalidSecret)?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
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
    pub const fn max_pending(&self) -> u32 {
        self.max_pending
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
    pub const fn claim_batch(&self) -> u16 {
        self.claim_batch
    }
    #[must_use]
    pub const fn worker_count(&self) -> u16 {
        self.worker_count
    }
    #[must_use]
    pub const fn claim_lease_ms(&self) -> u64 {
        self.claim_lease_ms
    }
    #[must_use]
    pub const fn max_response_bytes(&self) -> u32 {
        self.max_response_bytes
    }
    #[must_use]
    pub fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy::new(
            self.max_attempts,
            self.base_retry_ms,
            self.max_retry_ms,
            self.max_delivery_age_ms,
        )
        .expect("validated push policy")
    }
    #[must_use]
    pub const fn max_attempts(&self) -> u16 {
        self.max_attempts
    }
    #[must_use]
    pub const fn max_delivery_age_ms(&self) -> u64 {
        self.max_delivery_age_ms
    }
    #[must_use]
    pub fn enrollments(&self) -> &[PushEnrollment] {
        &self.enrollments
    }

    pub fn enrollment(
        &self,
        tenant: &str,
        endpoint_id: &str,
        exact_url: &str,
    ) -> Result<&PushEnrollment, PushSecurityError> {
        let requested = CanonicalCallbackUrl::parse(exact_url)?;
        self.enrollments
            .iter()
            .find(|entry| {
                entry.tenant == tenant && entry.endpoint_id == endpoint_id && entry.url == requested
            })
            .ok_or(PushSecurityError::EnrollmentDenied)
    }
}

fn validate_raw_policy(raw: RawPolicy) -> Result<PushPolicy, PushSecurityError> {
    let bounded_id = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    if raw.schema != "smesh-push/1"
        || !bounded_id(&raw.policy_id)
        || raw.policy_revision == 0
        || raw.policy_digest.len() != 71
        || !raw.policy_digest.starts_with("sha256:")
        || !raw.policy_digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || raw.max_pending == 0
        || raw.max_pending > 1_000_000
        || !(1..=32).contains(&raw.max_configs_per_task)
        || raw.max_configs_per_tenant == 0
        || raw.max_configs_per_tenant > raw.max_pending
        || !(1..=64).contains(&raw.worker_count)
        || raw.claim_batch == 0
        || raw.claim_batch > 1_000
        || !(1_000..=300_000).contains(&raw.claim_lease_ms)
        || !(10..=30_000).contains(&raw.dns_timeout_ms)
        || !(1..=32).contains(&raw.max_dns_answers)
        || !(10..=30_000).contains(&raw.connect_timeout_ms)
        || raw.request_timeout_ms < raw.connect_timeout_ms
        || raw.request_timeout_ms > 120_000
        || !(1..=65_536).contains(&raw.max_response_bytes)
        || !(1..=32).contains(&raw.max_attempts)
        || raw.base_retry_ms == 0
        || raw.max_retry_ms < raw.base_retry_ms
        || raw.max_retry_ms > 3_600_000
        || raw.max_delivery_age_ms < raw.max_retry_ms
        || raw.max_delivery_age_ms > 604_800_000
        || (raw.enabled && raw.enrollments.is_empty())
        || raw.enrollments.len() > 10_000
    {
        return Err(PushSecurityError::InvalidPolicy);
    }
    let mut identities = HashSet::new();
    let mut origins = HashSet::new();
    let mut enrollments = Vec::with_capacity(raw.enrollments.len());
    for entry in raw.enrollments {
        if !bounded_id(&entry.tenant)
            || !bounded_id(&entry.endpoint_id)
            || !bounded_id(&entry.key_generation)
            || entry.event != "terminal"
            || entry.auth != "hmac-sha256"
            || !entry.secret_file.is_absolute()
            || entry
                .ca_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || entry
                .mtls_cert_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || entry
                .mtls_key_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || entry.mtls_cert_file.is_some() != entry.mtls_key_file.is_some()
        {
            return Err(PushSecurityError::InvalidPolicy);
        }
        let url = CanonicalCallbackUrl::parse(&entry.url)?;
        if !identities.insert((entry.tenant.clone(), entry.endpoint_id.clone()))
            || !origins.insert((entry.tenant.clone(), url.clone()))
        {
            return Err(PushSecurityError::InvalidPolicy);
        }
        enrollments.push(PushEnrollment {
            tenant: entry.tenant,
            endpoint_id: entry.endpoint_id,
            url,
            key_generation: entry.key_generation,
            secret_file: entry.secret_file,
            ca_file: entry.ca_file,
            mtls_cert_file: entry.mtls_cert_file,
            mtls_key_file: entry.mtls_key_file,
        });
    }
    Ok(PushPolicy {
        enabled: raw.enabled,
        policy_id: raw.policy_id,
        policy_revision: raw.policy_revision,
        policy_digest: raw.policy_digest,
        max_pending: raw.max_pending,
        max_configs_per_task: raw.max_configs_per_task,
        max_configs_per_tenant: raw.max_configs_per_tenant,
        worker_count: raw.worker_count,
        claim_batch: raw.claim_batch,
        claim_lease_ms: raw.claim_lease_ms,
        dns_timeout_ms: raw.dns_timeout_ms,
        max_dns_answers: raw.max_dns_answers,
        connect_timeout_ms: raw.connect_timeout_ms,
        request_timeout_ms: raw.request_timeout_ms,
        max_response_bytes: raw.max_response_bytes,
        max_attempts: raw.max_attempts,
        base_retry_ms: raw.base_retry_ms,
        max_retry_ms: raw.max_retry_ms,
        max_delivery_age_ms: raw.max_delivery_age_ms,
        enrollments,
    })
}

fn parse_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, PushSecurityError> {
    use rustls::pki_types::pem::PemObject as _;
    let certificates: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<_, _>>()
        .map_err(|_| PushSecurityError::InvalidSecret)?;
    if certificates.is_empty() {
        return Err(PushSecurityError::InvalidSecret);
    }
    Ok(certificates
        .into_iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect())
}

fn validate_identity_material(
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<(), PushSecurityError> {
    use rustls::pki_types::pem::PemObject as _;
    parse_certificates(cert_bytes)?;
    let keys: Vec<_> = rustls::pki_types::PrivateKeyDer::pem_slice_iter(key_bytes)
        .collect::<Result<_, _>>()
        .map_err(|_| PushSecurityError::InvalidSecret)?;
    if keys.len() != 1 {
        return Err(PushSecurityError::InvalidSecret);
    }
    Ok(())
}

fn read_private_file(path: &Path, maximum: usize) -> Result<Vec<u8>, PushSecurityError> {
    if !path.is_absolute() {
        return Err(PushSecurityError::InvalidSecret);
    }
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| PushSecurityError::InvalidSecret)?;
    let file = std::fs::File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| PushSecurityError::InvalidSecret)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.is_file()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || usize::try_from(metadata.len())
                .ok()
                .is_none_or(|len| len > maximum)
        {
            return Err(PushSecurityError::InvalidSecret);
        }
    }
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PushSecurityError::InvalidSecret)?;
    if bytes.len() > maximum {
        return Err(PushSecurityError::InvalidSecret);
    }
    Ok(bytes)
}
