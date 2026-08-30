use std::{
    collections::HashMap, fmt, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc,
    time::Duration,
};

use a2a_server::tls::axum_server::accept::Accept;
use axum::{Extension, middleware::AddExtension};
use futures::future::BoxFuture;
use serde::{Deserialize, Deserializer as _};
use sha2::Digest as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::Layer as _;

use crate::auth::{Principal, PrincipalLimits};

/// How the public HTTP boundary is transported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportMode {
    /// Explicit unauthenticated-capable loopback development transport.
    LoopbackPlain,
    /// Plain HTTP accepted only from a loopback reverse proxy; OIDC remains mandatory.
    ReverseProxyLoopback,
    /// rustls terminates HTTPS directly in this process.
    DirectTls,
}

impl FromStr for TransportMode {
    type Err = TransportConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "loopback-plain" => Ok(Self::LoopbackPlain),
            "reverse-proxy-loopback" => Ok(Self::ReverseProxyLoopback),
            "direct-tls" => Ok(Self::DirectTls),
            _ => Err(TransportConfigError::Policy(
                "SMESH_A2A_TRANSPORT_MODE must be loopback-plain, reverse-proxy-loopback, or direct-tls",
            )),
        }
    }
}

/// Direct-TLS client-certificate policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuthMode {
    /// Never request or accept a client certificate as identity.
    Disabled,
    /// Accept no certificate or a valid certificate, rejecting invalid presented chains.
    Optional,
    /// Require a valid client certificate during the TLS handshake.
    Required,
}

impl FromStr for ClientAuthMode {
    type Err = TransportConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err(TransportConfigError::Policy(
                "SMESH_A2A_CLIENT_AUTH_MODE must be disabled, optional, or required",
            )),
        }
    }
}

/// Bounded principal-map parse failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrincipalMapError {
    /// Input exceeded configured byte/entry bounds.
    #[error("principal map exceeds configured byte or entry bounds")]
    Bounds,
    /// Input was malformed, noncanonical, empty, or duplicated a fingerprint.
    #[error("principal map is malformed or contains duplicate/invalid entries")]
    Invalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalRecord {
    issuer: String,
    subject: String,
}

/// Immutable, bounded exact-match map from a verified leaf DER fingerprint to identity.
#[derive(Clone, Default)]
pub struct PrincipalMap(Arc<HashMap<String, Principal>>);

impl PrincipalMap {
    /// Parse a bounded map while preserving duplicate-key detection.
    ///
    /// # Errors
    /// Returns an error for malformed, duplicate, noncanonical, empty, or excessive input.
    pub fn from_json(
        bytes: &[u8],
        max_bytes: usize,
        max_entries: usize,
    ) -> Result<Self, PrincipalMapError> {
        struct MapVisitor {
            max_entries: usize,
        }
        impl<'de> serde::de::Visitor<'de> for MapVisitor {
            type Value = HashMap<String, Principal>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a fingerprint-to-principal JSON object")
            }
            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut result = HashMap::new();
                while let Some((fingerprint, record)) =
                    access.next_entry::<String, PrincipalRecord>()?
                {
                    if result.len() >= self.max_entries || !canonical_fingerprint(&fingerprint) {
                        return Err(serde::de::Error::custom(
                            "invalid or excessive fingerprint entry",
                        ));
                    }
                    let principal = Principal::mutual_tls(
                        record.issuer,
                        record.subject,
                        PrincipalLimits::default(),
                    )
                    .map_err(serde::de::Error::custom)?;
                    if result.insert(fingerprint, principal).is_some() {
                        return Err(serde::de::Error::custom("duplicate fingerprint"));
                    }
                }
                if result.is_empty() {
                    return Err(serde::de::Error::custom("principal map must not be empty"));
                }
                Ok(result)
            }
        }
        if bytes.is_empty() || bytes.len() > max_bytes || max_entries == 0 {
            return Err(PrincipalMapError::Bounds);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let entries = deserializer
            .deserialize_map(MapVisitor { max_entries })
            .map_err(|_| PrincipalMapError::Invalid)?;
        deserializer.end().map_err(|_| PrincipalMapError::Invalid)?;
        Ok(Self(Arc::new(entries)))
    }

    /// Return the principal exact-mapped to a canonical SHA-256 fingerprint.
    #[must_use]
    pub fn lookup(&self, fingerprint: &str) -> Option<Principal> {
        self.0.get(fingerprint).cloned()
    }
}

fn canonical_fingerprint(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Fail-closed production transport policy error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransportConfigError {
    /// A static exposure-policy invariant was violated.
    #[error("{0}")]
    Policy(&'static str),
}

/// Fully parsed production transport policy. Validation is intentionally usable
/// before listener, SQLite, runtime, or mesh resources are acquired.
#[derive(Clone, Debug)]
pub struct ProductionTransportConfig {
    /// HTTP transport boundary mode.
    pub mode: TransportMode,
    /// Direct-TLS client-certificate policy.
    pub client_auth: ClientAuthMode,
    /// Listener address validated against exposure policy.
    pub bind: SocketAddr,
    /// Advertised URL whose host direct TLS must cover.
    pub public_url: String,
    /// Whether OIDC bearer verification is configured.
    pub oidc_enabled: bool,
    /// Serving certificate chain path for direct TLS.
    pub cert_path: Option<PathBuf>,
    /// Serving private-key path for direct TLS.
    pub key_path: Option<PathBuf>,
    /// Client trust-root path when mTLS is enabled.
    pub client_ca_path: Option<PathBuf>,
    /// Fingerprint-to-principal map path when mTLS is enabled.
    pub principal_map_path: Option<PathBuf>,
    /// Total permit-wait plus TLS-handshake deadline.
    pub handshake_timeout: Duration,
    /// Maximum simultaneous accepted or handshaking TLS connections.
    pub max_connections: usize,
}

/// Parse an advertised URL and return only its log-safe scheme/host/port origin.
///
/// # Errors
/// Rejects controls, credentials, query strings, fragments, unsupported schemes,
/// missing hosts, and values above the public configuration bound.
pub fn canonical_public_origin(value: &str) -> Result<String, TransportConfigError> {
    if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(TransportConfigError::Policy("public URL violates bounds"));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| TransportConfigError::Policy("public URL must be a valid HTTP(S) URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(TransportConfigError::Policy(
            "public URL must use HTTP(S) without credentials, query, or fragment",
        ));
    }
    Ok(parsed.origin().ascii_serialization())
}

impl ProductionTransportConfig {
    /// Validate exposure policy and bounded settings without acquiring resources.
    ///
    /// # Errors
    /// Returns a policy error for any unsafe or inconsistent combination.
    pub fn validate_paths_and_policy(&self) -> Result<(), TransportConfigError> {
        let _public_origin = canonical_public_origin(&self.public_url)?;
        if !self.bind.ip().is_loopback() && self.mode != TransportMode::DirectTls {
            return Err(TransportConfigError::Policy(
                "non-loopback binds require direct TLS",
            ));
        }
        if self.mode == TransportMode::ReverseProxyLoopback {
            if !self.bind.ip().is_loopback() {
                return Err(TransportConfigError::Policy(
                    "reverse proxy transport must bind loopback",
                ));
            }
            if !self.oidc_enabled {
                return Err(TransportConfigError::Policy(
                    "reverse proxy transport requires OIDC",
                ));
            }
        }
        if self.mode == TransportMode::DirectTls {
            if self.public_url.len() > 4_096 {
                return Err(TransportConfigError::Policy(
                    "direct TLS public URL exceeds 4096 bytes",
                ));
            }
            let parsed = url::Url::parse(&self.public_url).map_err(|_| {
                TransportConfigError::Policy("direct TLS public URL must be a valid HTTPS URL")
            })?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(TransportConfigError::Policy(
                    "direct TLS public URL must use HTTPS without credentials, query, or fragment",
                ));
            }
            if self.cert_path.is_none() || self.key_path.is_none() {
                return Err(TransportConfigError::Policy(
                    "direct TLS requires certificate and private-key paths",
                ));
            }
            if !self.oidc_enabled && self.client_auth != ClientAuthMode::Required {
                return Err(TransportConfigError::Policy(
                    "direct TLS requires OIDC and/or required mTLS",
                ));
            }
            if self.client_auth != ClientAuthMode::Disabled
                && (self.client_ca_path.is_none() || self.principal_map_path.is_none())
            {
                return Err(TransportConfigError::Policy(
                    "mTLS requires client CA and principal-map paths",
                ));
            }
        } else if self.client_auth != ClientAuthMode::Disabled {
            return Err(TransportConfigError::Policy(
                "client authentication is available only with direct TLS",
            ));
        }
        if self.handshake_timeout.is_zero() || self.handshake_timeout > Duration::from_secs(60) {
            return Err(TransportConfigError::Policy(
                "TLS handshake timeout must be 1ns..=60s",
            ));
        }
        if self.max_connections == 0 || self.max_connections > 1_000_000 {
            return Err(TransportConfigError::Policy(
                "connection bound must be 1..=1000000",
            ));
        }
        Ok(())
    }
}

/// Paths loaded together to form one coherent TLS generation.
#[derive(Clone, Debug)]
pub struct TlsMaterialPaths {
    /// PEM serving certificate chain.
    pub cert: PathBuf,
    /// PEM serving private key; Unix permissions must be owner-only.
    pub key: PathBuf,
    /// Optional PEM client trust roots.
    pub client_ca: Option<PathBuf>,
    /// Optional bounded fingerprint-to-principal JSON map.
    pub principal_map: Option<PathBuf>,
}

/// Opaque TLS material failure that never includes key or certificate bytes.
#[derive(Debug, Error)]
pub enum TlsMaterialError {
    /// Material was missing, insecure, malformed, inconsistent, or violated the SAN invariant.
    #[error("TLS material is missing, insecure, malformed, or inconsistent")]
    Invalid,
}

/// One coherent generation used for both a TLS handshake and its fingerprint map.
pub struct TlsSnapshot {
    generation: u64,
    server_config: Arc<a2a_server::tls::rustls::ServerConfig>,
    principal_map: PrincipalMap,
    leaf_certificate: Vec<u8>,
}

impl TlsSnapshot {
    /// Return the monotonic generation selected atomically per accepted connection.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Return the hardened rustls server configuration for this generation.
    #[must_use]
    pub fn server_config(&self) -> &a2a_server::tls::rustls::ServerConfig {
        &self.server_config
    }
    /// Return the fingerprint map paired with this generation's trust roots.
    #[must_use]
    pub fn principal_map(&self) -> &PrincipalMap {
        &self.principal_map
    }

    /// Check that the advertised HTTPS host is present in the leaf SAN.
    #[must_use]
    pub fn covers_public_url(&self, public_url: &str) -> bool {
        use x509_parser::extensions::GeneralName;
        use x509_parser::prelude::FromDer as _;

        let Ok(url) = url::Url::parse(public_url) else {
            return false;
        };
        let Some(host) = url.host() else {
            return false;
        };
        let Ok((_, certificate)) =
            x509_parser::certificate::X509Certificate::from_der(&self.leaf_certificate)
        else {
            return false;
        };
        let Ok(Some(san)) = certificate.subject_alternative_name() else {
            return false;
        };
        san.value
            .general_names
            .iter()
            .any(|name| match (host.clone(), name) {
                (url::Host::Domain(expected), GeneralName::DNSName(presented)) => {
                    dns_name_matches(expected, presented)
                }
                (url::Host::Ipv4(expected), GeneralName::IPAddress(presented)) => {
                    presented == &expected.octets()
                }
                (url::Host::Ipv6(expected), GeneralName::IPAddress(presented)) => {
                    presented == &expected.octets()
                }
                _ => false,
            })
    }
}

fn dns_name_matches(expected: &str, presented: &str) -> bool {
    if expected.eq_ignore_ascii_case(presented) {
        return true;
    }
    let Some(suffix) = presented.strip_prefix("*.") else {
        return false;
    };
    let Some((_, expected_suffix)) = expected.split_once('.') else {
        return false;
    };
    suffix.contains('.') && !suffix.contains('*') && expected_suffix.eq_ignore_ascii_case(suffix)
}

/// Load and cryptographically validate all files before any network/resource startup.
///
/// # Errors
/// Returns an opaque material error without exposing certificate or key bytes.
pub fn load_tls_snapshot(
    paths: &TlsMaterialPaths,
    client_auth: ClientAuthMode,
    generation: u64,
) -> Result<TlsSnapshot, TlsMaterialError> {
    use a2a_server::tls::rustls;
    use rustls::pki_types::pem::PemObject as _;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut key_bytes = read_bounded_material(&paths.key, 256 * 1024, true)?;
    let cert_bytes = read_bounded_material(&paths.cert, 1024 * 1024, false)?;
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<_, _>>()
        .map_err(|_| TlsMaterialError::Invalid)?;
    if certs.is_empty() {
        return Err(TlsMaterialError::Invalid);
    }
    let leaf_certificate = certs[0].as_ref().to_vec();

    let key_result: Result<Vec<_>, _> =
        rustls::pki_types::PrivateKeyDer::pem_slice_iter(&key_bytes).collect();
    key_bytes.fill(0);
    let mut keys = key_result.map_err(|_| TlsMaterialError::Invalid)?;
    if keys.len() != 1 {
        return Err(TlsMaterialError::Invalid);
    }
    let key = keys.pop().ok_or(TlsMaterialError::Invalid)?;

    let principal_map = if client_auth == ClientAuthMode::Disabled {
        PrincipalMap::default()
    } else {
        let map_path = paths
            .principal_map
            .as_ref()
            .ok_or(TlsMaterialError::Invalid)?;
        let bytes = read_bounded_material(map_path, 1024 * 1024, false)?;
        PrincipalMap::from_json(&bytes, 1024 * 1024, 4096).map_err(|_| TlsMaterialError::Invalid)?
    };

    let builder = rustls::ServerConfig::builder();
    let mut config = if client_auth == ClientAuthMode::Disabled {
        builder.with_no_client_auth().with_single_cert(certs, key)
    } else {
        let ca_path = paths.client_ca.as_ref().ok_or(TlsMaterialError::Invalid)?;
        let ca_bytes = read_bounded_material(ca_path, 1024 * 1024, false)?;
        let ca_certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(&ca_bytes)
            .collect::<Result<_, _>>()
            .map_err(|_| TlsMaterialError::Invalid)?;
        if ca_certs.is_empty() {
            return Err(TlsMaterialError::Invalid);
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert).map_err(|_| TlsMaterialError::Invalid)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots));
        let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
            if client_auth == ClientAuthMode::Optional {
                verifier
                    .allow_unauthenticated()
                    .build()
                    .map_err(|_| TlsMaterialError::Invalid)?
            } else {
                verifier.build().map_err(|_| TlsMaterialError::Invalid)?
            };
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
    }
    .map_err(|_| TlsMaterialError::Invalid)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    config.key_log = Arc::new(rustls::NoKeyLog {});
    Ok(TlsSnapshot {
        generation,
        server_config: Arc::new(config),
        principal_map,
        leaf_certificate,
    })
}

fn read_bounded_material(
    path: &std::path::Path,
    max_bytes: usize,
    private_key: bool,
) -> Result<Vec<u8>, TlsMaterialError> {
    use std::io::Read as _;

    #[cfg(unix)]
    let file = {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| TlsMaterialError::Invalid)?;
        let stat = rustix::fs::fstat(&fd).map_err(|_| TlsMaterialError::Invalid)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || (private_key
                && (stat.st_mode & 0o077 != 0 || stat.st_uid != rustix::process::getuid().as_raw()))
        {
            return Err(TlsMaterialError::Invalid);
        }
        std::fs::File::from(fd)
    };

    #[cfg(not(unix))]
    let file = {
        let file = std::fs::File::open(path).map_err(|_| TlsMaterialError::Invalid)?;
        if !file
            .metadata()
            .map_err(|_| TlsMaterialError::Invalid)?
            .is_file()
        {
            return Err(TlsMaterialError::Invalid);
        }
        file
    };

    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(max_bytes.min(16 * 1024));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| TlsMaterialError::Invalid)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        bytes.fill(0);
        return Err(TlsMaterialError::Invalid);
    }
    Ok(bytes)
}

/// Immutable identity derived after a successful rustls handshake.
#[derive(Clone)]
pub struct TlsConnectionIdentity {
    generation: u64,
    certificate_present: bool,
    principal: Option<Principal>,
}

impl TlsConnectionIdentity {
    /// Construct a test identity after simulating certificate verification.
    #[cfg(test)]
    pub(crate) fn from_verified(generation: u64, principal: Option<Principal>) -> Self {
        Self {
            generation,
            certificate_present: true,
            principal,
        }
    }
    /// Return the TLS generation used for this connection's handshake and identity map.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Whether the peer presented a rustls-verified certificate chain.
    #[must_use]
    pub const fn certificate_present(&self) -> bool {
        self.certificate_present
    }
    /// Return the exact-mapped principal, if the verified certificate was configured.
    #[must_use]
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }
}

impl fmt::Debug for TlsConnectionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsConnectionIdentity")
            .field("generation", &self.generation)
            .field("certificate_present", &self.certificate_present)
            .field("mapped", &self.principal.is_some())
            .finish()
    }
}

/// Atomically replaceable complete TLS material. Failed reloads never mutate it.
pub struct TlsSnapshotManager {
    current: arc_swap::ArcSwap<TlsSnapshot>,
    paths: TlsMaterialPaths,
    client_auth: ClientAuthMode,
    public_url: String,
}

impl TlsSnapshotManager {
    /// Retain material paths, client-auth policy, and advertised URL for every reload.
    ///
    /// The caller must have checked that `snapshot` covers `public_url`; each replacement is
    /// checked again before atomic publication.
    #[must_use]
    pub fn new(
        snapshot: TlsSnapshot,
        paths: TlsMaterialPaths,
        client_auth: ClientAuthMode,
        public_url: String,
    ) -> Self {
        Self {
            current: arc_swap::ArcSwap::from_pointee(snapshot),
            paths,
            client_auth,
            public_url,
        }
    }
    /// Load the currently published complete generation.
    #[must_use]
    pub fn current(&self) -> Arc<TlsSnapshot> {
        self.current.load_full()
    }
    /// Reload and publish only after every component validates.
    ///
    /// # Errors
    /// Returns an opaque material error and retains the previous generation.
    pub fn reload(&self) -> Result<u64, TlsMaterialError> {
        let generation = self.current.load().generation.saturating_add(1);
        let replacement = load_tls_snapshot(&self.paths, self.client_auth, generation)?;
        if !replacement.covers_public_url(&self.public_url) {
            return Err(TlsMaterialError::Invalid);
        }
        self.current.store(Arc::new(replacement));
        Ok(generation)
    }
}

/// Axum acceptor that bounds connection and handshake work and injects verified identity.
#[derive(Clone)]
pub struct TlsIdentityAcceptor {
    snapshots: Arc<TlsSnapshotManager>,
    handshake_timeout: Duration,
    connections: Arc<tokio::sync::Semaphore>,
}

impl TlsIdentityAcceptor {
    /// Build an acceptor with one total permit-wait and TLS-handshake deadline.
    #[must_use]
    pub fn new(
        snapshots: Arc<TlsSnapshotManager>,
        handshake_timeout: Duration,
        max_connections: usize,
    ) -> Self {
        Self {
            snapshots,
            handshake_timeout,
            connections: Arc::new(tokio::sync::Semaphore::new(max_connections)),
        }
    }
}

/// TLS stream that owns a production connection permit for its full lifetime.
pub struct BoundedTlsStream<I> {
    inner: tokio_rustls::server::TlsStream<I>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<I: AsyncRead + AsyncWrite + Unpin> AsyncRead for BoundedTlsStream<I> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<I: AsyncRead + AsyncWrite + Unpin> AsyncWrite for BoundedTlsStream<I> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<I, S> Accept<I, S> for TlsIdentityAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = BoundedTlsStream<I>;
    type Service = AddExtension<S, TlsConnectionIdentity>;
    type Future = BoxFuture<'static, std::io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let snapshots = Arc::clone(&self.snapshots);
        let timeout = self.handshake_timeout;
        let connections = Arc::clone(&self.connections);
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + timeout;
            let permit = tokio::time::timeout_at(deadline, connections.acquire_owned())
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "TLS accept and handshake deadline exceeded",
                    )
                })?
                .map_err(|_| std::io::Error::other("TLS connection limiter closed"))?;
            // Select a coherent generation only after capacity is reserved. Raw
            // sockets queued behind the limiter therefore cannot pin old trust.
            let snapshot = snapshots.current();
            let config = a2a_server::tls::axum_server::tls_rustls::RustlsConfig::from_config(
                Arc::clone(&snapshot.server_config),
            );
            let acceptor = a2a_server::tls::axum_server::tls_rustls::RustlsAcceptor::new(config);
            let (stream, service) =
                tokio::time::timeout_at(deadline, acceptor.accept(stream, service))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "TLS accept and handshake deadline exceeded",
                        )
                    })??;
            let certificates = stream.get_ref().1.peer_certificates();
            let principal = certificates
                .and_then(|chain| chain.first())
                .and_then(|leaf| {
                    let digest = sha2::Sha256::digest(leaf.as_ref());
                    let mut fingerprint = String::with_capacity(71);
                    fingerprint.push_str("sha256:");
                    for byte in digest {
                        use std::fmt::Write as _;
                        let _ = write!(fingerprint, "{byte:02x}");
                    }
                    snapshot.principal_map.lookup(&fingerprint)
                });
            let identity = TlsConnectionIdentity {
                generation: snapshot.generation,
                certificate_present: certificates.is_some_and(|chain| !chain.is_empty()),
                principal,
            };
            Ok((
                BoundedTlsStream {
                    inner: stream,
                    _permit: permit,
                },
                Extension(identity).layer(service),
            ))
        })
    }
}

impl fmt::Display for TransportMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LoopbackPlain => "loopback-plain",
            Self::ReverseProxyLoopback => "reverse-proxy-loopback",
            Self::DirectTls => "direct-tls",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use a2a_server::tls::rustls;
    use rustls::pki_types::pem::PemObject as _;
    use tower::ServiceExt as _;

    struct TestTlsMaterial(std::path::PathBuf);

    impl TestTlsMaterial {
        fn copy_from_fixtures() -> Self {
            let source =
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
            let path = std::env::temp_dir().join(format!(
                "smesh-transport-unit-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock after epoch")
                    .as_nanos()
            ));
            std::fs::create_dir(&path).expect("create isolated TLS material directory");
            std::fs::copy(source.join("server.pem"), path.join("server.pem"))
                .expect("copy server certificate");
            std::fs::copy(source.join("server.key"), path.join("server.key"))
                .expect("copy server key");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(
                    path.join("server.key"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .expect("secure copied server key");
            }
            Self(path)
        }
    }

    impl Drop for TestTlsMaterial {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug)]
    struct TestServerVerifier;

    impl rustls::client::danger::ServerCertVerifier for TestServerVerifier {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn queued_connection_uses_reloaded_generation_and_capacity_recovers() {
        let material = TestTlsMaterial::copy_from_fixtures();
        let root = &material.0;
        let paths = TlsMaterialPaths {
            cert: root.join("server.pem"),
            key: root.join("server.key"),
            client_ca: None,
            principal_map: None,
        };
        let initial = load_tls_snapshot(&paths, ClientAuthMode::Disabled, 1).unwrap();
        let manager = Arc::new(TlsSnapshotManager::new(
            initial,
            paths,
            ClientAuthMode::Disabled,
            "https://localhost".to_owned(),
        ));
        let acceptor = TlsIdentityAcceptor::new(Arc::clone(&manager), Duration::from_secs(2), 1);
        let held = Arc::clone(&acceptor.connections)
            .acquire_owned()
            .await
            .unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let service = tower::service_fn(
            |request: axum::http::Request<axum::body::Body>| async move {
                Ok::<_, std::convert::Infallible>(
                    request
                        .extensions()
                        .get::<TlsConnectionIdentity>()
                        .unwrap()
                        .generation(),
                )
            },
        );
        let mut queued = acceptor.accept(server_io, service);
        assert!(matches!(
            futures::poll!(&mut queued),
            std::task::Poll::Pending
        ));
        assert_eq!(manager.reload().unwrap(), 2);
        drop(held);

        let cert = rustls::pki_types::CertificateDer::pem_file_iter(root.join("server.pem"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let mut roots = a2a_server::tls::rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client_config = a2a_server::tls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(TestServerVerifier));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let client = connector.connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            client_io,
        );
        let (client, server) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(client, queued)
        })
        .await
        .expect("handshake watchdog");
        let _client_stream = client.expect("client handshake");
        let (server_stream, service) = server.expect("server handshake");
        let generation = service
            .oneshot(axum::http::Request::new(axum::body::Body::empty()))
            .await
            .unwrap();
        assert_eq!(generation, 2);
        drop(server_stream);

        // Completion dropped the bounded stream and returned the sole permit.
        let recovered = tokio::time::timeout(
            Duration::from_millis(100),
            Arc::clone(&acceptor.connections).acquire_owned(),
        )
        .await
        .expect("capacity recovery watchdog")
        .unwrap();
        drop(recovered);

        let short = TlsIdentityAcceptor::new(manager, Duration::from_millis(20), 1);
        let held = Arc::clone(&short.connections)
            .acquire_owned()
            .await
            .unwrap();
        let (_client, server) = tokio::io::duplex(1024);
        let Err(error) = short
            .accept(
                server,
                tower::service_fn(|_: axum::http::Request<axum::body::Body>| async {
                    Ok::<_, std::convert::Infallible>(())
                }),
            )
            .await
        else {
            panic!("permit wait must share the total TLS deadline");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(held);
        let recovered = tokio::time::timeout(
            Duration::from_millis(100),
            Arc::clone(&short.connections).acquire_owned(),
        )
        .await
        .expect("timeout recovery watchdog")
        .unwrap();
        drop(recovered);
    }
}
