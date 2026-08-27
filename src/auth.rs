use std::fmt;
use std::sync::Arc;

use thiserror::Error;

/// Cryptographically verified mechanism that established a [`Principal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthenticationMethod {
    /// RFC 9068 bearer access token.
    BearerJwt,
    /// Verified and fingerprint-mapped client certificate.
    MutualTls,
}

/// Byte bounds applied before an authenticated identity is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrincipalLimits {
    /// Maximum UTF-8 byte length of an issuer.
    pub max_issuer_bytes: usize,
    /// Maximum UTF-8 byte length of a subject.
    pub max_subject_bytes: usize,
}

impl Default for PrincipalLimits {
    fn default() -> Self {
        Self {
            max_issuer_bytes: 2_048,
            max_subject_bytes: 256,
        }
    }
}

/// Opaque failure to construct a bounded nonempty principal.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("principal identifier violates configured bounds")]
pub struct PrincipalError;

/// Immutable authenticated issuer/subject tuple and its verification method.
#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
    issuer: Arc<str>,
    subject: Arc<str>,
    authentication: AuthenticationMethod,
}

impl Principal {
    fn new(
        issuer: String,
        subject: String,
        authentication: AuthenticationMethod,
        limits: PrincipalLimits,
    ) -> Result<Self, PrincipalError> {
        if issuer.is_empty()
            || subject.is_empty()
            || issuer.len() > limits.max_issuer_bytes
            || subject.len() > limits.max_subject_bytes
        {
            return Err(PrincipalError);
        }
        Ok(Self {
            issuer: issuer.into(),
            subject: subject.into(),
            authentication,
        })
    }

    /// Construct a bounded identity after a [`BearerVerifier`] has verified a token.
    ///
    /// This does not perform token verification; implementations of
    /// [`BearerVerifier`] are responsible for calling it only after verification.
    ///
    /// # Errors
    /// Returns [`PrincipalError`] when either identifier is empty or exceeds its bound.
    pub fn bearer_for_verifier(
        issuer: String,
        subject: String,
        limits: PrincipalLimits,
    ) -> Result<Self, PrincipalError> {
        Self::new(issuer, subject, AuthenticationMethod::BearerJwt, limits)
    }

    /// Construct a bounded identity selected exclusively from the verified
    /// client-certificate fingerprint map.
    ///
    /// # Errors
    /// Returns [`PrincipalError`] when either identifier is empty or exceeds its bound.
    pub fn mutual_tls(
        issuer: String,
        subject: String,
        limits: PrincipalLimits,
    ) -> Result<Self, PrincipalError> {
        Self::new(issuer, subject, AuthenticationMethod::MutualTls, limits)
    }

    /// Return the verified issuer identifier.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Return the verified subject identifier.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Return the mechanism that established this identity.
    #[must_use]
    pub const fn authentication_method(&self) -> AuthenticationMethod {
        self.authentication
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Principal")
            .field("authentication", &self.authentication)
            .finish_non_exhaustive()
    }
}

/// Time source used for JWT wall-clock and cache-freshness checks.
pub trait AuthClock: Send + Sync {
    /// Current Unix timestamp in seconds.
    fn unix_seconds(&self) -> i64;
    /// Monotonic process-relative timestamp in seconds.
    fn monotonic_seconds(&self) -> u64;
}

/// Syntactically bounded bearer presentation passed to a verifier.
pub struct PresentedBearer<'a>(&'a str);

impl<'a> PresentedBearer<'a> {
    /// Apply cheap bounds before decoding or cryptography.
    ///
    /// # Errors
    /// Returns [`AuthenticationError::Malformed`] for invalid presentation text.
    pub fn new(token: &'a str) -> Result<Self, AuthenticationError> {
        if token.is_empty()
            || token.len() > 16 * 1024
            || token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(AuthenticationError::Malformed);
        }
        Ok(Self(token))
    }

    /// Access the bounded presentation inside a [`BearerVerifier`] implementation.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// Stable, redacted authentication failure categories.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationError {
    /// No credential was available.
    #[error("missing bearer credential")]
    Missing,
    /// Credential presentation syntax or bounds were invalid.
    #[error("malformed bearer credential")]
    Malformed,
    /// Signature, JOSE metadata, or claims were invalid.
    #[error("invalid bearer token")]
    InvalidToken,
    /// The bounded JWKS snapshot does not contain the requested key ID.
    #[error("unknown signing key")]
    UnknownKeyId,
    /// The JWKS provider or its bounded response could not be trusted.
    #[error("identity provider unavailable")]
    ProviderUnavailable,
}

/// Bounded bytes and freshness metadata returned by a [`JwksProvider`].
pub struct JwksFetch {
    /// Raw JWKS JSON body; the verifier enforces its configured byte bound.
    pub body: Vec<u8>,
    /// Provider-advertised freshness, already capped by the provider.
    pub fresh_for: std::time::Duration,
}

#[async_trait::async_trait]
/// Source of bounded JWKS snapshots.
pub trait JwksProvider: Send + Sync {
    /// Fetch at most `max_bytes` of JWKS data.
    async fn fetch(&self, max_bytes: usize) -> Result<JwksFetch, AuthenticationError>;
}

/// Production wall and monotonic clock.
pub struct SystemAuthClock {
    started: std::time::Instant,
}

impl SystemAuthClock {
    /// Start a monotonic epoch while using system time for JWT claims.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
        }
    }
}

impl Default for SystemAuthClock {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthClock for SystemAuthClock {
    fn unix_seconds(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            })
    }

    fn monotonic_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

/// HTTPS-only, no-proxy, no-redirect JWKS provider with bounded streaming.
pub struct HttpJwksProvider {
    url: url::Url,
    client: reqwest::Client,
    default_ttl: std::time::Duration,
    maximum_ttl: std::time::Duration,
}

impl HttpJwksProvider {
    /// Build a bounded, no-proxy, no-redirect rustls provider.
    ///
    /// # Errors
    /// Returns a provider error for invalid/non-HTTPS URLs or client setup failure.
    pub fn new(
        url: &str,
        connect_timeout: std::time::Duration,
        request_timeout: std::time::Duration,
        default_ttl: std::time::Duration,
        maximum_ttl: std::time::Duration,
    ) -> Result<Self, AuthenticationError> {
        let url = url::Url::parse(url).map_err(|_| AuthenticationError::ProviderUnavailable)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(AuthenticationError::ProviderUnavailable);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| AuthenticationError::ProviderUnavailable)?;
        Ok(Self {
            url,
            client,
            default_ttl,
            maximum_ttl,
        })
    }

    fn ttl(&self, headers: &reqwest::header::HeaderMap) -> std::time::Duration {
        let directives: Vec<String> = headers
            .get_all(reqwest::header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| {
                value
                    .split(',')
                    .map(|part| part.trim().to_ascii_lowercase())
            })
            .collect();
        if directives
            .iter()
            .any(|directive| directive == "no-cache" || directive == "no-store")
        {
            return std::time::Duration::ZERO;
        }
        let age = headers
            .get(reqwest::header::AGE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let freshness = directives
            .iter()
            .find_map(|directive| directive.strip_prefix("max-age="))
            .and_then(|seconds| seconds.trim_matches('"').parse::<u64>().ok())
            .map(|seconds| std::time::Duration::from_secs(seconds.saturating_sub(age)))
            .or_else(|| {
                let expires = headers
                    .get(reqwest::header::EXPIRES)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| httpdate::parse_http_date(value).ok())?;
                let base = headers
                    .get(reqwest::header::DATE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| httpdate::parse_http_date(value).ok())
                    .unwrap_or_else(std::time::SystemTime::now);
                Some(
                    expires
                        .duration_since(base)
                        .unwrap_or_default()
                        .saturating_sub(std::time::Duration::from_secs(age)),
                )
            })
            .unwrap_or(self.default_ttl);
        freshness.min(self.maximum_ttl)
    }
}

#[async_trait::async_trait]
impl JwksProvider for HttpJwksProvider {
    async fn fetch(&self, max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
        use futures::StreamExt as _;
        let response = self
            .client
            .get(self.url.clone())
            .header(
                reqwest::header::ACCEPT,
                "application/jwk-set+json, application/json",
            )
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(|_| AuthenticationError::ProviderUnavailable)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > u64::try_from(max_bytes).unwrap_or(u64::MAX))
        {
            return Err(AuthenticationError::ProviderUnavailable);
        }
        let fresh_for = self.ttl(response.headers());
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(max_bytes),
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| AuthenticationError::ProviderUnavailable)?;
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(AuthenticationError::ProviderUnavailable);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(JwksFetch { body, fresh_for })
    }
}

/// Strict RFC 9068/JWKS verifier bounds and accepted identity namespace.
#[derive(Clone)]
pub struct JwtVerifierConfig {
    issuer: Arc<str>,
    audience: Arc<str>,
    algorithms: Arc<[jsonwebtoken::Algorithm]>,
    /// Allowed wall-clock skew for temporal claims.
    pub clock_skew_seconds: i64,
    /// Maximum compact token length.
    pub max_token_bytes: usize,
    /// Maximum decoded JOSE header length.
    pub max_header_bytes: usize,
    /// Maximum decoded claims length.
    pub max_claims_bytes: usize,
    /// Maximum streamed JWKS response length.
    pub max_jwks_bytes: usize,
    /// Maximum keys accepted in one JWKS.
    pub max_keys: usize,
    /// Maximum key-ID length.
    pub max_kid_bytes: usize,
    /// Maximum `exp - iat` token lifetime.
    pub max_token_lifetime_seconds: i64,
    /// Global minimum interval between unknown-key refresh attempts, including outages.
    pub unknown_kid_refresh_interval_seconds: u64,
    principal_limits: PrincipalLimits,
}

impl JwtVerifierConfig {
    /// Build the default strict RS256 policy for an exact issuer and audience.
    #[must_use]
    pub fn strict(issuer: impl Into<Arc<str>>, audience: impl Into<Arc<str>>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: Arc::from([jsonwebtoken::Algorithm::RS256]),
            clock_skew_seconds: 30,
            max_token_bytes: 16 * 1024,
            max_header_bytes: 4 * 1024,
            max_claims_bytes: 8 * 1024,
            max_jwks_bytes: 256 * 1024,
            max_keys: 32,
            max_kid_bytes: 128,
            max_token_lifetime_seconds: 3_600,
            unknown_kid_refresh_interval_seconds: 30,
            principal_limits: PrincipalLimits::default(),
        }
    }
}

struct JwksSnapshot {
    keys: std::collections::HashMap<Arc<str>, Arc<jsonwebtoken::jwk::Jwk>>,
    fresh_until: u64,
    revision: u64,
}

/// RFC 9068 bearer verifier with eager, bounded, singleflight JWKS rotation.
pub struct JwtBearerVerifier {
    config: JwtVerifierConfig,
    provider: Arc<dyn JwksProvider>,
    clock: Arc<dyn AuthClock>,
    cache: tokio::sync::Mutex<JwksSnapshot>,
    refresh_lock: tokio::sync::Mutex<()>,
    last_unknown_refresh: tokio::sync::Mutex<Option<u64>>,
    #[cfg(test)]
    before_refresh_lock: std::sync::Mutex<Option<Arc<tokio::sync::Barrier>>>,
}

#[derive(serde::Deserialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    #[allow(dead_code)]
    aud: serde_json::Value,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    client_id: String,
    jti: String,
}

impl JwtBearerVerifier {
    /// Eagerly fetch and validate the initial JWKS snapshot.
    ///
    /// # Errors
    /// Returns a bounded provider/authentication category if initialization fails.
    pub async fn new(
        config: JwtVerifierConfig,
        provider: Arc<dyn JwksProvider>,
        clock: Arc<dyn AuthClock>,
    ) -> Result<Self, AuthenticationError> {
        let snapshot =
            Self::fetch_snapshot(&config, provider.as_ref(), clock.monotonic_seconds()).await?;
        Ok(Self {
            config,
            provider,
            clock,
            cache: tokio::sync::Mutex::new(snapshot),
            refresh_lock: tokio::sync::Mutex::new(()),
            last_unknown_refresh: tokio::sync::Mutex::new(None),
            #[cfg(test)]
            before_refresh_lock: std::sync::Mutex::new(None),
        })
    }

    async fn fetch_snapshot(
        config: &JwtVerifierConfig,
        provider: &dyn JwksProvider,
        now: u64,
    ) -> Result<JwksSnapshot, AuthenticationError> {
        use base64::Engine as _;

        let fetch = provider.fetch(config.max_jwks_bytes).await?;
        if fetch.body.len() > config.max_jwks_bytes {
            return Err(AuthenticationError::ProviderUnavailable);
        }
        let set: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&fetch.body)
            .map_err(|_| AuthenticationError::ProviderUnavailable)?;
        if set.keys.is_empty() || set.keys.len() > config.max_keys {
            return Err(AuthenticationError::ProviderUnavailable);
        }
        let mut keys = std::collections::HashMap::with_capacity(set.keys.len());
        for key in set.keys {
            let kid = key
                .common
                .key_id
                .as_deref()
                .ok_or(AuthenticationError::ProviderUnavailable)?;
            if kid.is_empty() || kid.len() > config.max_kid_bytes || keys.contains_key(kid) {
                return Err(AuthenticationError::ProviderUnavailable);
            }
            if key
                .common
                .public_key_use
                .as_ref()
                .is_some_and(|usage| *usage != jsonwebtoken::jwk::PublicKeyUse::Signature)
                || key
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|operations| {
                        operations.as_slice() != [jsonwebtoken::jwk::KeyOperations::Verify]
                    })
            {
                return Err(AuthenticationError::ProviderUnavailable);
            }
            let jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa) = &key.algorithm else {
                return Err(AuthenticationError::ProviderUnavailable);
            };
            let modulus = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&rsa.n)
                .map_err(|_| AuthenticationError::ProviderUnavailable)?;
            let first = modulus
                .iter()
                .position(|byte| *byte != 0)
                .ok_or(AuthenticationError::ProviderUnavailable)?;
            let significant = &modulus[first..];
            let modulus_bits = significant
                .len()
                .saturating_mul(8)
                .saturating_sub(significant[0].leading_zeros() as usize);
            let exponent = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&rsa.e)
                .map_err(|_| AuthenticationError::ProviderUnavailable)?;
            if !(2_048..=8_192).contains(&modulus_bits) || exponent.as_slice() != [1, 0, 1] {
                return Err(AuthenticationError::ProviderUnavailable);
            }
            keys.insert(Arc::<str>::from(kid), Arc::new(key));
        }
        Ok(JwksSnapshot {
            keys,
            fresh_until: now.saturating_add(fetch.fresh_for.as_secs()),
            revision: 0,
        })
    }

    async fn key_for(&self, kid: &str) -> Result<Arc<jsonwebtoken::jwk::Jwk>, AuthenticationError> {
        let now = self.clock.monotonic_seconds();
        let observed_revision = {
            let cache = self.cache.lock().await;
            if now < cache.fresh_until
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(Arc::clone(key));
            }
            cache.revision
        };
        #[cfg(test)]
        let before_refresh = { self.before_refresh_lock.lock().unwrap().clone() };
        #[cfg(test)]
        if let Some(barrier) = before_refresh {
            barrier.wait().await;
        }
        let _singleflight = self.refresh_lock.lock().await;
        let known_but_stale = {
            let cache = self.cache.lock().await;
            if now < cache.fresh_until
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(Arc::clone(key));
            }
            if cache.revision != observed_revision
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(Arc::clone(key));
            }
            cache.keys.contains_key(kid)
        };
        let unknown_attempt = !known_but_stale;
        if unknown_attempt {
            let mut last = self.last_unknown_refresh.lock().await;
            if last.is_some_and(|previous| {
                now.saturating_sub(previous) < self.config.unknown_kid_refresh_interval_seconds
            }) {
                return Err(AuthenticationError::UnknownKeyId);
            }
            // Reserve the bounded global unknown-kid refresh window before the
            // outbound call. The reservation deliberately survives provider
            // failure so an outage cannot turn an unknown-kid storm into one
            // network fetch per request.
            *last = Some(now);
        }
        let mut snapshot = Self::fetch_snapshot(&self.config, self.provider.as_ref(), now).await?;
        let result = snapshot
            .keys
            .get(kid)
            .cloned()
            .ok_or(AuthenticationError::UnknownKeyId);
        if unknown_attempt && result.is_ok() {
            // A successful rotation is not an unknown-key miss. Clear its
            // provisional reservation so a genuinely different unknown key
            // can receive the one bounded refresh it had before this hardening.
            *self.last_unknown_refresh.lock().await = None;
        }
        let mut cache = self.cache.lock().await;
        snapshot.revision = cache.revision.saturating_add(1);
        *cache = snapshot;
        result
    }

    /// Verify signature and all configured JOSE/claim constraints.
    ///
    /// # Errors
    /// Returns bounded categories that never include token or claim bytes.
    pub async fn verify(
        &self,
        presented: PresentedBearer<'_>,
    ) -> Result<Principal, AuthenticationError> {
        let token = presented.0;
        if token.len() > self.config.max_token_bytes {
            return Err(AuthenticationError::Malformed);
        }
        let mut segments = token.split('.');
        let header_segment = segments.next().ok_or(AuthenticationError::Malformed)?;
        let claims_segment = segments.next().ok_or(AuthenticationError::Malformed)?;
        if segments.next().is_none()
            || segments.next().is_some()
            || header_segment.len() > self.config.max_header_bytes.saturating_mul(4) / 3 + 4
            || claims_segment.len() > self.config.max_claims_bytes.saturating_mul(4) / 3 + 4
        {
            return Err(AuthenticationError::Malformed);
        }
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| AuthenticationError::Malformed)?;
        if !self.config.algorithms.contains(&header.alg)
            || !header.typ.as_deref().is_some_and(|typ| {
                typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt")
            })
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.crit.is_some()
            || header.zip.is_some()
        {
            return Err(AuthenticationError::InvalidToken);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.is_empty() && kid.len() <= self.config.max_kid_bytes)
            .ok_or(AuthenticationError::InvalidToken)?;
        let jwk = self.key_for(kid).await?;
        if jwk.common.key_algorithm.is_some()
            && jwk.common.key_algorithm != Some(jsonwebtoken::jwk::KeyAlgorithm::RS256)
        {
            return Err(AuthenticationError::InvalidToken);
        }
        let key = jsonwebtoken::DecodingKey::from_jwk(&jwk)
            .map_err(|_| AuthenticationError::InvalidToken)?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.leeway = 0;
        validation.set_issuer(&[self.config.issuer.as_ref()]);
        validation.set_audience(&[self.config.audience.as_ref()]);
        validation.set_required_spec_claims(&[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "client_id",
            "jti",
        ]);
        let data = jsonwebtoken::decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|_| AuthenticationError::InvalidToken)?;
        let claims = data.claims;
        if claims.iss != self.config.issuer.as_ref()
            || claims.client_id.is_empty()
            || claims.client_id.len() > 256
            || claims.jti.is_empty()
            || claims.jti.len() > 256
        {
            return Err(AuthenticationError::InvalidToken);
        }
        let now = self.clock.unix_seconds();
        let skew = self.config.clock_skew_seconds;
        let iat = claims.iat.ok_or(AuthenticationError::InvalidToken)?;
        if claims.exp <= now.saturating_sub(skew)
            || claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(skew))
            || iat > now.saturating_add(skew)
            || claims.exp <= iat
            || claims.exp.saturating_sub(iat) > self.config.max_token_lifetime_seconds
        {
            return Err(AuthenticationError::InvalidToken);
        }
        Principal::bearer_for_verifier(claims.iss, claims.sub, self.config.principal_limits)
            .map_err(|_| AuthenticationError::InvalidToken)
    }
}

#[async_trait::async_trait]
/// Interface consumed by the HTTP authentication boundary.
pub trait BearerVerifier: Send + Sync {
    /// Verify a bounded presentation and return its immutable identity.
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError>;
}

#[async_trait::async_trait]
impl BearerVerifier for JwtBearerVerifier {
    async fn verify(&self, token: PresentedBearer<'_>) -> Result<Principal, AuthenticationError> {
        JwtBearerVerifier::verify(self, token).await
    }
}

/// Internal authenticated-principal bridge header stripped from external requests.
pub const RESERVED_PRINCIPAL_HEADER: &str = "x-smesh-authenticated-principal";

tokio::task_local! {
    static AUTHORITATIVE_PRINCIPAL: Principal;
}

/// Return the server-authenticated principal while an authenticated handler method is running.
/// Caller-controlled protocol metadata is never consulted.
#[must_use]
pub fn current_principal() -> Option<Principal> {
    AUTHORITATIVE_PRINCIPAL.try_with(Clone::clone).ok()
}

#[derive(Clone)]
struct PrincipalBridge {
    key: [u8; 32],
}

impl PrincipalBridge {
    fn seal(&self, principal: &Principal) -> String {
        use base64::Engine as _;
        use hmac::Mac as _;
        let issuer =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.issuer().as_bytes());
        let subject =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(principal.subject().as_bytes());
        let method = match principal.authentication_method() {
            AuthenticationMethod::BearerJwt => "bearer",
            AuthenticationMethod::MutualTls => "mtls",
        };
        let payload = format!("v1.{issuer}.{subject}.{method}");
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.key)
            .expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let tag =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{payload}.{tag}")
    }

    fn open(&self, value: &str) -> Result<Principal, AuthenticationError> {
        use base64::Engine as _;
        use hmac::Mac as _;
        let mut parts = value.split('.');
        let version = parts.next();
        let issuer = parts.next();
        let subject = parts.next();
        let method = parts.next();
        let tag = parts.next();
        if version != Some("v1")
            || !matches!(method, Some("bearer" | "mtls"))
            || parts.next().is_some()
        {
            return Err(AuthenticationError::InvalidToken);
        }
        let (issuer, subject, tag) = (
            issuer.ok_or(AuthenticationError::InvalidToken)?,
            subject.ok_or(AuthenticationError::InvalidToken)?,
            tag.ok_or(AuthenticationError::InvalidToken)?,
        );
        let method = method.ok_or(AuthenticationError::InvalidToken)?;
        let payload = format!("v1.{issuer}.{subject}.{method}");
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| AuthenticationError::InvalidToken)?;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.key)
            .expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        mac.verify_slice(&tag)
            .map_err(|_| AuthenticationError::InvalidToken)?;
        let issuer = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(issuer)
                .map_err(|_| AuthenticationError::InvalidToken)?,
        )
        .map_err(|_| AuthenticationError::InvalidToken)?;
        let subject = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(subject)
                .map_err(|_| AuthenticationError::InvalidToken)?,
        )
        .map_err(|_| AuthenticationError::InvalidToken)?;
        let principal = match method {
            "bearer" => Principal::bearer_for_verifier(issuer, subject, PrincipalLimits::default()),
            "mtls" => Principal::mutual_tls(issuer, subject, PrincipalLimits::default()),
            _ => return Err(AuthenticationError::InvalidToken),
        };
        principal.map_err(|_| AuthenticationError::InvalidToken)
    }
}

/// Configured bearer/mTLS policy and internal principal-bridge key.
#[derive(Clone)]
pub struct AuthState {
    verifier: Option<Arc<dyn BearerVerifier>>,
    mutual_tls: bool,
    mutual_tls_required: bool,
    bridge: PrincipalBridge,
}

impl AuthState {
    /// Build a bearer-only authentication boundary.
    #[must_use]
    pub fn new(verifier: Arc<dyn BearerVerifier>, bridge_key: [u8; 32]) -> Self {
        Self {
            verifier: Some(verifier),
            mutual_tls: false,
            mutual_tls_required: false,
            bridge: PrincipalBridge { key: bridge_key },
        }
    }

    /// Build an authentication boundary where only a mapped verified client
    /// certificate can establish identity.
    #[must_use]
    pub fn mutual_tls_only(bridge_key: [u8; 32]) -> Self {
        Self {
            verifier: None,
            mutual_tls: true,
            mutual_tls_required: true,
            bridge: PrincipalBridge { key: bridge_key },
        }
    }

    /// Permit mapped mTLS identity as an alternative to bearer identity.
    #[must_use]
    pub fn with_mutual_tls(mut self) -> Self {
        self.mutual_tls = true;
        self.mutual_tls_required = false;
        self
    }

    /// Require mapped mTLS identity, optionally bound to an identical bearer identity.
    #[must_use]
    pub fn with_required_mutual_tls(mut self) -> Self {
        self.mutual_tls = true;
        self.mutual_tls_required = true;
        self
    }

    /// Whether bearer verification is configured.
    #[must_use]
    pub const fn bearer_enabled(&self) -> bool {
        self.verifier.is_some()
    }

    /// Whether mapped client certificates may establish identity.
    #[must_use]
    pub const fn mutual_tls_enabled(&self) -> bool {
        self.mutual_tls
    }

    /// Whether every authenticated request must present a mapped client certificate.
    #[must_use]
    pub const fn mutual_tls_required(&self) -> bool {
        self.mutual_tls_required
    }

    /// Wrap an A2A handler so deferred handler work receives the verified principal.
    #[must_use]
    pub fn wrap_handler(
        &self,
        inner: Arc<dyn a2a_server::RequestHandler>,
    ) -> Arc<AuthenticatedRequestHandler> {
        Arc::new(AuthenticatedRequestHandler {
            inner,
            bridge: self.bridge.clone(),
        })
    }

    /// Wrap an executor so spawned execution and stream polls retain principal scope.
    #[must_use]
    pub fn wrap_executor<E: a2a_server::AgentExecutor>(
        &self,
        inner: E,
    ) -> PrincipalScopedExecutor<E> {
        PrincipalScopedExecutor {
            inner: Arc::new(inner),
            bridge: self.bridge.clone(),
        }
    }
}

fn unauthorized(invalid_token: bool, bearer_enabled: bool) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let mut response = (axum::http::StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    if bearer_enabled {
        let challenge = if invalid_token {
            "Bearer realm=\"smesh-a2a\", error=\"invalid_token\""
        } else {
            "Bearer realm=\"smesh-a2a\""
        };
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static(challenge),
        );
    }
    response
}

/// Axum middleware that strips spoofable credentials and establishes one authoritative principal.
pub async fn authenticate_request(
    axum::extract::State(state): axum::extract::State<AuthState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION};
    for value in request.headers_mut().values_mut() {
        value.set_sensitive(true);
    }
    let credentials: Vec<_> = request.headers().get_all(AUTHORIZATION).iter().collect();
    let raw = match credentials.as_slice() {
        [] => None,
        [value] => match value.to_str() {
            Ok(raw) if !raw.contains(',') => Some(raw.to_owned()),
            _ => return unauthorized(true, state.bearer_enabled()),
        },
        _ => return unauthorized(true, state.bearer_enabled()),
    };
    for name in [
        AUTHORIZATION.as_str(),
        PROXY_AUTHORIZATION.as_str(),
        COOKIE.as_str(),
        RESERVED_PRINCIPAL_HEADER,
        "forwarded",
        "x-forwarded-client-cert",
        "x-client-cert",
    ] {
        request.headers_mut().remove(name);
    }

    let tls_identity = request
        .extensions()
        .get::<crate::transport::TlsConnectionIdentity>();
    let mtls_principal = tls_identity
        .and_then(|identity| identity.principal())
        .cloned();
    if mtls_principal.is_some() && !state.mutual_tls_enabled() {
        return unauthorized(true, state.bearer_enabled());
    }
    if tls_identity
        .is_some_and(|identity| identity.certificate_present() && identity.principal().is_none())
    {
        // A certificate was presented and cryptographically accepted by rustls,
        // but it is not mapped to an application identity. This is an mTLS
        // identity failure, so advertising Bearer would incorrectly suggest
        // that another credential could recover the same request.
        return unauthorized(true, false);
    }
    if state.mutual_tls_required() && mtls_principal.is_none() {
        return unauthorized(false, state.bearer_enabled());
    }
    let bearer_principal = if let Some(raw) = raw {
        let Some(separator) = raw.find(' ') else {
            return unauthorized(true, state.bearer_enabled());
        };
        let scheme = &raw[..separator];
        let token = raw[separator..].trim_start_matches(' ');
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.contains(char::is_whitespace)
        {
            return unauthorized(true, state.bearer_enabled());
        }
        let Ok(presented) = PresentedBearer::new(token) else {
            return unauthorized(true, state.bearer_enabled());
        };
        let Some(verifier) = state.verifier.as_ref() else {
            return unauthorized(true, state.bearer_enabled());
        };
        let Ok(principal) = verifier.verify(presented).await else {
            return unauthorized(true, state.bearer_enabled());
        };
        Some(principal)
    } else {
        None
    };

    let principal = match (mtls_principal, bearer_principal) {
        (Some(mtls), Some(bearer))
            if mtls.issuer() == bearer.issuer() && mtls.subject() == bearer.subject() =>
        {
            mtls
        }
        (Some(_), Some(_)) => return unauthorized(true, state.bearer_enabled()),
        (Some(principal), None) | (None, Some(principal)) => principal,
        (None, None) => return unauthorized(false, state.bearer_enabled()),
    };
    let Ok(mut bridge) = axum::http::HeaderValue::from_str(&state.bridge.seal(&principal)) else {
        return unauthorized(true, state.bearer_enabled());
    };
    bridge.set_sensitive(true);
    request
        .headers_mut()
        .insert(RESERVED_PRINCIPAL_HEADER, bridge);
    request.extensions_mut().insert(Arc::new(principal));
    next.run(request).await
}

/// Verified principal paired with sanitized A2A service parameters.
pub struct AuthenticatedRequest {
    principal: Principal,
    service_params: a2a_server::ServiceParams,
}

impl AuthenticatedRequest {
    fn extract(
        params: &a2a_server::ServiceParams,
        bridge: &PrincipalBridge,
    ) -> Result<Self, AuthenticationError> {
        let values = params
            .get(RESERVED_PRINCIPAL_HEADER)
            .ok_or(AuthenticationError::Missing)?;
        if values.len() != 1 {
            return Err(AuthenticationError::InvalidToken);
        }
        let principal = bridge.open(&values[0])?;
        let mut service_params = params.clone();
        for name in ["authorization", "proxy-authorization", "cookie"] {
            service_params.remove(name);
        }
        Ok(Self {
            principal,
            service_params,
        })
    }

    /// Return the immutable authenticated identity.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Return metadata after credential and internal bridge headers were removed.
    #[must_use]
    pub fn service_params(&self) -> &a2a_server::ServiceParams {
        &self.service_params
    }
}

fn scoped_stream(
    principal: Principal,
    stream: futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>,
) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>> {
    use futures::StreamExt as _;

    Box::pin(futures::stream::unfold(
        (stream, principal),
        |(mut stream, principal)| async move {
            let item = AUTHORITATIVE_PRINCIPAL
                .scope(principal.clone(), stream.next())
                .await?;
            Some((item, (stream, principal)))
        },
    ))
}

/// Restores an authenticated principal at the executor boundary crossed by
/// `DefaultRequestHandler`'s spawned execution task.
pub struct PrincipalScopedExecutor<E: a2a_server::AgentExecutor> {
    inner: Arc<E>,
    bridge: PrincipalBridge,
}

impl<E: a2a_server::AgentExecutor> PrincipalScopedExecutor<E> {
    /// Build an executor wrapper with the same bridge key as the HTTP boundary.
    #[must_use]
    pub fn new(inner: E, bridge_key: [u8; 32]) -> Self {
        Self {
            inner: Arc::new(inner),
            bridge: PrincipalBridge { key: bridge_key },
        }
    }

    fn request(
        &self,
        mut context: a2a_server::ExecutorContext,
    ) -> Result<(Principal, a2a_server::ExecutorContext), a2a::A2AError> {
        let values = context
            .service_params
            .get(RESERVED_PRINCIPAL_HEADER)
            .ok_or_else(|| a2a::A2AError::internal("authenticated executor context missing"))?;
        if values.len() != 1 {
            return Err(a2a::A2AError::internal(
                "authenticated executor context missing",
            ));
        }
        let principal = self
            .bridge
            .open(&values[0])
            .map_err(|_| a2a::A2AError::internal("authenticated executor context missing"))?;
        for name in [
            RESERVED_PRINCIPAL_HEADER,
            "authorization",
            "proxy-authorization",
            "cookie",
        ] {
            context.service_params.remove(name);
        }
        Ok((principal, context))
    }

    fn invalid_stream(
        error: a2a::A2AError,
    ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>> {
        Box::pin(futures::stream::once(async move { Err(error) }))
    }
}

impl<E: a2a_server::AgentExecutor> a2a_server::AgentExecutor for PrincipalScopedExecutor<E> {
    fn execute(
        &self,
        context: a2a_server::ExecutorContext,
    ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>> {
        use futures::StreamExt as _;

        let (principal, context) = match self.request(context) {
            Ok(request) => request,
            Err(error) => return Self::invalid_stream(error),
        };
        let inner = Arc::clone(&self.inner);
        let invocation_principal = principal.clone();
        let stream = futures::stream::once(async move {
            AUTHORITATIVE_PRINCIPAL
                .scope(invocation_principal, async move { inner.execute(context) })
                .await
        })
        .flatten();
        scoped_stream(principal, Box::pin(stream))
    }

    fn cancel(
        &self,
        context: a2a_server::ExecutorContext,
    ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>> {
        use futures::StreamExt as _;

        let (principal, context) = match self.request(context) {
            Ok(request) => request,
            Err(error) => return Self::invalid_stream(error),
        };
        let inner = Arc::clone(&self.inner);
        let invocation_principal = principal.clone();
        let stream = futures::stream::once(async move {
            AUTHORITATIVE_PRINCIPAL
                .scope(invocation_principal, async move { inner.cancel(context) })
                .await
        })
        .flatten();
        scoped_stream(principal, Box::pin(stream))
    }
}

/// A2A handler wrapper that restores principal scope for every handler method.
pub struct AuthenticatedRequestHandler {
    inner: Arc<dyn a2a_server::RequestHandler>,
    bridge: PrincipalBridge,
}

impl AuthenticatedRequestHandler {
    /// Build a handler wrapper with the same bridge key as the HTTP boundary.
    #[must_use]
    pub fn new(inner: Arc<dyn a2a_server::RequestHandler>, bridge_key: [u8; 32]) -> Self {
        Self {
            inner,
            bridge: PrincipalBridge { key: bridge_key },
        }
    }

    fn request(
        &self,
        params: &a2a_server::ServiceParams,
    ) -> Result<AuthenticatedRequest, a2a::A2AError> {
        AuthenticatedRequest::extract(params, &self.bridge)
            .map_err(|_| a2a::A2AError::internal("authenticated request context missing"))
    }
}

#[async_trait::async_trait]
impl a2a_server::RequestHandler for AuthenticatedRequestHandler {
    async fn send_message(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::SendMessageRequest,
    ) -> Result<a2a::SendMessageResponse, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.send_message(request.service_params(), req),
            )
            .await
    }

    async fn send_streaming_message(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::SendMessageRequest,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>,
        a2a::A2AError,
    > {
        let request = self.request(params)?;
        let principal = request.principal.clone();
        let stream = AUTHORITATIVE_PRINCIPAL
            .scope(
                principal.clone(),
                self.inner
                    .send_streaming_message(request.service_params(), req),
            )
            .await?;
        Ok(scoped_stream(principal, stream))
    }

    async fn get_task(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::GetTaskRequest,
    ) -> Result<a2a::Task, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.get_task(request.service_params(), req),
            )
            .await
    }

    async fn list_tasks(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::ListTasksRequest,
    ) -> Result<a2a::ListTasksResponse, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.list_tasks(request.service_params(), req),
            )
            .await
    }

    async fn cancel_task(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::CancelTaskRequest,
    ) -> Result<a2a::Task, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.cancel_task(request.service_params(), req),
            )
            .await
    }

    async fn subscribe_to_task(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::SubscribeToTaskRequest,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>,
        a2a::A2AError,
    > {
        let request = self.request(params)?;
        let principal = request.principal.clone();
        let stream = AUTHORITATIVE_PRINCIPAL
            .scope(
                principal.clone(),
                self.inner.subscribe_to_task(request.service_params(), req),
            )
            .await?;
        Ok(scoped_stream(principal, stream))
    }

    async fn create_push_config(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::TaskPushNotificationConfig,
    ) -> Result<a2a::TaskPushNotificationConfig, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.create_push_config(request.service_params(), req),
            )
            .await
    }

    async fn get_push_config(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::GetTaskPushNotificationConfigRequest,
    ) -> Result<a2a::TaskPushNotificationConfig, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.get_push_config(request.service_params(), req),
            )
            .await
    }

    async fn list_push_configs(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::ListTaskPushNotificationConfigsRequest,
    ) -> Result<a2a::ListTaskPushNotificationConfigsResponse, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.list_push_configs(request.service_params(), req),
            )
            .await
    }

    async fn delete_push_config(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::DeleteTaskPushNotificationConfigRequest,
    ) -> Result<(), a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner.delete_push_config(request.service_params(), req),
            )
            .await
    }

    async fn get_extended_agent_card(
        &self,
        params: &a2a_server::ServiceParams,
        req: a2a::GetExtendedAgentCardRequest,
    ) -> Result<a2a::AgentCard, a2a::A2AError> {
        let request = self.request(params)?;
        AUTHORITATIVE_PRINCIPAL
            .scope(
                request.principal.clone(),
                self.inner
                    .get_extended_agent_card(request.service_params(), req),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_jwks_client_rejects_non_https_urls() {
        let result = HttpJwksProvider::new(
            "http://issuer.example/jwks",
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(3600),
        );
        assert!(result.is_err());
    }

    #[test]
    fn typed_authenticated_request_preserves_bridge_and_strips_credentials() {
        let principal = Principal::bearer_for_verifier(
            "https://issuer.example".to_owned(),
            "agent-17".to_owned(),
            PrincipalLimits::default(),
        )
        .expect("principal");
        let codec = PrincipalBridge { key: [9; 32] };
        let mut params = a2a_server::ServiceParams::new();
        assert!(AuthenticatedRequest::extract(&params, &codec).is_err());
        params.insert(
            RESERVED_PRINCIPAL_HEADER.to_owned(),
            vec![codec.seal(&principal)],
        );
        params.insert(
            "authorization".to_owned(),
            vec!["should-never-survive".to_owned()],
        );
        let request = AuthenticatedRequest::extract(&params, &codec).expect("server bridge");
        assert_eq!(request.principal(), &principal);
        assert_eq!(
            request
                .service_params()
                .get(RESERVED_PRINCIPAL_HEADER)
                .map(Vec::len),
            Some(1),
            "authenticated bridge must survive until the executor boundary"
        );
        assert!(!request.service_params().contains_key("authorization"));
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn principal_scoped_executor_scopes_invocation_and_every_deferred_poll() {
        struct PollProbe {
            observations: Arc<std::sync::Mutex<Vec<&'static str>>>,
        }

        impl a2a_server::AgentExecutor for PollProbe {
            fn execute(
                &self,
                context: a2a_server::ExecutorContext,
            ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>
            {
                assert_eq!(current_principal().unwrap().subject(), "agent-17");
                assert!(context.service_params.is_empty());
                self.observations.lock().unwrap().push("execute");
                let observations = Arc::clone(&self.observations);
                let mut polls = 0;
                Box::pin(futures::stream::poll_fn(move |_| {
                    assert_eq!(current_principal().unwrap().subject(), "agent-17");
                    polls += 1;
                    observations.lock().unwrap().push("execute-poll");
                    if polls <= 2 {
                        std::task::Poll::Ready(Some(Err(a2a::A2AError::internal("probe"))))
                    } else {
                        std::task::Poll::Ready(None)
                    }
                }))
            }

            fn cancel(
                &self,
                context: a2a_server::ExecutorContext,
            ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>
            {
                assert_eq!(current_principal().unwrap().subject(), "agent-17");
                assert!(context.service_params.is_empty());
                self.observations.lock().unwrap().push("cancel");
                let observations = Arc::clone(&self.observations);
                let mut polls = 0;
                Box::pin(futures::stream::poll_fn(move |_| {
                    assert_eq!(current_principal().unwrap().subject(), "agent-17");
                    polls += 1;
                    observations.lock().unwrap().push("cancel-poll");
                    if polls <= 2 {
                        std::task::Poll::Ready(Some(Err(a2a::A2AError::internal("probe"))))
                    } else {
                        std::task::Poll::Ready(None)
                    }
                }))
            }
        }

        fn context(bridge: &PrincipalBridge, principal: &Principal) -> a2a_server::ExecutorContext {
            let mut service_params = a2a_server::ServiceParams::new();
            service_params.insert(
                RESERVED_PRINCIPAL_HEADER.to_owned(),
                vec![bridge.seal(principal)],
            );
            service_params.insert("authorization".to_owned(), vec!["raw".to_owned()]);
            a2a_server::ExecutorContext {
                message: None,
                task_id: "task-17".to_owned(),
                stored_task: None,
                context_id: "context-17".to_owned(),
                metadata: None,
                user: None,
                service_params,
                tenant: None,
            }
        }

        use futures::StreamExt as _;
        let principal = Principal::bearer_for_verifier(
            "https://issuer.example".to_owned(),
            "agent-17".to_owned(),
            PrincipalLimits::default(),
        )
        .unwrap();
        let bridge = PrincipalBridge { key: [51; 32] };
        let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
        let executor = Arc::new(PrincipalScopedExecutor::new(
            PollProbe {
                observations: Arc::clone(&observations),
            },
            [51; 32],
        ));

        assert!(current_principal().is_none());
        for cancel in [false, true] {
            let executor = Arc::clone(&executor);
            let context = context(&bridge, &principal);
            tokio::time::timeout(std::time::Duration::from_secs(2), async move {
                let mut stream = tokio::spawn(async move {
                    if cancel {
                        a2a_server::AgentExecutor::cancel(executor.as_ref(), context)
                    } else {
                        a2a_server::AgentExecutor::execute(executor.as_ref(), context)
                    }
                })
                .await
                .unwrap();
                while stream.next().await.is_some() {}
            })
            .await
            .expect("bounded executor stream");
            assert!(current_principal().is_none());
        }
        assert_eq!(
            observations.lock().unwrap().as_slice(),
            [
                "execute",
                "execute-poll",
                "execute-poll",
                "execute-poll",
                "cancel",
                "cancel-poll",
                "cancel-poll",
                "cancel-poll",
            ]
        );
    }

    #[tokio::test]
    async fn default_request_handler_spawned_execute_and_cancel_restore_principal() {
        struct SpawnProbe {
            observations: Arc<std::sync::Mutex<Vec<&'static str>>>,
            executed: Arc<tokio::sync::Notify>,
        }

        impl a2a_server::AgentExecutor for SpawnProbe {
            fn execute(
                &self,
                context: a2a_server::ExecutorContext,
            ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>
            {
                assert_eq!(current_principal().unwrap().subject(), "agent-17");
                assert!(context.service_params.is_empty());
                self.observations.lock().unwrap().push("execute");
                self.executed.notify_one();
                Box::pin(futures::stream::empty())
            }

            fn cancel(
                &self,
                context: a2a_server::ExecutorContext,
            ) -> futures::stream::BoxStream<'static, Result<a2a::StreamResponse, a2a::A2AError>>
            {
                assert_eq!(current_principal().unwrap().subject(), "agent-17");
                assert!(context.service_params.is_empty());
                self.observations.lock().unwrap().push("cancel");
                Box::pin(futures::stream::empty())
            }
        }

        use a2a_server::{RequestHandler as _, TaskStore as _};
        let principal = Principal::bearer_for_verifier(
            "https://issuer.example".to_owned(),
            "agent-17".to_owned(),
            PrincipalLimits::default(),
        )
        .unwrap();
        let bridge = PrincipalBridge { key: [61; 32] };
        let mut params = a2a_server::ServiceParams::new();
        params.insert(
            RESERVED_PRINCIPAL_HEADER.to_owned(),
            vec![bridge.seal(&principal)],
        );
        let store = a2a_server::InMemoryTaskStore::new();
        store
            .create(a2a::Task {
                id: "cancel-task".to_owned(),
                context_id: "cancel-context".to_owned(),
                status: a2a::TaskStatus {
                    state: a2a::TaskState::Submitted,
                    message: None,
                    timestamp: None,
                },
                artifacts: None,
                history: None,
                metadata: None,
            })
            .await
            .unwrap();
        let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
        let auth = AuthState::new(Arc::new(AcceptingVerifier), [61; 32]);
        let executed = Arc::new(tokio::sync::Notify::new());
        let default = a2a_server::DefaultRequestHandler::new(
            auth.wrap_executor(SpawnProbe {
                observations: Arc::clone(&observations),
                executed: Arc::clone(&executed),
            }),
            store,
        );
        let inner: Arc<dyn a2a_server::RequestHandler> = Arc::new(default);
        let handler = auth.wrap_handler(inner);

        let request = a2a::SendMessageRequest {
            message: a2a::Message::new(a2a::Role::User, vec![a2a::Part::text("probe")]),
            configuration: None,
            metadata: None,
            tenant: None,
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handler.send_message(&params, request),
        )
        .await
        .expect("bounded spawned execution");
        tokio::time::timeout(std::time::Duration::from_secs(2), executed.notified())
            .await
            .expect("spawned executor invocation");
        handler
            .cancel_task(
                &params,
                a2a::CancelTaskRequest {
                    id: "cancel-task".to_owned(),
                    metadata: None,
                    tenant: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            observations.lock().unwrap().as_slice(),
            ["execute", "cancel"]
        );
        assert!(current_principal().is_none());
    }

    #[test]
    fn principal_bridge_is_authenticated_and_redacted() {
        let codec = PrincipalBridge { key: [9; 32] };
        let principal = Principal::bearer_for_verifier(
            "https://issuer.example".to_owned(),
            "agent-17".to_owned(),
            PrincipalLimits::default(),
        )
        .expect("principal");
        let sealed = codec.seal(&principal);
        assert!(!sealed.contains("issuer.example"));
        assert!(!sealed.contains("agent-17"));
        assert_eq!(codec.open(&sealed).expect("authentic bridge"), principal);
        let mut forged = sealed;
        forged.push('x');
        assert_eq!(codec.open(&forged), Err(AuthenticationError::InvalidToken));
    }

    struct AcceptingVerifier;
    #[async_trait::async_trait]
    impl BearerVerifier for AcceptingVerifier {
        async fn verify(
            &self,
            _token: PresentedBearer<'_>,
        ) -> Result<Principal, AuthenticationError> {
            Principal::bearer_for_verifier(
                "https://issuer.example".to_owned(),
                "agent-17".to_owned(),
                PrincipalLimits::default(),
            )
            .map_err(|_| AuthenticationError::InvalidToken)
        }
    }

    struct CountingVerifier(Arc<std::sync::atomic::AtomicUsize>);
    #[async_trait::async_trait]
    impl BearerVerifier for CountingVerifier {
        async fn verify(
            &self,
            token: PresentedBearer<'_>,
        ) -> Result<Principal, AuthenticationError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            AcceptingVerifier.verify(token).await
        }
    }

    #[tokio::test]
    async fn mtls_identity_combines_with_bearer_and_unmapped_never_falls_back() {
        use axum::{Router, body::Body, http::Request, middleware, routing::post};
        use tower::ServiceExt;

        async fn status(
            state: AuthState,
            identity: crate::transport::TlsConnectionIdentity,
            bearer: bool,
        ) -> axum::http::StatusCode {
            let app = Router::new()
                .route(
                    "/protected",
                    post(|| async { axum::http::StatusCode::NO_CONTENT }),
                )
                .layer(middleware::from_fn_with_state(state, authenticate_request));
            let mut request = Request::post("/protected");
            if bearer {
                request = request.header("authorization", "Bearer signed");
            }
            app.oneshot(request.extension(identity).body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status()
        }

        let matching = Principal::mutual_tls(
            "https://issuer.example".to_owned(),
            "agent-17".to_owned(),
            PrincipalLimits::default(),
        )
        .unwrap();
        let mapped = crate::transport::TlsConnectionIdentity::from_verified(1, Some(matching));
        assert_eq!(
            status(AuthState::mutual_tls_only([1; 32]), mapped.clone(), false).await,
            axum::http::StatusCode::NO_CONTENT
        );
        assert_eq!(
            status(
                AuthState::new(Arc::new(AcceptingVerifier), [1; 32]),
                mapped,
                true
            )
            .await,
            axum::http::StatusCode::UNAUTHORIZED
        );

        let conflicting = Principal::mutual_tls(
            "https://issuer.example".to_owned(),
            "other-agent".to_owned(),
            PrincipalLimits::default(),
        )
        .unwrap();
        assert_eq!(
            status(
                AuthState::new(Arc::new(AcceptingVerifier), [1; 32]),
                crate::transport::TlsConnectionIdentity::from_verified(1, Some(conflicting)),
                true
            )
            .await,
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                AuthState::new(Arc::new(AcceptingVerifier), [1; 32]),
                crate::transport::TlsConnectionIdentity::from_verified(1, None),
                true
            )
            .await,
            axum::http::StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn mtls_policy_is_enforced_at_http_boundary_without_bearer_challenge() {
        use axum::{Router, body::Body, http::Request, middleware, routing::post};
        use tower::ServiceExt as _;

        let state = AuthState::mutual_tls_only([9; 32]);
        let app = Router::new()
            .route(
                "/protected",
                post(|| async { axum::http::StatusCode::NO_CONTENT }),
            )
            .layer(middleware::from_fn_with_state(state, authenticate_request));
        let missing = app
            .clone()
            .oneshot(Request::post("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            missing
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none()
        );

        let unmapped = app
            .oneshot(
                Request::post("/protected")
                    .extension(crate::transport::TlsConnectionIdentity::from_verified(
                        1, None,
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unmapped.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(
            unmapped
                .headers()
                .get(axum::http::header::WWW_AUTHENTICATE)
                .is_none()
        );
    }

    #[tokio::test]
    async fn middleware_replaces_credentials_with_server_principal_bridge() {
        use axum::{Router, body::Body, http::Request, middleware, routing::post};
        use tower::ServiceExt;

        let state = AuthState::new(Arc::new(AcceptingVerifier), [7; 32]);
        let app = Router::new()
            .route(
                "/protected",
                post(|headers: axum::http::HeaderMap| async move {
                    assert!(headers.get(axum::http::header::AUTHORIZATION).is_none());
                    assert!(
                        headers
                            .get(axum::http::header::PROXY_AUTHORIZATION)
                            .is_none()
                    );
                    assert!(headers.get(axum::http::header::COOKIE).is_none());
                    assert_eq!(headers.get_all(RESERVED_PRINCIPAL_HEADER).iter().count(), 1);
                    axum::http::StatusCode::NO_CONTENT
                }),
            )
            .layer(middleware::from_fn_with_state(state, authenticate_request));
        let response = app
            .oneshot(
                Request::post("/protected")
                    .header("authorization", "Bearer   signed-canary-token")
                    .header("proxy-authorization", "canary")
                    .header("cookie", "canary")
                    .header(RESERVED_PRINCIPAL_HEADER, "caller-forgery")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn middleware_rejects_duplicate_authorization_without_calling_verifier() {
        use axum::{Router, body::Body, http::Request, middleware, routing::post};
        use tower::ServiceExt;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = AuthState::new(Arc::new(CountingVerifier(Arc::clone(&calls))), [7; 32]);
        let app = Router::new()
            .route(
                "/protected",
                post(|| async { axum::http::StatusCode::NO_CONTENT }),
            )
            .layer(middleware::from_fn_with_state(state, authenticate_request));
        let mut request = Request::post("/protected")
            .body(Body::empty())
            .expect("request");
        request.headers_mut().append(
            "authorization",
            axum::http::HeaderValue::from_static("Bearer first"),
        );
        request.headers_mut().append(
            "authorization",
            axum::http::HeaderValue::from_static("Bearer second"),
        );
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    struct ScriptedProvider {
        responses:
            tokio::sync::Mutex<std::collections::VecDeque<Result<Vec<u8>, AuthenticationError>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl JwksProvider for ScriptedProvider {
        async fn fetch(&self, _max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body = self
                .responses
                .lock()
                .await
                .pop_front()
                .expect("scripted response")?;
            Ok(JwksFetch {
                body,
                fresh_for: std::time::Duration::from_secs(300),
            })
        }
    }

    fn jwks(kid: &str) -> Vec<u8> {
        format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","use":"sig","alg":"RS256","n":"{TEST_RSA_N}","e":"AQAB"}}]}}"#).into_bytes()
    }

    fn signed_token(kid: &str, exp: i64, nbf: i64, iat: i64) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        header.typ = Some("at+jwt".to_owned());
        jsonwebtoken::encode(
            &header,
            &TestClaims {
                iss: "https://issuer.example",
                sub: "agent-17",
                aud: "smesh-api",
                exp,
                nbf,
                iat,
                client_id: "client-17",
                jti: "token-17",
            },
            &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
                "../tests/fixtures/issue12-test-private.pem"
            ))
            .expect("test key"),
        )
        .expect("token")
    }

    struct ManualClock {
        unix: std::sync::atomic::AtomicI64,
        monotonic: std::sync::atomic::AtomicU64,
    }

    impl AuthClock for ManualClock {
        fn unix_seconds(&self) -> i64 {
            self.unix.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn monotonic_seconds(&self) -> u64 {
            self.monotonic.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn outage_uses_fresh_known_key_but_expired_cache_fails_closed() {
        let now = 1_800_000_000;
        let provider = Arc::new(ScriptedProvider {
            responses: tokio::sync::Mutex::new(std::collections::VecDeque::from([
                Ok(jwks("key-a")),
                Err(AuthenticationError::ProviderUnavailable),
            ])),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let clock = Arc::new(ManualClock {
            unix: std::sync::atomic::AtomicI64::new(now),
            monotonic: std::sync::atomic::AtomicU64::new(0),
        });
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            provider.clone(),
            clock.clone(),
        )
        .await
        .expect("initial JWKS");
        let token = signed_token("key-a", now + 600, now - 1, now - 1);
        assert!(
            verifier
                .verify(PresentedBearer::new(&token).unwrap())
                .await
                .is_ok()
        );
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        clock
            .monotonic
            .store(301, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            verifier.verify(PresentedBearer::new(&token).unwrap()).await,
            Err(AuthenticationError::ProviderUnavailable)
        );
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn zero_freshness_known_key_revalidates_each_valid_token() {
        struct ZeroFreshnessProvider {
            body: Vec<u8>,
            calls: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl JwksProvider for ZeroFreshnessProvider {
            async fn fetch(&self, _max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(JwksFetch {
                    body: self.body.clone(),
                    fresh_for: std::time::Duration::ZERO,
                })
            }
        }

        let now = 1_800_000_000;
        let provider = Arc::new(ZeroFreshnessProvider {
            body: jwks("key-a"),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            provider.clone(),
            Arc::new(FixedClock(now)),
        )
        .await
        .expect("initial zero-freshness JWKS");
        let token = signed_token("key-a", now + 60, now - 1, now - 1);

        for _ in 0..2 {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                verifier.verify(PresentedBearer::new(&token).expect("token")),
            )
            .await
            .expect("bounded revalidation")
            .expect("known key remains valid after revalidation");
        }
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "eager fetch plus one revalidation per token"
        );
    }

    #[tokio::test]
    async fn zero_freshness_concurrent_revalidation_remains_singleflight() {
        struct ZeroFreshnessProvider {
            body: Vec<u8>,
            calls: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl JwksProvider for ZeroFreshnessProvider {
            async fn fetch(&self, _max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(JwksFetch {
                    body: self.body.clone(),
                    fresh_for: std::time::Duration::ZERO,
                })
            }
        }

        let now = 1_800_000_000;
        let provider = Arc::new(ZeroFreshnessProvider {
            body: jwks("key-a"),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let verifier = Arc::new(
            JwtBearerVerifier::new(
                JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
                provider.clone(),
                Arc::new(FixedClock(now)),
            )
            .await
            .unwrap(),
        );
        let token = signed_token("key-a", now + 60, now - 1, now - 1);
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        *verifier.before_refresh_lock.lock().unwrap() = Some(Arc::clone(&barrier));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let verifier = Arc::clone(&verifier);
            let token = token.clone();
            tasks.push(tokio::spawn(async move {
                verifier.verify(PresentedBearer::new(&token).unwrap()).await
            }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), barrier.wait())
            .await
            .expect("all refresh contenders reached deterministic barrier");
        *verifier.before_refresh_lock.lock().unwrap() = None;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            for task in tasks {
                task.await.unwrap().unwrap();
            }
        })
        .await
        .expect("bounded concurrent revalidation");
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "eager fetch plus one shared concurrent refresh"
        );
    }

    #[tokio::test]
    async fn unknown_kid_single_refresh_admits_rotated_key() {
        let now = 1_800_000_000;
        let provider = Arc::new(ScriptedProvider {
            responses: tokio::sync::Mutex::new(std::collections::VecDeque::from([
                Ok(jwks("key-a")),
                Ok(jwks("key-b")),
            ])),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            provider.clone(),
            Arc::new(FixedClock(now)),
        )
        .await
        .expect("initial JWKS");
        let token = signed_token("key-b", now + 60, now - 1, now - 1);
        let principal = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            verifier.verify(PresentedBearer::new(&token).expect("token")),
        )
        .await
        .expect("watchdog")
        .expect("rotated key");
        assert_eq!(principal.subject(), "agent-17");
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn unknown_kid_provider_outage_is_singleflight_and_backed_off_for_the_storm() {
        struct OutageProvider {
            initial: Vec<u8>,
            calls: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl JwksProvider for OutageProvider {
            async fn fetch(&self, _max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
                let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if call == 0 {
                    Ok(JwksFetch {
                        body: self.initial.clone(),
                        fresh_for: std::time::Duration::from_secs(300),
                    })
                } else {
                    Err(AuthenticationError::ProviderUnavailable)
                }
            }
        }

        let now = 1_800_000_000;
        let provider = Arc::new(OutageProvider {
            initial: jwks("key-a"),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let verifier = Arc::new(
            JwtBearerVerifier::new(
                JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
                provider.clone(),
                Arc::new(FixedClock(now)),
            )
            .await
            .expect("initial JWKS"),
        );
        let token = signed_token("outage-key", now + 60, now - 1, now - 1);
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        *verifier.before_refresh_lock.lock().unwrap() = Some(Arc::clone(&barrier));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let verifier = Arc::clone(&verifier);
            let token = token.clone();
            tasks.push(tokio::spawn(async move {
                verifier.verify(PresentedBearer::new(&token).unwrap()).await
            }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), barrier.wait())
            .await
            .expect("all outage contenders reached deterministic barrier");
        *verifier.before_refresh_lock.lock().unwrap() = None;
        let results = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut results = Vec::new();
            for task in tasks {
                results.push(task.await.expect("outage verifier task"));
            }
            results
        })
        .await
        .expect("bounded outage storm");
        assert!(results.iter().all(Result::is_err));
        assert_eq!(
            provider.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "eager fetch plus exactly one failed refresh during the backoff interval"
        );
    }

    #[tokio::test]
    async fn clock_skew_boundaries_are_explicit() {
        let now = 1_800_000_000;
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            Arc::new(StaticProvider(jwks("key-a"))),
            Arc::new(FixedClock(now)),
        )
        .await
        .expect("JWKS");
        let accepted = signed_token("key-a", now + 60, now + 30, now + 30);
        assert!(
            verifier
                .verify(PresentedBearer::new(&accepted).unwrap())
                .await
                .is_ok()
        );
        let expired_boundary = signed_token("key-a", now - 30, now - 100, now - 100);
        assert_eq!(
            verifier
                .verify(PresentedBearer::new(&expired_boundary).unwrap())
                .await,
            Err(AuthenticationError::InvalidToken)
        );
        let future = signed_token("key-a", now + 60, now + 31, now + 31);
        assert_eq!(
            verifier
                .verify(PresentedBearer::new(&future).unwrap())
                .await,
            Err(AuthenticationError::InvalidToken)
        );
    }

    #[derive(serde::Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        exp: i64,
        nbf: i64,
        iat: i64,
        client_id: &'a str,
        jti: &'a str,
    }

    const TEST_RSA_N: &str = "p26N-Nwoj5-nUmncx2MHcT01-VCtp6LLQaOPv6tFIE4J3GS6Acccllk_QqMUamBnfwzgFErmBznMY8MfqZUM1-HNd_9GgvlJHIJUbYrU5Jbn1QnkY51GW5L4BXpyMeovuTPOjyKuAgRuAlaRI0W8JjZXGZt6stPFyofx-wZLT5eM0_ppclD-jJUQ_yt5tmkidf7SeXE7zDt8eg1aR2wolmhYfVzELkPRLYF4mLcMWXK7eV5Oc9L_u4NobVqAMlFX309TALcS_zrs7EbY9aB7m75RAhLjhPw8F-f_CLpvw5XMQ9OACg5NDqXEfTQUzHf9GWIHCC8JmJufvAn9jJI04Q";

    struct FixedClock(i64);
    impl AuthClock for FixedClock {
        fn unix_seconds(&self) -> i64 {
            self.0
        }
        fn monotonic_seconds(&self) -> u64 {
            0
        }
    }

    struct StaticProvider(Vec<u8>);
    #[async_trait::async_trait]
    impl JwksProvider for StaticProvider {
        async fn fetch(&self, _max_bytes: usize) -> Result<JwksFetch, AuthenticationError> {
            Ok(JwksFetch {
                body: self.0.clone(),
                fresh_for: std::time::Duration::from_secs(300),
            })
        }
    }

    #[tokio::test]
    async fn valid_rs256_token_derives_exact_principal() {
        let now = 1_800_000_000;
        let jwks = format!(r#"{{"keys":[{{"kty":"RSA","kid":"key-a","use":"sig","alg":"RS256","n":"{TEST_RSA_N}","e":"AQAB"}}]}}"#).into_bytes();
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            Arc::new(StaticProvider(jwks)),
            Arc::new(FixedClock(now)),
        )
        .await
        .expect("valid JWKS");
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("key-a".to_owned());
        header.typ = Some("at+jwt".to_owned());
        let token = jsonwebtoken::encode(
            &header,
            &TestClaims {
                iss: "https://issuer.example",
                sub: "agent-17",
                aud: "smesh-api",
                exp: now + 60,
                nbf: now - 1,
                iat: now - 1,
                client_id: "client-17",
                jti: "token-17",
            },
            &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
                "../tests/fixtures/issue12-test-private.pem"
            ))
            .expect("test key"),
        )
        .expect("signed token");

        let principal = verifier
            .verify(PresentedBearer::new(&token).expect("bounded token"))
            .await
            .expect("verified");
        assert_eq!(principal.issuer(), "https://issuer.example");
        assert_eq!(principal.subject(), "agent-17");
    }

    #[tokio::test]
    async fn application_access_token_typ_is_accepted_case_insensitively() {
        let now = 1_800_000_000;
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            Arc::new(StaticProvider(jwks("key-a"))),
            Arc::new(FixedClock(now)),
        )
        .await
        .expect("JWKS");
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("key-a".to_owned());
        header.typ = Some("Application/AT+JWT".to_owned());
        let token = jsonwebtoken::encode(
            &header,
            &TestClaims {
                iss: "https://issuer.example",
                sub: "agent-17",
                aud: "smesh-api",
                exp: now + 60,
                nbf: now - 1,
                iat: now - 1,
                client_id: "client-17",
                jti: "token-17",
            },
            &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
                "../tests/fixtures/issue12-test-private.pem"
            ))
            .expect("test key"),
        )
        .expect("token");
        assert!(
            verifier
                .verify(PresentedBearer::new(&token).unwrap())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn jwt_profile_rejects_any_crit_and_missing_client_id_or_jti() {
        let now = 1_800_000_000;
        let verifier = JwtBearerVerifier::new(
            JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
            Arc::new(StaticProvider(jwks("key-a"))),
            Arc::new(FixedClock(now)),
        )
        .await
        .expect("JWKS");
        let signing_key = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../tests/fixtures/issue12-test-private.pem"
        ))
        .expect("key");
        let claims = serde_json::json!({
            "iss":"https://issuer.example", "sub":"agent-17", "aud":"smesh-api",
            "exp":now + 60, "iat":now - 1, "client_id":"client-17", "jti":"token-17"
        });
        let mut critical = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        critical.kid = Some("key-a".to_owned());
        critical.typ = Some("at+jwt".to_owned());
        critical.crit = Some(Vec::new());
        let token = jsonwebtoken::encode(&critical, &claims, &signing_key).unwrap();
        assert_eq!(
            verifier.verify(PresentedBearer::new(&token).unwrap()).await,
            Err(AuthenticationError::InvalidToken)
        );

        let mut normal = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        normal.kid = Some("key-a".to_owned());
        normal.typ = Some("at+jwt".to_owned());
        for missing in ["client_id", "jti"] {
            let mut incomplete = claims.clone();
            incomplete.as_object_mut().unwrap().remove(missing);
            let token = jsonwebtoken::encode(&normal, &incomplete, &signing_key).unwrap();
            assert_eq!(
                verifier.verify(PresentedBearer::new(&token).unwrap()).await,
                Err(AuthenticationError::InvalidToken)
            );
        }
    }

    #[test]
    fn jwks_cache_directives_are_case_insensitive_and_honor_age_and_no_store() {
        let provider = HttpJwksProvider::new(
            "https://issuer.example/jwks",
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(3600),
        )
        .expect("provider");
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            "MAX-AGE=60".parse().unwrap(),
        );
        headers.insert(reqwest::header::AGE, "10".parse().unwrap());
        assert_eq!(provider.ttl(&headers), std::time::Duration::from_secs(50));
        headers.insert(reqwest::header::CACHE_CONTROL, "No-StOrE".parse().unwrap());
        assert_eq!(provider.ttl(&headers), std::time::Duration::ZERO);
    }

    #[tokio::test]
    async fn weak_rsa_modulus_and_inconsistent_key_ops_are_rejected() {
        use base64::Engine as _;
        let weak = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xff; 128]);
        for metadata in ["", r#",\"key_ops\":[\"verify\",\"encrypt\"]"#] {
            let body = format!(
                r#"{{"keys":[{{"kty":"RSA","kid":"weak","use":"sig","alg":"RS256","n":"{weak}","e":"AQAB"{metadata}}}]}}"#
            )
            .into_bytes();
            assert!(
                JwtBearerVerifier::new(
                    JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
                    Arc::new(StaticProvider(body)),
                    Arc::new(FixedClock(1_800_000_000)),
                )
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn rsa_modulus_larger_than_8192_bits_is_rejected_during_jwks_loading() {
        use base64::Engine as _;
        let oversized = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xff; 1_025]);
        let body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"oversized","use":"sig","alg":"RS256","n":"{oversized}","e":"AQAB"}}]}}"#
        )
        .into_bytes();

        assert_eq!(
            JwtBearerVerifier::new(
                JwtVerifierConfig::strict("https://issuer.example", "smesh-api"),
                Arc::new(StaticProvider(body)),
                Arc::new(FixedClock(1_800_000_000)),
            )
            .await
            .err(),
            Some(AuthenticationError::ProviderUnavailable)
        );
    }

    #[test]
    fn principal_is_bounded_and_debug_is_redacted() {
        let principal = Principal::bearer_for_verifier(
            "https://issuer.example".to_owned(),
            "secret-subject-canary".to_owned(),
            PrincipalLimits::default(),
        )
        .expect("bounded principal");

        assert_eq!(principal.issuer(), "https://issuer.example");
        assert_eq!(principal.subject(), "secret-subject-canary");
        assert_eq!(
            principal.authentication_method(),
            AuthenticationMethod::BearerJwt
        );
        let debug = format!("{principal:?}");
        assert!(!debug.contains("issuer.example"));
        assert!(!debug.contains("secret-subject-canary"));
        assert!(debug.contains("BearerJwt"));

        let too_long = "x".repeat(PrincipalLimits::default().max_subject_bytes + 1);
        assert!(
            Principal::bearer_for_verifier(
                "https://issuer.example".to_owned(),
                too_long,
                PrincipalLimits::default()
            )
            .is_err()
        );
    }
}
