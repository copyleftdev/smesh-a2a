use std::net::SocketAddr;
use std::sync::Arc;

use smesh_a2a::auth::{
    AuthState, HttpJwksProvider, JwtBearerVerifier, JwtVerifierConfig, SystemAuthClock,
};
use smesh_a2a::telemetry::{
    AuditProjectorConfig, OtlpConfig, OtlpMode, OtlpOwner, TelemetryHandle,
    instrument_router_with_telemetry,
};
use smesh_a2a::transport::{
    ClientAuthMode, ProductionTransportConfig, TlsIdentityAcceptor, TlsMaterialPaths,
    TlsSnapshotManager, TransportMode, canonical_public_origin, load_tls_snapshot,
};
use smesh_a2a::{
    ArtifactAuthority, ArtifactBackupPlanFile, ArtifactKeyRotationPlanFile,
    ArtifactMigrationPlanFile, ArtifactRestorePlanFile, ArtifactStoreConfig, AuthorizationPolicy,
    CallbackWorkerHandle, CorrelatingRuntimeProcessor, DurableLoopbackEndpoint, GatewayConfig,
    GatewayMode, InjectedClock, LegacyTenantBinding, LoopbackDispatcher, PostgresStoreConfig,
    PostgresTaskStore, ProductionCallbackQuotaAuthority, QuotaPolicy, RuntimeAdmissionProcessor,
    RuntimeEventCapture, RuntimeModeConfig, RuntimeWorker, SecureCallbackSender, SqliteTaskStore,
    SystemCallbackJitter, SystemClockTicker, build_authenticated_router,
    build_authenticated_router_with_trace,
    build_authorized_durable_loopback_gateway_with_telemetry,
    build_durable_loopback_gateway_with_telemetry, build_router, build_router_with_trace,
};
use smesh_core::{Network, Node};
use smesh_runtime::{MeshConfig, RuntimeConfig, SmeshRuntime};

async fn auth_state_from_environment() -> Result<Option<AuthState>, Box<dyn std::error::Error>> {
    let mode = std::env::var("SMESH_A2A_AUTH_MODE").unwrap_or_else(|_| "oidc".to_owned());
    if mode == "disabled" {
        return Ok(None);
    }
    if mode != "oidc" {
        return Err(
            "SMESH_A2A_AUTH_MODE must be oidc or explicitly disabled for loopback development"
                .into(),
        );
    }
    let issuer = std::env::var("SMESH_A2A_OIDC_ISSUER")
        .map_err(|_| "SMESH_A2A_OIDC_ISSUER is required when OIDC authentication is enabled")?;
    let audience = std::env::var("SMESH_A2A_OIDC_AUDIENCE")
        .map_err(|_| "SMESH_A2A_OIDC_AUDIENCE is required when OIDC authentication is enabled")?;
    let jwks_uri = std::env::var("SMESH_A2A_OIDC_JWKS_URI")
        .map_err(|_| "SMESH_A2A_OIDC_JWKS_URI is required when OIDC authentication is enabled")?;
    if issuer.is_empty()
        || issuer.len() > 2_048
        || audience.is_empty()
        || audience.len() > 512
        || jwks_uri.is_empty()
        || jwks_uri.len() > 4_096
    {
        return Err("OIDC issuer, audience, or JWKS URI violates configured bounds".into());
    }
    let issuer_url = url::Url::parse(&issuer)?;
    let parsed_jwks = url::Url::parse(&jwks_uri)?;
    for parsed in [&issuer_url, &parsed_jwks] {
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err("OIDC issuer and JWKS URI must be bounded HTTPS URLs without credentials or fragments".into());
        }
    }
    if issuer_url.query().is_some() {
        return Err("OIDC issuer URL must not contain a query".into());
    }
    let allow_cross_origin = match std::env::var("SMESH_A2A_OIDC_ALLOW_CROSS_ORIGIN_JWKS") {
        Ok(value) if value == "1" => true,
        Ok(value) if value == "0" => false,
        Ok(_) => return Err("SMESH_A2A_OIDC_ALLOW_CROSS_ORIGIN_JWKS must be 0 or 1".into()),
        Err(std::env::VarError::NotPresent) => false,
        Err(error) => return Err(error.into()),
    };
    if !allow_cross_origin
        && (
            issuer_url.scheme(),
            issuer_url.host_str(),
            issuer_url.port_or_known_default(),
        ) != (
            parsed_jwks.scheme(),
            parsed_jwks.host_str(),
            parsed_jwks.port_or_known_default(),
        )
    {
        return Err(
            "cross-origin OIDC JWKS URI requires SMESH_A2A_OIDC_ALLOW_CROSS_ORIGIN_JWKS=1".into(),
        );
    }
    let max_jwks_bytes = std::env::var("SMESH_A2A_OIDC_MAX_JWKS_BYTES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(256 * 1024);
    let clock_skew_seconds = std::env::var("SMESH_A2A_OIDC_CLOCK_SKEW_SECONDS")
        .ok()
        .map(|value| value.parse::<i64>())
        .transpose()?
        .unwrap_or(30);
    if !(1..=1024 * 1024).contains(&max_jwks_bytes) || !(0..=300).contains(&clock_skew_seconds) {
        return Err("OIDC JWKS limit must be 1..=1048576 and clock skew 0..=300 seconds".into());
    }
    let provider = Arc::new(HttpJwksProvider::new(
        &jwks_uri,
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_secs(300),
        std::time::Duration::from_secs(6 * 60 * 60),
    )?);
    let mut config = JwtVerifierConfig::strict(issuer, audience);
    config.max_jwks_bytes = max_jwks_bytes;
    config.clock_skew_seconds = clock_skew_seconds;
    let verifier =
        Arc::new(JwtBearerVerifier::new(config, provider, Arc::new(SystemAuthClock::new())).await?);
    Ok(Some(AuthState::new(verifier, rand::random())))
}

#[derive(Clone)]
enum HttpTransport {
    Plain,
    Direct {
        snapshots: Arc<TlsSnapshotManager>,
        handshake_timeout: std::time::Duration,
        max_connections: usize,
    },
}

fn transport_from_environment(
    bind: SocketAddr,
    public_url: &str,
    oidc_enabled: bool,
) -> Result<(ProductionTransportConfig, HttpTransport), Box<dyn std::error::Error>> {
    let mode: TransportMode = std::env::var("SMESH_A2A_TRANSPORT_MODE")
        .unwrap_or_else(|_| "loopback-plain".to_owned())
        .parse()?;
    let client_auth: ClientAuthMode = std::env::var("SMESH_A2A_CLIENT_AUTH_MODE")
        .unwrap_or_else(|_| "disabled".to_owned())
        .parse()?;
    let cert_path = std::env::var_os("SMESH_A2A_TLS_CERT_PATH").map(std::path::PathBuf::from);
    let key_path = std::env::var_os("SMESH_A2A_TLS_KEY_PATH").map(std::path::PathBuf::from);
    let client_ca_path =
        std::env::var_os("SMESH_A2A_TLS_CLIENT_CA_PATH").map(std::path::PathBuf::from);
    let principal_map_path =
        std::env::var_os("SMESH_A2A_TLS_PRINCIPAL_MAP_PATH").map(std::path::PathBuf::from);
    let handshake_timeout = std::time::Duration::from_secs(
        std::env::var("SMESH_A2A_TLS_HANDSHAKE_TIMEOUT_SECONDS")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(10),
    );
    let max_connections = std::env::var("SMESH_A2A_MAX_CONNECTIONS")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1024);
    let config = ProductionTransportConfig {
        mode,
        client_auth,
        bind,
        public_url: public_url.to_owned(),
        oidc_enabled,
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        client_ca_path: client_ca_path.clone(),
        principal_map_path: principal_map_path.clone(),
        handshake_timeout,
        max_connections,
    };
    config.validate_paths_and_policy()?;
    let runtime = if mode == TransportMode::DirectTls {
        let paths = TlsMaterialPaths {
            cert: cert_path.ok_or("TLS certificate path is required")?,
            key: key_path.ok_or("TLS private key path is required")?,
            client_ca: client_ca_path,
            principal_map: principal_map_path,
        };
        let snapshot = load_tls_snapshot(&paths, client_auth, 1)?;
        if !snapshot.covers_public_url(public_url) {
            return Err(
                "direct TLS public URL host is not covered by the serving certificate".into(),
            );
        }
        HttpTransport::Direct {
            snapshots: Arc::new(TlsSnapshotManager::new(
                snapshot,
                paths,
                client_auth,
                public_url.to_owned(),
            )),
            handshake_timeout,
            max_connections,
        }
    } else {
        HttpTransport::Plain
    };
    Ok((config, runtime))
}

#[derive(Clone, Copy)]
enum ServerControl {
    Shutdown,
    Reload,
}

#[cfg(unix)]
struct ServerControlSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ServerControlSignals {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            hangup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    async fn next(&mut self) -> Result<ServerControl, std::io::Error> {
        tokio::select! {
            signal = self.interrupt.recv() => signal.map(|()| ServerControl::Shutdown).ok_or_else(|| std::io::Error::other("SIGINT stream closed")),
            signal = self.terminate.recv() => signal.map(|()| ServerControl::Shutdown).ok_or_else(|| std::io::Error::other("SIGTERM stream closed")),
            signal = self.hangup.recv() => signal.map(|()| ServerControl::Reload).ok_or_else(|| std::io::Error::other("SIGHUP stream closed")),
        }
    }
}

#[cfg(not(unix))]
struct ServerControlSignals;

#[cfg(not(unix))]
impl ServerControlSignals {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self)
    }

    async fn next(&mut self) -> Result<ServerControl, std::io::Error> {
        tokio::signal::ctrl_c()
            .await
            .map(|()| ServerControl::Shutdown)
    }
}

struct AbortServerTask(tokio::task::JoinHandle<Result<(), std::io::Error>>);
impl Drop for AbortServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve_router(
    listener: std::net::TcpListener,
    app: axum::Router,
    transport: HttpTransport,
    telemetry: Option<TelemetryHandle>,
) -> Result<(), std::io::Error> {
    let app = instrument_router_with_telemetry(app, telemetry);
    let cancellation = tokio_util::sync::CancellationToken::new();
    let direct_handle = a2a_server::tls::axum_server::Handle::new();
    let snapshots = match &transport {
        HttpTransport::Direct { snapshots, .. } => Some(Arc::clone(snapshots)),
        HttpTransport::Plain => None,
    };
    let mut server = AbortServerTask(match transport {
        HttpTransport::Plain => {
            listener.set_nonblocking(true)?;
            let listener = tokio::net::TcpListener::from_std(listener)?;
            let stop = cancellation.clone();
            tokio::spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await
            })
        }
        HttpTransport::Direct {
            snapshots,
            handshake_timeout,
            max_connections,
        } => {
            listener.set_nonblocking(true)?;
            let acceptor = TlsIdentityAcceptor::new(snapshots, handshake_timeout, max_connections);
            let handle = direct_handle.clone();
            let server = a2a_server::tls::axum_server::from_tcp(listener)?
                .acceptor(acceptor)
                .handle(handle);
            tokio::spawn(async move { server.serve(app.into_make_service()).await })
        }
    });
    let mut signals = ServerControlSignals::new()?;
    tracing::info!("server control signals armed");
    loop {
        tokio::select! {
            result = &mut server.0 => return result.map_err(std::io::Error::other)?,
            control = signals.next() => match control? {
                ServerControl::Reload => {
                    if let Some(snapshots) = snapshots.as_ref() {
                        if let Ok(generation) = snapshots.reload() {
                            tracing::info!(generation, "TLS snapshot reloaded");
                        } else {
                            tracing::error!("TLS snapshot reload rejected; retaining prior generation");
                        }
                    }
                }
                ServerControl::Shutdown => {
                    cancellation.cancel();
                    direct_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
                    if let Ok(result) = tokio::time::timeout(
                        std::time::Duration::from_secs(6),
                        &mut server.0,
                    ).await {
                        return result.map_err(std::io::Error::other)?;
                    }
                    server.0.abort();
                    let _ = (&mut server.0).await;
                    return Err(std::io::Error::other("HTTP server shutdown deadline exceeded"));
                }
            }
        }
    }
}

fn required_operator_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("{name} is required").into())
}

async fn run_artifact_restore_command() -> Result<(), Box<dyn std::error::Error>> {
    let p = std::env::args_os()
        .nth(2)
        .ok_or("usage: smesh-a2a-gateway artifact-restore /absolute/private/plan.json")?;
    if std::env::args_os().nth(3).is_some() {
        return Err("artifact-restore accepts exactly one plan file".into());
    }
    let plan = ArtifactRestorePlanFile::open(p)?;
    let migrator = required_operator_env("SMESH_A2A_POSTGRES_MIGRATOR_URL")?;
    let runtime = required_operator_env("SMESH_A2A_POSTGRES_RUNTIME_URL")?;
    let schema = required_operator_env("SMESH_A2A_POSTGRES_SCHEMA")?;
    let keys = std::env::var_os("SMESH_A2A_ARTIFACT_KEYRING_PATH")
        .ok_or("SMESH_A2A_ARTIFACT_KEYRING_PATH is required")?;
    let config = PostgresStoreConfig::new(&migrator, &runtime, &schema)?
        .with_artifact_store(ArtifactStoreConfig::new(plan.target_root(), keys)?);
    #[cfg(debug_assertions)]
    let config = if std::env::var("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK").as_deref() == Ok("1") {
        config.with_test_only_insecure_loopback(true)
    } else {
        config
    };
    let out = PostgresTaskStore::restore_artifacts(config, &plan).await?;
    println!(
        "artifact restore objects={} enabled={}",
        out.objects, out.enabled
    );
    Ok(())
}

async fn run_artifact_key_rotate_command() -> Result<(), Box<dyn std::error::Error>> {
    let plan_path = std::env::args_os()
        .nth(2)
        .ok_or("usage: smesh-a2a-gateway artifact-key-rotate /absolute/private/plan.json")?;
    if std::env::args_os().nth(3).is_some() {
        return Err("artifact-key-rotate accepts exactly one plan file".into());
    }
    let plan = ArtifactKeyRotationPlanFile::open(plan_path)?;
    let migrator = required_operator_env("SMESH_A2A_POSTGRES_MIGRATOR_URL")?;
    let runtime = required_operator_env("SMESH_A2A_POSTGRES_RUNTIME_URL")?;
    let schema = required_operator_env("SMESH_A2A_POSTGRES_SCHEMA")?;
    let root =
        std::env::var_os("SMESH_A2A_ARTIFACT_ROOT").ok_or("SMESH_A2A_ARTIFACT_ROOT is required")?;
    let keys = std::env::var_os("SMESH_A2A_ARTIFACT_KEYRING_PATH")
        .ok_or("SMESH_A2A_ARTIFACT_KEYRING_PATH is required")?;
    let owner = std::env::var("SMESH_A2A_ARTIFACT_ROTATION_OWNER")
        .map_err(|_| "SMESH_A2A_ARTIFACT_ROTATION_OWNER is required")?;
    let config = PostgresStoreConfig::new(&migrator, &runtime, &schema)?
        .with_artifact_store(ArtifactStoreConfig::new(root, keys)?);
    #[cfg(debug_assertions)]
    let config = if std::env::var("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK").as_deref() == Ok("1") {
        config.with_test_only_insecure_loopback(true)
    } else {
        config
    };
    let out = PostgresTaskStore::rotate_artifact_key(config, &plan, &owner).await?;
    println!(
        "artifact key rotation reencrypted={} cleaned={} completed={}",
        out.reencrypted, out.cleaned, out.completed
    );
    Ok(())
}

async fn run_artifact_backup_command() -> Result<(), Box<dyn std::error::Error>> {
    let plan_path = std::env::args_os()
        .nth(2)
        .ok_or("usage: smesh-a2a-gateway artifact-backup /absolute/private/plan.json")?;
    if std::env::args_os().nth(3).is_some() {
        return Err("artifact-backup accepts exactly one plan file".into());
    }
    let plan = ArtifactBackupPlanFile::open(&plan_path)?;
    let migrator = required_operator_env("SMESH_A2A_POSTGRES_MIGRATOR_URL")?;
    let runtime = required_operator_env("SMESH_A2A_POSTGRES_RUNTIME_URL")?;
    let schema = required_operator_env("SMESH_A2A_POSTGRES_SCHEMA")?;
    let root =
        std::env::var_os("SMESH_A2A_ARTIFACT_ROOT").ok_or("SMESH_A2A_ARTIFACT_ROOT is required")?;
    let keyring = std::env::var_os("SMESH_A2A_ARTIFACT_KEYRING_PATH")
        .ok_or("SMESH_A2A_ARTIFACT_KEYRING_PATH is required")?;
    let owner = std::env::var("SMESH_A2A_ARTIFACT_BACKUP_OWNER")
        .map_err(|_| "SMESH_A2A_ARTIFACT_BACKUP_OWNER is required")?;
    let config = PostgresStoreConfig::new(&migrator, &runtime, &schema)?
        .with_artifact_store(ArtifactStoreConfig::new(root, keyring)?);
    #[cfg(debug_assertions)]
    let config = if std::env::var("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK").as_deref() == Ok("1") {
        config.with_test_only_insecure_loopback(true)
    } else {
        config
    };
    let result = PostgresTaskStore::backup_artifacts(config, &plan, &owner).await?;
    println!(
        "artifact backup objects={} inventory_digest={} signed={}",
        result.objects,
        result.inventory_digest,
        result.signature.is_some()
    );
    Ok(())
}

async fn run_artifact_migrate_command() -> Result<(), Box<dyn std::error::Error>> {
    let plan_path = std::env::args_os()
        .nth(2)
        .ok_or("usage: smesh-a2a-gateway artifact-migrate /absolute/private/plan.json")?;
    if std::env::args_os().nth(3).is_some() {
        return Err("artifact-migrate accepts exactly one plan file".into());
    }
    let plan = ArtifactMigrationPlanFile::open(&plan_path)?;
    let migrator = required_operator_env("SMESH_A2A_POSTGRES_MIGRATOR_URL")?;
    let runtime = required_operator_env("SMESH_A2A_POSTGRES_RUNTIME_URL")?;
    let schema = required_operator_env("SMESH_A2A_POSTGRES_SCHEMA")?;
    let root =
        std::env::var_os("SMESH_A2A_ARTIFACT_ROOT").ok_or("SMESH_A2A_ARTIFACT_ROOT is required")?;
    let keyring = std::env::var_os("SMESH_A2A_ARTIFACT_KEYRING_PATH")
        .ok_or("SMESH_A2A_ARTIFACT_KEYRING_PATH is required")?;
    let owner = std::env::var("SMESH_A2A_ARTIFACT_MIGRATION_OWNER")
        .map_err(|_| "SMESH_A2A_ARTIFACT_MIGRATION_OWNER is required")?;
    let config = PostgresStoreConfig::new(&migrator, &runtime, &schema)?
        .with_artifact_store(ArtifactStoreConfig::new(root, keyring)?);
    #[cfg(debug_assertions)]
    let config = if std::env::var("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK").as_deref() == Ok("1") {
        config.with_test_only_insecure_loopback(true)
    } else {
        config
    };
    let result = PostgresTaskStore::migrate_inline_artifacts(config, &plan, &owner).await?;
    println!(
        "artifact migration completed={} migrated_artifacts={} rewritten_rows={} completion_seal={}",
        result.completed,
        result.migrated_artifacts,
        result.rewritten_rows,
        result.completion_seal.as_deref().unwrap_or("none")
    );
    Ok(())
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("artifact-restore")) {
        return run_artifact_restore_command().await;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("artifact-key-rotate")) {
        return run_artifact_key_rotate_command().await;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("artifact-backup")) {
        return run_artifact_backup_command().await;
    }
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("artifact-migrate")) {
        return run_artifact_migrate_command().await;
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind: SocketAddr = std::env::var("SMESH_A2A_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()?;
    let public_base_url =
        std::env::var("SMESH_A2A_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind}"));
    let oidc_enabled = std::env::var("SMESH_A2A_AUTH_MODE").as_deref() != Ok("disabled");
    if oidc_enabled && std::env::var_os("SMESH_A2A_OIDC_ISSUER").is_none() {
        return Err("SMESH_A2A_OIDC_ISSUER is required when OIDC authentication is enabled".into());
    }
    let client_auth_mode = match std::env::var("SMESH_A2A_CLIENT_AUTH_MODE").as_deref() {
        Ok("optional") => ClientAuthMode::Optional,
        Ok("required") => ClientAuthMode::Required,
        Ok("disabled") | Err(std::env::VarError::NotPresent) => ClientAuthMode::Disabled,
        _ => {
            return Err(
                "SMESH_A2A_CLIENT_AUTH_MODE must be disabled, optional, or required".into(),
            );
        }
    };
    let authentication_enabled = oidc_enabled || client_auth_mode != ClientAuthMode::Disabled;
    let policy_configured = std::env::var_os("SMESH_A2A_AUTHORIZATION_POLICY_PATH").is_some();
    if authentication_enabled != policy_configured {
        return Err(if authentication_enabled {
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH is required when authentication is enabled"
        } else {
            "an authorization policy requires OIDC or mTLS authentication"
        }
        .into());
    }
    let tenant_authorization_enabled = authentication_enabled;
    let authorization = if tenant_authorization_enabled {
        let path = std::env::var_os("SMESH_A2A_AUTHORIZATION_POLICY_PATH").ok_or(
            "SMESH_A2A_AUTHORIZATION_POLICY_PATH is required when authentication is enabled",
        )?;
        Some(Arc::new(AuthorizationPolicy::load(
            std::path::PathBuf::from(path),
        )?))
    } else {
        None
    };
    let legacy_binding = match (
        std::env::var("SMESH_A2A_LEGACY_TENANT_ID").ok(),
        std::env::var("SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID").ok(),
    ) {
        (None, None) => None,
        (Some(tenant), Some(account)) if tenant_authorization_enabled => Some(
            authorization
                .as_ref()
                .ok_or("authorization policy missing for legacy binding")?
                .legacy_tenant_binding(&tenant, &account)?,
        ),
        (Some(_), Some(_)) => {
            return Err("legacy tenant binding is only valid in authenticated durable mode".into());
        }
        _ => return Err(
            "SMESH_A2A_LEGACY_TENANT_ID and SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID must be set together"
                .into(),
        ),
    };
    let (transport_config, http_transport) =
        transport_from_environment(bind, &public_base_url, oidc_enabled)?;
    let otlp_config = OtlpConfig::parse(std::env::vars().filter(|(key, _)| {
        key.starts_with("SMESH_A2A_OTLP_") || key == "SMESH_TEST_OTLP_INSECURE_LOOPBACK"
    }))?;
    let audit_projection_enabled = otlp_config.mode != OtlpMode::Disabled;
    let legacy_unsafe_public = std::env::var("SMESH_A2A_UNSAFE_PUBLIC").as_deref() == Ok("1");
    if legacy_unsafe_public {
        tracing::warn!(
            "SMESH_A2A_UNSAFE_PUBLIC is ignored; transport/auth policy remains fail-closed"
        );
    }
    let gateway_node_id =
        std::env::var("SMESH_A2A_NODE_ID").unwrap_or_else(|_| "smesh-a2a-gateway".to_owned());
    let mode = std::env::var("SMESH_A2A_MODE").ok();
    let mesh_bind = std::env::var("SMESH_A2A_MESH_BIND").ok();
    let bootstrap = std::env::var("SMESH_A2A_BOOTSTRAP").ok();
    let mode = GatewayMode::parse(mode.as_deref(), mesh_bind.as_deref(), bootstrap.as_deref())?;
    let sqlite_path = std::env::var_os("SMESH_A2A_SQLITE_PATH").map(std::path::PathBuf::from);
    let pg_migrator = std::env::var("SMESH_A2A_POSTGRES_MIGRATOR_URL").ok();
    let pg_runtime = std::env::var("SMESH_A2A_POSTGRES_RUNTIME_URL").ok();
    let pg_schema = std::env::var("SMESH_A2A_POSTGRES_SCHEMA").ok();
    let quota_policy = std::env::var_os("SMESH_A2A_QUOTA_POLICY_PATH")
        .map(|path| QuotaPolicy::load(std::path::PathBuf::from(path)).map(Arc::new))
        .transpose()?;
    let push_config = std::env::var_os("SMESH_A2A_PUSH_CONFIG_PATH");
    let push_policy_alias = std::env::var_os("SMESH_A2A_PUSH_POLICY_PATH");
    if push_config.is_some() && push_policy_alias.is_some() {
        return Err(
            "SMESH_A2A_PUSH_CONFIG_PATH conflicts with deprecated SMESH_A2A_PUSH_POLICY_PATH"
                .into(),
        );
    }
    let push_config_path =
        smesh_a2a::push::resolve_push_config_path(push_config, push_policy_alias)?;
    if push_config_path.is_some() && std::env::var_os("SMESH_A2A_PUSH_POLICY_PATH").is_some() {
        tracing::warn!("SMESH_A2A_PUSH_POLICY_PATH is deprecated; use SMESH_A2A_PUSH_CONFIG_PATH");
    }
    let push_policy = push_config_path
        .map(|path| {
            smesh_a2a::push::PushPolicy::load(&std::path::PathBuf::from(path)).map(Arc::new)
        })
        .transpose()?;
    let push_enabled = push_policy.as_ref().is_some_and(|policy| policy.enabled());
    let artifact_root = std::env::var_os("SMESH_A2A_ARTIFACT_ROOT");
    let artifact_keyring = std::env::var_os("SMESH_A2A_ARTIFACT_KEYRING_PATH");
    let artifact_store = match (artifact_root, artifact_keyring) {
        (None, None) => None,
        (Some(root), Some(keyring)) => Some(ArtifactStoreConfig::new(root, keyring)?),
        _ => {
            return Err(
                "SMESH_A2A_ARTIFACT_ROOT and SMESH_A2A_ARTIFACT_KEYRING_PATH must be set together"
                    .into(),
            );
        }
    };
    let backend = std::env::var("SMESH_A2A_DURABLE_BACKEND").ok();
    if quota_policy.is_some() && backend.as_deref() != Some("postgres") {
        return Err(
            "distributed quota enforcement requires the PostgreSQL durable authority".into(),
        );
    }
    if artifact_store.is_some() && backend.as_deref() != Some("postgres") {
        return Err("artifact storage requires the PostgreSQL durable authority".into());
    }
    if push_enabled
        && (backend.as_deref() != Some("postgres")
            || !authentication_enabled
            || authorization.is_none()
            || quota_policy.is_none())
    {
        return Err("enabled push policy requires PostgreSQL, authentication, authorization, and distributed quota enforcement".into());
    }
    if let Ok(replica_id) = std::env::var("SMESH_A2A_REPLICA_ID")
        && (replica_id.is_empty()
            || replica_id.len() > 128
            || !replica_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)))
    {
        return Err(
            "SMESH_A2A_REPLICA_ID must be 1..=128 ASCII letters, digits, '.', '_', ':', or '-'"
                .into(),
        );
    }
    let postgres_config = match backend.as_deref() {
        None if sqlite_path.is_none() && pg_migrator.is_none() && pg_runtime.is_none() && pg_schema.is_none() => None,
        None => return Err("SMESH_A2A_DURABLE_BACKEND=sqlite|postgres is required when durable authority configuration is present".into()),
        Some("sqlite") if sqlite_path.is_some() && pg_migrator.is_none() && pg_runtime.is_none() && pg_schema.is_none() => None,
        Some("postgres") if sqlite_path.is_none() => {
            if !authentication_enabled || !matches!(mode, GatewayMode::Loopback) {
                return Err("PostgreSQL durable authority requires authenticated authorized loopback mode".into());
            }
            let mut config = PostgresStoreConfig::new(
                pg_migrator.ok_or("SMESH_A2A_POSTGRES_MIGRATOR_URL is required")?,
                pg_runtime.ok_or("SMESH_A2A_POSTGRES_RUNTIME_URL is required")?,
                pg_schema.ok_or("SMESH_A2A_POSTGRES_SCHEMA is required")?,
            )?
            .with_audit_projection(audit_projection_enabled)
            .with_quota_policy(quota_policy.clone().ok_or(
                "SMESH_A2A_QUOTA_POLICY_PATH is required for PostgreSQL production authority",
            )?);
            if let Some(policy) = push_policy.as_ref().filter(|policy| policy.enabled()) {
                config = config.with_push_policy((**policy).clone());
            }
            if let Some(artifact_store) = artifact_store.clone() {
                config = config.with_artifact_store(artifact_store);
                if let Some(path) = std::env::var_os("SMESH_A2A_ARTIFACT_MIGRATION_PLAN_PATH") {
                    config = config.with_artifact_migration_plan_file(
                        ArtifactMigrationPlanFile::open(std::path::PathBuf::from(path))?,
                    );
                }
            }
            #[cfg(debug_assertions)]
            let config = {
                let mut config = config;
                if std::env::var("SMESH_TEST_POSTGRES_INSECURE_LOOPBACK").as_deref() == Ok("1") {
                    config = config.with_test_only_insecure_loopback(true);
                    if std::env::var("SMESH_TEST_POSTGRES_PARENT_MANAGED_CLEANUP").as_deref()
                        == Ok("1")
                    {
                        config = config.with_test_only_parent_managed_cleanup();
                    }
                }
                config
            };
            config.validate_tls_policy()?;
            Some(config)
        }
        Some("sqlite") if sqlite_path.is_none() => {
            return Err("SMESH_A2A_SQLITE_PATH is required when SMESH_A2A_DURABLE_BACKEND=sqlite".into());
        }
        Some("sqlite") => return Err("SQLite backend requires only SMESH_A2A_SQLITE_PATH; PostgreSQL configuration must be absent".into()),
        Some("postgres") => return Err("PostgreSQL backend cannot be combined with SMESH_A2A_SQLITE_PATH".into()),
        Some(_) => return Err("SMESH_A2A_DURABLE_BACKEND must be sqlite or postgres".into()),
    };
    let durable_configured = sqlite_path.is_some() || postgres_config.is_some();
    if matches!(mode, GatewayMode::Runtime(_)) && durable_configured {
        return Err("durable authority routing is supported only in loopback mode".into());
    }
    if tenant_authorization_enabled
        && (!matches!(mode, GatewayMode::Loopback) || !durable_configured)
    {
        return Err("authenticated task operations require an authorized durable loopback gateway; generic authenticated handlers are development-only and not tenant-safe".into());
    }

    let mut auth = auth_state_from_environment().await?;
    if transport_config.client_auth != ClientAuthMode::Disabled {
        auth = Some(match auth {
            Some(state) if transport_config.client_auth == ClientAuthMode::Required => {
                state.with_required_mutual_tls()
            }
            Some(state) => state.with_mutual_tls(),
            None => AuthState::mutual_tls_only(rand::random()),
        });
    }
    // Reserve the public endpoint before SQLite, runtime, mesh, ticker, or
    // worker resources can be acquired or mutate durable state.
    let listener = std::net::TcpListener::bind(bind)?;
    let telemetry_shutdown_timeout = otlp_config.shutdown_timeout;
    let telemetry = OtlpOwner::start(otlp_config)?;
    let telemetry_handle = telemetry.as_ref().map(OtlpOwner::handle);
    if let Some(handle) = telemetry_handle.as_ref() {
        auth = auth.map(|state| state.with_telemetry(handle.clone()));
    }

    match mode {
        GatewayMode::Loopback => {
            let config = GatewayConfig::new(&public_base_url, &gateway_node_id);
            if let Some(path) = sqlite_path {
                run_durable_loopback_gateway(
                    listener,
                    bind,
                    public_base_url,
                    config,
                    path,
                    auth,
                    authorization.clone(),
                    legacy_binding,
                    http_transport.clone(),
                    telemetry_handle.clone(),
                )
                .await?;
            } else if let Some(postgres_config) = postgres_config {
                if legacy_binding.is_some() {
                    return Err(
                        "legacy tenant binding is not supported by the PostgreSQL backend".into(),
                    );
                }
                run_postgres_durable_loopback_gateway(
                    listener,
                    bind,
                    public_base_url,
                    config,
                    postgres_config,
                    auth,
                    authorization.clone(),
                    http_transport.clone(),
                    telemetry_handle.clone(),
                    push_policy.clone(),
                    quota_policy.clone(),
                )
                .await?;
            } else {
                let app = if let Some(auth) = auth {
                    build_authenticated_router(config, LoopbackDispatcher, auth)
                } else {
                    build_router(config, LoopbackDispatcher)
                };
                let public_origin = canonical_public_origin(&public_base_url)?;
                tracing::info!(%bind, %public_origin, mode = "loopback", transport = %transport_config.mode, "SMESH A2A gateway listening");
                serve_router(
                    listener,
                    app,
                    http_transport.clone(),
                    telemetry_handle.clone(),
                )
                .await?;
            }
        }
        GatewayMode::Runtime(runtime_config) => {
            run_runtime_gateway(
                listener,
                bind,
                public_base_url,
                gateway_node_id,
                runtime_config,
                auth,
                http_transport,
                telemetry_handle.clone(),
            )
            .await?;
        }
    }
    drop(telemetry_handle);
    if let Some(owner) = telemetry
        && !owner.shutdown(telemetry_shutdown_timeout)
    {
        eprintln!("smesh.telemetry.shutdown_failed category=otlp_owner");
    }
    Ok(())
}

fn audit_projector_config() -> Result<AuditProjectorConfig, Box<dyn std::error::Error>> {
    let poll = std::env::var("SMESH_A2A_AUDIT_PROJECTOR_POLL_MS")
        .ok()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(100_u64);
    let batch = std::env::var("SMESH_A2A_AUDIT_PROJECTOR_BATCH")
        .ok()
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(100_usize);
    let poll_interval = std::time::Duration::from_millis(poll);
    if let Ok(replica_id) = std::env::var("SMESH_A2A_REPLICA_ID") {
        Ok(AuditProjectorConfig::for_replica_id(
            &replica_id,
            poll_interval,
            batch,
        )?)
    } else {
        Ok(AuditProjectorConfig::new(
            "smesh-audit-projector",
            poll_interval,
            batch,
        )?)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_durable_loopback_gateway(
    listener: std::net::TcpListener,
    bind: SocketAddr,
    public_base_url: String,
    config: GatewayConfig,
    sqlite_path: std::path::PathBuf,
    auth: Option<AuthState>,
    authorization: Option<Arc<AuthorizationPolicy>>,
    legacy_binding: Option<LegacyTenantBinding>,
    transport: HttpTransport,
    telemetry: Option<TelemetryHandle>,
) -> Result<(), Box<dyn std::error::Error>> {
    if auth.is_some() != authorization.is_some() {
        return Err("durable production authentication and tenant authorization must be configured together".into());
    }
    let store = if let Some(binding) = legacy_binding {
        if telemetry.is_some() {
            SqliteTaskStore::open_with_legacy_binding_and_audit_projection(
                sqlite_path,
                config.max_tasks,
                binding,
            )
            .await?
        } else {
            SqliteTaskStore::open_with_legacy_binding(sqlite_path, config.max_tasks, binding)
                .await?
        }
    } else if telemetry.is_some() {
        SqliteTaskStore::open_with_audit_projection(sqlite_path, config.max_tasks).await?
    } else {
        SqliteTaskStore::open(sqlite_path, config.max_tasks).await?
    };
    let clock = InjectedClock::new(chrono::Utc::now().timestamp_millis());
    let mut gateway = if let Some(auth) = auth {
        if let Some(policy) = authorization {
            build_authorized_durable_loopback_gateway_with_telemetry(
                config,
                store,
                DurableLoopbackEndpoint::new(),
                clock.clone(),
                auth,
                policy,
                telemetry.clone(),
            )?
        } else {
            unreachable!("authentication without tenant authorization was rejected before SQLite")
        }
    } else {
        build_durable_loopback_gateway_with_telemetry(
            config,
            store,
            DurableLoopbackEndpoint::new(),
            clock.clone(),
            telemetry.clone(),
        )?
    };
    if let Some(handle) = telemetry.clone()
        && !gateway.start_audit_projector(handle, audit_projector_config()?)?
    {
        return Err("telemetry requested but audit projection worker is unavailable".into());
    }
    let ticker = SystemClockTicker::spawn(clock);
    let app = gateway.router();
    let public_origin = canonical_public_origin(&public_base_url)?;
    tracing::info!(%bind, %public_origin, mode = "loopback", durable = true, "SMESH A2A gateway listening");
    let serve_result = serve_router(listener, app, transport, telemetry).await;

    let ticker_result = ticker.shutdown().await;
    let gateway_result = gateway.shutdown().await;
    serve_result?;
    ticker_result?;
    gateway_result?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_postgres_durable_loopback_gateway(
    listener: std::net::TcpListener,
    bind: SocketAddr,
    public_base_url: String,
    config: GatewayConfig,
    postgres_config: PostgresStoreConfig,
    auth: Option<AuthState>,
    authorization: Option<Arc<AuthorizationPolicy>>,
    transport: HttpTransport,
    telemetry: Option<TelemetryHandle>,
    push_policy: Option<Arc<smesh_a2a::push::PushPolicy>>,
    quota_policy: Option<Arc<QuotaPolicy>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth = auth.ok_or("PostgreSQL durable authority requires authentication")?;
    let policy =
        authorization.ok_or("PostgreSQL durable authority requires authorization policy")?;
    let store = PostgresTaskStore::open(postgres_config)
        .await?
        .with_telemetry(telemetry.clone());
    tracing::info!(
        artifact_storage = store.artifact_capabilities().publication,
        "PostgreSQL durable authority opened"
    );
    let clock = InjectedClock::new(chrono::Utc::now().timestamp_millis());
    let mut gateway = build_authorized_durable_loopback_gateway_with_telemetry(
        config,
        store.clone(),
        DurableLoopbackEndpoint::new(),
        clock.clone(),
        auth,
        policy,
        telemetry.clone(),
    )?;
    if let Some(push) = push_policy.filter(|policy| policy.enabled()) {
        let quota_policy = quota_policy.ok_or("enabled push policy requires quota policy")?;
        let callback_authority: Arc<dyn smesh_a2a::CallbackAuthority> = Arc::new(store.clone());
        let durable_authority: Arc<dyn smesh_a2a::DurableAuthority> = Arc::new(store.clone());
        let sender = Arc::new(SecureCallbackSender::new(
            smesh_a2a::push::SecureCallbackTransport::from_policy_system(&push)?,
            usize::try_from(push.max_response_bytes())?,
        ));
        let quota = Arc::new(ProductionCallbackQuotaAuthority::new(
            durable_authority,
            quota_policy,
        ));
        let owner =
            std::env::var("SMESH_A2A_REPLICA_ID").unwrap_or_else(|_| "smesh-callback".to_owned());
        let worker = CallbackWorkerHandle::spawn_with_telemetry(
            callback_authority,
            push,
            sender,
            quota,
            Arc::new(SystemCallbackJitter),
            &owner,
            gateway.push_readiness(),
            telemetry.clone(),
        )?;
        worker
            .wait_initial_cycle(std::time::Duration::from_secs(5))
            .await?;
        gateway.own_callback_worker(worker)?;
    }
    if let Some(handle) = telemetry.clone()
        && !gateway.start_audit_projector(handle, audit_projector_config()?)?
    {
        return Err("telemetry requested but audit projection worker is unavailable".into());
    }
    let ticker = SystemClockTicker::spawn(clock);
    let app = gateway.router();
    let public_origin = canonical_public_origin(&public_base_url)?;
    tracing::info!(%bind, %public_origin, mode = "loopback", durable = true, backend = "postgres", "SMESH A2A gateway listening");
    let serve_result = serve_router(listener, app, transport, telemetry).await;
    let ticker_result = ticker.shutdown().await;
    let gateway_result = gateway.shutdown().await;
    serve_result?;
    ticker_result?;
    gateway_result?;
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // Keep runtime startup, trace supervision, and shutdown ownership linear.
async fn run_runtime_gateway(
    listener: std::net::TcpListener,
    bind: SocketAddr,
    public_base_url: String,
    gateway_node_id: String,
    runtime_config: RuntimeModeConfig,
    auth: Option<AuthState>,
    transport: HttpTransport,
    telemetry: Option<TelemetryHandle>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = GatewayConfig::new(&public_base_url, &gateway_node_id);
    let mut network = Network::new();
    network.add_node(Node::named(&gateway_node_id));
    let mut runtime_value = SmeshRuntime::with_network(network, RuntimeConfig::default());
    let mut runtime_events = runtime_value
        .take_events()
        .ok_or("SMESH runtime event receiver was already taken")?;
    let runtime = Arc::new(runtime_value);
    let capture =
        Arc::new(RuntimeEventCapture::new(65_536, 1_024).with_telemetry(telemetry.clone()));
    let mut runtime_loop = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.run().await })
    };
    let event_capture = Arc::clone(&capture);
    let trace_failure = capture.failure_token();
    let trace_drain_stop = tokio_util::sync::CancellationToken::new();
    let trace_drain_stop_signal = trace_drain_stop.clone();
    let mut event_drain = tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                biased;
                event = runtime_events.recv() => event,
                () = trace_drain_stop_signal.cancelled() => {
                    while let Ok(event) = runtime_events.try_recv() {
                        if let Err(_error) = event_capture.record(event).await {
                            tracing::error!(error_category = "runtime_trace_capture", "required SMESH runtime trace capture failed");
                            return;
                        }
                    }
                    return;
                }
            };
            let Some(event) = event else {
                return;
            };
            if let Err(_error) = event_capture.record(event).await {
                tracing::error!(
                    error_category = "runtime_trace_capture",
                    "required SMESH runtime trace capture failed"
                );
                return;
            }
        }
    });
    let mesh = runtime
        .join_mesh(
            MeshConfig {
                bind_addr: runtime_config.mesh_bind,
                bootstrap: runtime_config.bootstrap,
                node_metadata: serde_json::json!({
                    "component": "smesh-a2a",
                    "role": "gateway-runtime-worker",
                }),
                peer_discovery: false,
                ..MeshConfig::default()
            },
            &gateway_node_id,
        )
        .await?;
    let mesh_listen = mesh.listen_addr();
    let (dispatcher, worker) = RuntimeWorker::spawn(
        Arc::clone(&runtime),
        &gateway_node_id,
        CorrelatingRuntimeProcessor::new(RuntimeAdmissionProcessor, Arc::clone(&capture)),
        64,
    )
    .await?;
    let app = if let Some(auth) = auth {
        build_authenticated_router_with_trace(config, dispatcher, auth, Arc::clone(&capture))
    } else {
        build_router_with_trace(config, dispatcher, Arc::clone(&capture))
    };
    let public_origin = canonical_public_origin(&public_base_url)?;
    tracing::info!(
        %bind,
        %public_origin,
        %mesh_listen,
        mode = "runtime",
        "SMESH A2A gateway listening"
    );
    let mut event_drain_finished = false;
    let mut http_server = std::pin::pin!(serve_router(listener, app, transport, telemetry));
    let serve_result = tokio::select! {
        result = &mut http_server => result,
        () = trace_failure.cancelled() => Err(std::io::Error::other(
            "required SMESH runtime trace capture failed",
        )),
        result = &mut event_drain => {
            event_drain_finished = true;
            capture.invalidate();
            match result {
                Ok(()) => Err(std::io::Error::other(
                    "SMESH runtime trace event channel closed unexpectedly",
                )),
                Err(error) => Err(std::io::Error::other(error)),
            }
        },
    };
    let worker_result = worker.shutdown().await;
    runtime.shutdown().await;
    mesh.shutdown().await;
    if tokio::time::timeout(std::time::Duration::from_secs(5), &mut runtime_loop)
        .await
        .is_err()
    {
        runtime_loop.abort();
        let _ = runtime_loop.await;
    }
    if !event_drain_finished {
        trace_drain_stop.cancel();
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut event_drain).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                tracing::error!("SMESH runtime trace drain task failed");
                capture.invalidate();
            }
            Err(_) => {
                tracing::error!("SMESH runtime trace drain did not stop within its deadline");
                capture.invalidate();
                event_drain.abort();
                let _ = event_drain.await;
            }
        }
    }
    worker_result?;
    if capture.failure_token().is_cancelled() {
        return Err("required SMESH runtime trace capture failed".into());
    }
    let trace = capture.snapshot().await;
    if let Ok(path) = std::env::var("SMESH_RUNTIME_TRACE_PATH") {
        capture.persist_new(path).await?;
    }
    tracing::info!(
        events = trace.events.len(),
        dropped_optional = trace.dropped_optional,
        "SMESH runtime trace capture stopped"
    );
    serve_result?;
    Ok(())
}
