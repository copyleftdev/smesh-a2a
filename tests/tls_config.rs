use std::{net::SocketAddr, path::PathBuf};

use smesh_a2a::{
    auth::{AuthenticationMethod, Principal, PrincipalLimits},
    build_secured_agent_card_with_policy,
    transport::{
        ClientAuthMode, PrincipalMap, ProductionTransportConfig, TlsMaterialPaths,
        TlsSnapshotManager, TransportMode, load_tls_snapshot,
    },
};

struct SecureTestKey(PathBuf);

impl SecureTestKey {
    fn copy(source: &std::path::Path, label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "smesh-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        std::fs::copy(source, &path).expect("copy test private key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secure copied test private key");
        }
        Self(path)
    }
}

impl Drop for SecureTestKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn required_mtls_card_does_not_advertise_bearer_as_a_standalone_alternative() {
    let card = build_secured_agent_card_with_policy("https://gateway.example", true, true, true);
    let requirements = card.security_requirements.unwrap();
    assert_eq!(requirements.len(), 1);
    assert!(requirements[0].contains_key("mutual_tls"));
    assert!(!requirements[0].contains_key("oidc_bearer"));
    let schemes = card.security_schemes.unwrap();
    assert!(schemes.contains_key("oidc_bearer"));
    assert!(schemes.contains_key("mutual_tls"));
}

#[test]
fn typed_transport_and_client_auth_modes_parse_exact_values() {
    assert_eq!("loopback-plain".parse(), Ok(TransportMode::LoopbackPlain));
    assert_eq!(
        "reverse-proxy-loopback".parse(),
        Ok(TransportMode::ReverseProxyLoopback)
    );
    assert_eq!("direct-tls".parse(), Ok(TransportMode::DirectTls));
    assert!("plain".parse::<TransportMode>().is_err());

    assert_eq!("disabled".parse(), Ok(ClientAuthMode::Disabled));
    assert_eq!("optional".parse(), Ok(ClientAuthMode::Optional));
    assert_eq!("required".parse(), Ok(ClientAuthMode::Required));
    assert!("request".parse::<ClientAuthMode>().is_err());
}

#[test]
fn public_bind_requires_direct_tls_https_and_authentication() {
    let bind: SocketAddr = "0.0.0.0:443".parse().unwrap();
    let config = ProductionTransportConfig {
        mode: TransportMode::LoopbackPlain,
        client_auth: ClientAuthMode::Disabled,
        bind,
        public_url: "http://gateway.example".to_owned(),
        oidc_enabled: false,
        cert_path: None,
        key_path: None,
        client_ca_path: None,
        principal_map_path: None,
        handshake_timeout: std::time::Duration::from_secs(5),
        max_connections: 1024,
    };
    let error = config.validate_paths_and_policy().unwrap_err().to_string();
    assert!(error.contains("non-loopback"));

    let mut direct = config;
    direct.mode = TransportMode::DirectTls;
    direct.public_url = "https://gateway.example".to_owned();
    direct.cert_path = Some(PathBuf::from("server.pem"));
    direct.key_path = Some(PathBuf::from("server.key"));
    let error = direct.validate_paths_and_policy().unwrap_err().to_string();
    assert!(error.contains("OIDC") || error.contains("mTLS"));

    direct.oidc_enabled = true;
    for invalid in [
        "https://user@gateway.example",
        "https://gateway.example/path?query=secret",
        "https://gateway.example/path#fragment",
    ] {
        direct.public_url = invalid.to_owned();
        assert!(
            direct.validate_paths_and_policy().is_err(),
            "accepted {invalid}"
        );
    }
    direct.public_url = format!("https://gateway.example/{}", "a".repeat(4096));
    assert!(direct.validate_paths_and_policy().is_err());
}

#[test]
fn tls_loader_builds_hardened_rustls_snapshot_and_rejects_insecure_key_mode() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let secure_key = SecureTestKey::copy(&root.join("server.key"), "secure-key");
    let paths = TlsMaterialPaths {
        cert: root.join("server.pem"),
        key: secure_key.0.clone(),
        client_ca: Some(root.join("client-ca.pem")),
        principal_map: Some(root.join("principals.json")),
    };
    let snapshot = load_tls_snapshot(&paths, ClientAuthMode::Optional, 7).unwrap();
    assert_eq!(snapshot.generation(), 7);
    assert_eq!(
        snapshot.server_config().alpn_protocols,
        [b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(snapshot.server_config().max_early_data_size, 0);
    assert!(snapshot.covers_public_url("https://localhost:8443/base"));
    assert!(snapshot.covers_public_url("https://127.0.0.1:8443/base"));
    assert!(!snapshot.covers_public_url("https://gateway.example/base"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let copy = std::env::temp_dir().join(format!("smesh-insecure-key-{}", std::process::id()));
        std::fs::copy(root.join("server.key"), &copy).unwrap();
        std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mut insecure = paths.clone();
        insecure.key = copy.clone();
        assert!(load_tls_snapshot(&insecure, ClientAuthMode::Optional, 8).is_err());
        std::fs::remove_file(copy).unwrap();

        let symlink =
            std::env::temp_dir().join(format!("smesh-symlink-key-{}", std::process::id()));
        std::os::unix::fs::symlink(root.join("server.key"), &symlink).unwrap();
        let mut replaced = paths;
        replaced.key = symlink.clone();
        assert!(load_tls_snapshot(&replaced, ClientAuthMode::Optional, 9).is_err());
        std::fs::remove_file(symlink).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn failed_snapshot_reload_retains_the_complete_previous_generation() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let key = std::env::temp_dir().join(format!("smesh-reload-key-{}", std::process::id()));
    std::fs::copy(root.join("server.key"), &key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let paths = TlsMaterialPaths {
        cert: root.join("server.pem"),
        key: key.clone(),
        client_ca: Some(root.join("client-ca.pem")),
        principal_map: Some(root.join("principals.json")),
    };
    let initial = load_tls_snapshot(&paths, ClientAuthMode::Required, 41).unwrap();
    let manager = TlsSnapshotManager::new(
        initial,
        paths,
        ClientAuthMode::Required,
        "https://localhost:8443".to_owned(),
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(manager.reload().is_err());
    assert_eq!(manager.current().generation(), 41);
    std::fs::remove_file(key).unwrap();
}

#[cfg(unix)]
#[test]
fn reload_rejects_certificate_that_drops_the_configured_public_url() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let root = std::env::temp_dir().join(format!(
        "smesh-public-url-reload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let cert = root.join("server.pem");
    let key = root.join("server.key");
    std::fs::copy(fixtures.join("server.pem"), &cert).unwrap();
    std::fs::copy(fixtures.join("server.key"), &key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let paths = TlsMaterialPaths {
        cert: cert.clone(),
        key: key.clone(),
        client_ca: None,
        principal_map: None,
    };
    let initial = load_tls_snapshot(&paths, ClientAuthMode::Disabled, 7).unwrap();
    let manager = TlsSnapshotManager::new(
        initial,
        paths,
        ClientAuthMode::Disabled,
        "https://localhost:8443".to_owned(),
    );

    std::fs::copy(fixtures.join("evil-server.pem"), cert).unwrap();
    std::fs::copy(fixtures.join("evil-server.key"), &key).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(manager.reload().is_err());
    assert_eq!(manager.current().generation(), 7);
    assert!(
        manager
            .current()
            .covers_public_url("https://localhost:8443")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mutual_tls_principal_constructor_is_bounded_and_typed() {
    let principal = Principal::mutual_tls(
        "spiffe://trust.example".to_owned(),
        "agent-17".to_owned(),
        PrincipalLimits::default(),
    )
    .unwrap();
    assert_eq!(principal.issuer(), "spiffe://trust.example");
    assert_eq!(principal.subject(), "agent-17");
    assert_eq!(
        principal.authentication_method(),
        AuthenticationMethod::MutualTls
    );
    assert!(!format!("{principal:?}").contains("agent-17"));
}

#[test]
fn principal_map_requires_canonical_fingerprints_and_rejects_duplicates() {
    let fingerprint = format!("sha256:{}", "a".repeat(64));
    let json = format!(r#"{{"{fingerprint}":{{"issuer":"mtls:partners","subject":"agent-17"}}}}"#);
    let map = PrincipalMap::from_json(json.as_bytes(), 64 * 1024, 128).unwrap();
    let principal = map.lookup(&fingerprint).unwrap();
    assert_eq!(principal.subject(), "agent-17");
    assert_eq!(
        principal.authentication_method(),
        AuthenticationMethod::MutualTls
    );

    let uppercase = format!(
        r#"{{"sha256:{}":{{"issuer":"x","subject":"y"}}}}"#,
        "A".repeat(64)
    );
    assert!(PrincipalMap::from_json(uppercase.as_bytes(), 64 * 1024, 128).is_err());

    let duplicate = format!(
        r#"{{"{fingerprint}":{{"issuer":"x","subject":"y"}},"{fingerprint}":{{"issuer":"x","subject":"z"}}}}"#
    );
    assert!(PrincipalMap::from_json(duplicate.as_bytes(), 64 * 1024, 128).is_err());
}

#[test]
fn reverse_proxy_is_loopback_only_and_requires_oidc() {
    let config = ProductionTransportConfig {
        mode: TransportMode::ReverseProxyLoopback,
        client_auth: ClientAuthMode::Disabled,
        bind: "127.0.0.1:3000".parse().unwrap(),
        public_url: "https://gateway.example".to_owned(),
        oidc_enabled: false,
        cert_path: None,
        key_path: None,
        client_ca_path: None,
        principal_map_path: None,
        handshake_timeout: std::time::Duration::from_secs(5),
        max_connections: 1024,
    };
    assert!(
        config
            .validate_paths_and_policy()
            .unwrap_err()
            .to_string()
            .contains("OIDC")
    );
}
