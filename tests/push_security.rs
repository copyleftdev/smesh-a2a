#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(all(debug_assertions, unix))]
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use std::{net::IpAddr, str::FromStr};

use smesh_a2a::{
    build_agent_card_with_push_readiness, callback_quota_semantic_id,
    callback_request_accounted_bytes,
    push::{
        CallbackResolver, CallbackSigner, CallbackTransportError, CanonicalCallbackUrl,
        DeliveryDisposition, PushPolicy, PushReadiness, RetryPolicy, SecureCallbackTransport,
        SystemCallbackResolver, classify_status, delivery_event_id, is_public_callback_ip,
        resolve_push_config_path, retry_after_seconds, retry_after_seconds_at,
    },
};

#[test]
fn callback_quota_identity_and_serialized_byte_accounting_are_attempt_exact() {
    let first = callback_quota_semantic_id("event-a", "config-a", 1);
    assert_eq!(first, callback_quota_semantic_id("event-a", "config-a", 1));
    assert_ne!(first, callback_quota_semantic_id("event-a", "config-a", 2));
    assert_ne!(first, callback_quota_semantic_id("event-a", "config-b", 1));
    let one = callback_request_accounted_bytes(
        "https://callbacks.example.com:443/a2a/task",
        "endpoint",
        "event-a",
        1_700_000_000,
        1,
        "generation-1",
        100,
    )
    .unwrap();
    let plus_one = callback_request_accounted_bytes(
        "https://callbacks.example.com:443/a2a/task",
        "endpoint",
        "event-a",
        1_700_000_000,
        1,
        "generation-1",
        101,
    )
    .unwrap();
    assert_eq!(plus_one, one + 1);
}

#[test]
fn callback_transport_errors_are_closed_and_do_not_carry_raw_details() {
    for error in [
        CallbackTransportError::DnsUnsafe,
        CallbackTransportError::DnsUnavailable,
        CallbackTransportError::Tls,
        CallbackTransportError::Configuration,
        CallbackTransportError::Connect,
        CallbackTransportError::Timeout,
        CallbackTransportError::Reset,
        CallbackTransportError::ResponseTooLarge,
    ] {
        let rendered = error.to_string();
        assert!(!rendered.contains("http"));
        assert!(!rendered.contains("127.0.0.1"));
    }
    let _resolver: SystemCallbackResolver = SystemCallbackResolver::new();
}

#[test]
fn canonical_callback_url_accepts_only_exact_https_dns_targets() {
    let valid = CanonicalCallbackUrl::parse("https://callbacks.example.com:443/a2a/task").unwrap();
    assert_eq!(valid.as_str(), "https://callbacks.example.com:443/a2a/task");
    assert_eq!(valid.host(), "callbacks.example.com");
    assert_eq!(valid.port(), 443);
    assert_eq!(valid.path(), "/a2a/task");

    for invalid in [
        "http://callbacks.example.com:443/a2a/task",
        "https://callbacks.example.com/a2a/task",
        "https://CALLBACKS.example.com:443/a2a/task",
        "https://callbacks.example.com.:443/a2a/task",
        "https://user@callbacks.example.com:443/a2a/task",
        "https://callbacks.example.com:443/a2a/task?q=1",
        "https://callbacks.example.com:443/a2a/task#fragment",
        "https://127.0.0.1:443/a2a/task",
        "https://[::1]:443/a2a/task",
        "https://*.example.com:443/a2a/task",
        "https://callbacks.example.com:443//a2a",
        "https://callbacks.example.com:443/a2a%2ftask",
        "https://callbacks.example.com:443/a2a\\task",
    ] {
        assert!(
            CanonicalCallbackUrl::parse(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn callback_ip_policy_rejects_special_use_and_mapped_addresses() {
    for blocked in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "64:ff9b::192.0.2.1",
        "100::1",
        "2001::1",
        "2001:2::1",
        "2001:db8::1",
        "2002:c000:0201::1",
        "fc00::1",
        "fe80::1",
        "ff00::1",
    ] {
        let ip = IpAddr::from_str(blocked).unwrap();
        assert!(!is_public_callback_ip(ip), "accepted {blocked}");
    }
    for allowed in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
        assert!(is_public_callback_ip(IpAddr::from_str(allowed).unwrap()));
    }
}

#[test]
fn hmac_signature_binds_every_delivery_field_and_exact_body() {
    let signer = CallbackSigner::new(b"0123456789abcdef0123456789abcdef").unwrap();
    let body = br#"{"status":"completed"}"#;
    let signature = signer.sign(
        "https://callbacks.example.com:443/a2a/task",
        "endpoint-1",
        "event-1",
        1_788_080_400,
        2,
        "generation-7",
        body,
    );
    assert!(signer.verify(
        "https://callbacks.example.com:443/a2a/task",
        "endpoint-1",
        "event-1",
        1_788_080_400,
        2,
        "generation-7",
        body,
        &signature,
    ));
    assert!(!signer.verify(
        "https://callbacks.example.com:443/a2a/other",
        "endpoint-1",
        "event-1",
        1_788_080_400,
        2,
        "generation-7",
        body,
        &signature,
    ));
    assert!(!signer.verify(
        "https://callbacks.example.com:443/a2a/task",
        "endpoint-1",
        "event-1",
        1_788_080_400,
        3,
        "generation-7",
        body,
        &signature,
    ));
}

#[test]
fn status_and_retry_after_are_closed_and_bounded() {
    for status in 200..=299 {
        assert_eq!(classify_status(status), DeliveryDisposition::Delivered);
    }
    for status in [408, 425, 429, 500, 502, 503, 504] {
        assert_eq!(classify_status(status), DeliveryDisposition::Retry);
    }
    for status in [300, 301, 302, 307, 308, 400, 401, 403, 409, 422, 501, 511] {
        assert_eq!(classify_status(status), DeliveryDisposition::Permanent);
    }
    assert_eq!(retry_after_seconds(429, &["60"], 5, 3_600), Some(60));
    assert_eq!(retry_after_seconds(503, &["99999"], 5, 3_600), Some(3_600));
    assert_eq!(retry_after_seconds(429, &["1"], 5, 3_600), Some(5));
    assert_eq!(retry_after_seconds(500, &["60"], 5, 3_600), None);
    assert_eq!(retry_after_seconds(429, &["1", "2"], 5, 3_600), None);
    assert_eq!(retry_after_seconds(429, &["-1"], 5, 3_600), None);
    assert_eq!(
        retry_after_seconds_at(
            503,
            &["Sun, 06 Nov 1994 08:50:00 GMT"],
            784_111_200,
            5,
            3_600,
        ),
        Some(600)
    );
    assert_eq!(
        retry_after_seconds_at(
            503,
            &["Sun, 06 Nov 1994 08:30:00 GMT"],
            784_111_200,
            5,
            3_600,
        ),
        None
    );
    assert_eq!(
        retry_after_seconds_at(
            429,
            &["Sat, 06 Nov 2094 08:50:00 GMT"],
            784_111_200,
            5,
            3_600,
        ),
        Some(3_600)
    );
}

#[test]
fn callback_ip_special_range_boundaries_and_mapped_v4_are_exact() {
    for blocked in [
        "0.255.255.255",
        "10.255.255.255",
        "100.127.255.255",
        "127.255.255.255",
        "169.254.255.255",
        "172.31.255.255",
        "192.0.0.255",
        "192.0.2.255",
        "192.31.196.255",
        "192.52.193.255",
        "192.88.99.255",
        "192.168.255.255",
        "192.175.48.255",
        "198.19.255.255",
        "198.51.100.255",
        "203.0.113.255",
        "239.255.255.255",
        "255.255.255.255",
        "::ffff:10.255.255.255",
        "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:2::ffff",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ] {
        assert!(
            !is_public_callback_ip(blocked.parse().unwrap()),
            "accepted {blocked}"
        );
    }
    for allowed in [
        "1.0.0.0",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "191.255.255.255",
        "192.0.1.0",
        "192.0.3.0",
        "192.31.195.255",
        "192.31.197.0",
        "192.52.192.255",
        "192.52.194.0",
        "192.88.98.255",
        "192.88.100.0",
        "192.167.255.255",
        "192.169.0.0",
        "192.175.47.255",
        "192.175.49.0",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.99.255",
        "198.51.101.0",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255",
        "::ffff:8.8.8.8",
        "2001:200::",
        "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
        "2001:db9::",
        "2003::",
    ] {
        assert!(
            is_public_callback_ip(allowed.parse().unwrap()),
            "rejected {allowed}"
        );
    }
}

#[test]
fn callback_ipv6_documentation_3fff_prefix_is_never_public() {
    for address in ["3fff::", "3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff"] {
        assert!(
            !is_public_callback_ip(address.parse().unwrap()),
            "{address}"
        );
    }
    assert!(is_public_callback_ip(
        "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
    ));
    assert!(!is_public_callback_ip("4000::".parse().unwrap()));
}

#[tokio::test]
async fn resolver_is_fresh_per_attempt_and_mixed_answers_fail_closed() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct SequenceResolver(AtomicUsize);
    #[async_trait::async_trait]
    impl CallbackResolver for SequenceResolver {
        async fn resolve(
            &self,
            _host: &str,
        ) -> Result<Vec<IpAddr>, smesh_a2a::push::PushSecurityError> {
            let call = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(match call {
                0 => vec!["8.8.8.8".parse().unwrap()],
                1 => vec!["1.1.1.1".parse().unwrap()],
                _ => vec!["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            })
        }
    }

    let resolver = Arc::new(SequenceResolver(AtomicUsize::new(0)));
    let transport = SecureCallbackTransport::new(resolver.clone(), 8).unwrap();
    let target = CanonicalCallbackUrl::parse("https://callbacks.example.com:443/a2a/task").unwrap();
    assert_eq!(
        transport
            .resolve_attempt(&target)
            .await
            .unwrap()
            .ip()
            .to_string(),
        "8.8.8.8"
    );
    assert_eq!(
        transport
            .resolve_attempt(&target)
            .await
            .unwrap()
            .ip()
            .to_string(),
        "1.1.1.1"
    );
    assert!(transport.resolve_attempt(&target).await.is_err());
    assert_eq!(resolver.0.load(Ordering::SeqCst), 3);
}

#[test]
fn readiness_card_and_retry_identity_are_stable_and_bounded() {
    let readiness = PushReadiness::new();
    let starting = build_agent_card_with_push_readiness("https://gateway.example", &readiness);
    assert_eq!(starting.capabilities.push_notifications, Some(false));
    assert_eq!(starting.capabilities.extended_agent_card, Some(false));
    readiness.mark_ready();
    let ready = build_agent_card_with_push_readiness("https://gateway.example", &readiness);
    assert_eq!(ready.capabilities.push_notifications, Some(true));
    assert_eq!(ready.capabilities.extended_agent_card, Some(false));
    readiness.mark_fatal();
    assert!(readiness.is_fatal());
    let fatal = build_agent_card_with_push_readiness("https://gateway.example", &readiness);
    assert_eq!(fatal.capabilities.push_notifications, Some(false));
    assert_eq!(fatal.capabilities.extended_agent_card, Some(false));

    let first = delivery_event_id("tenant-a", "task-1", 42, 7, "config-1", 3);
    let replay = delivery_event_id("tenant-a", "task-1", 42, 7, "config-1", 3);
    assert_eq!(first, replay);
    assert_ne!(
        first,
        delivery_event_id("tenant-a", "task-1", 42, 7, "config-1", 4)
    );

    let retry = RetryPolicy::new(8, 5_000, 900_000, 86_400_000).unwrap();
    assert_eq!(retry.full_jitter_ms(1, 0), Some(0));
    assert_eq!(retry.full_jitter_ms(1, u64::MAX), Some(3_210));
    assert_eq!(retry.clamp_delay_ms(Some(0), 1, 17), Some(5_000));
    assert_eq!(retry.clamp_delay_ms(Some(u64::MAX), 1, 17), Some(900_000));
    assert_eq!(retry.clamp_delay_ms(Some(50_000), 1, 17), Some(50_000));
    assert!(retry.full_jitter_ms(9, 0).is_none());
    assert!(retry.can_attempt(8, 86_399_999));
    assert!(!retry.can_attempt(9, 1));
    assert!(!retry.can_attempt(1, 86_400_000));
}

#[test]
fn callback_readiness_waits_for_every_configured_worker_and_fatal_is_sticky() {
    let readiness = PushReadiness::for_workers(3).unwrap();
    assert!(!readiness.is_ready());
    readiness.mark_worker_ready();
    readiness.mark_worker_ready();
    assert!(
        !readiness.is_ready(),
        "a partial worker set must not advertise push"
    );
    readiness.mark_worker_ready();
    assert!(readiness.is_ready());
    readiness.mark_fatal();
    readiness.mark_worker_ready();
    assert!(!readiness.is_ready());
    assert!(readiness.is_fatal());
    assert!(PushReadiness::for_workers(0).is_none());
}

#[test]
fn production_push_config_name_is_canonical_and_legacy_alias_conflicts_fail_closed() {
    use std::ffi::{OsStr, OsString};

    assert_eq!(
        resolve_push_config_path(Some(OsString::from("new.toml")), None).unwrap(),
        Some(OsString::from("new.toml"))
    );
    assert_eq!(
        resolve_push_config_path(None, Some(OsString::from("old.toml"))).unwrap(),
        Some(OsString::from("old.toml"))
    );
    assert!(
        resolve_push_config_path(
            Some(OsString::from("new.toml")),
            Some(OsString::from("old.toml"))
        )
        .is_err()
    );
    assert!(resolve_push_config_path(Some(OsStr::new("").to_os_string()), None).is_err());
}

#[test]
fn callback_telemetry_names_are_closed_and_low_cardinality() {
    use smesh_a2a::telemetry::{EventName, MetricName};

    assert_eq!(
        EventName::PushConfigChanged.as_str(),
        "smesh.push.config.changed"
    );
    assert_eq!(EventName::PushDelivery.as_str(), "smesh.push.delivery");
    assert_eq!(
        EventName::PushPolicyReconciled.as_str(),
        "smesh.push.policy.reconciled"
    );
    assert_eq!(MetricName::PushDelivery.as_str(), "smesh.a2a.push.delivery");
}

#[test]
#[cfg(unix)]
fn policy_load_validates_all_secret_and_tls_material_before_startup() {
    let root = std::env::temp_dir().join(format!("smesh-push-material-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let secret = root.join("secret");
    let ca = root.join("ca.pem");
    std::fs::write(&secret, b"0123456789abcdef0123456789abcdef").unwrap();
    std::fs::write(&ca, b"not a certificate").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600)).unwrap();
    let policy_path = root.join("push.toml");
    let document = POLICY
        .replace("/run/secrets/billing-events.key", secret.to_str().unwrap())
        .replace(
            "event = \"terminal\"",
            &format!("event = \"terminal\"\nca_file = {ca:?}"),
        );
    std::fs::write(&policy_path, document).unwrap();
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(PushPolicy::load(&policy_path).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn strict_policy_enrolls_exact_tenant_url_and_rejects_unknown_fields() {
    let policy = PushPolicy::parse_bytes(POLICY.as_bytes()).unwrap();
    assert!(policy.enabled());
    let enrollment = policy
        .enrollment(
            "tenant-a",
            "billing-events",
            "https://callbacks.example.com:443/a2a/task",
        )
        .unwrap();
    assert_eq!(enrollment.endpoint_id(), "billing-events");
    assert!(
        policy
            .enrollment(
                "tenant-b",
                "billing-events",
                "https://callbacks.example.com:443/a2a/task"
            )
            .is_err()
    );
    assert!(
        policy
            .enrollment(
                "tenant-a",
                "billing-events",
                "https://callbacks.example.com:443/a2a/other"
            )
            .is_err()
    );

    let unknown = format!("{POLICY}\nattacker_override = true\n");
    assert!(PushPolicy::parse_bytes(unknown.as_bytes()).is_err());
    for caller_auth in [
        "token = \"caller-secret\"",
        "credentials = \"caller-secret\"",
        "authentication = { credentials = \"caller-secret\" }",
    ] {
        let forbidden = POLICY.replace(
            "auth = \"hmac-sha256\"",
            &format!("auth = \"hmac-sha256\"\n{caller_auth}"),
        );
        assert!(PushPolicy::parse_bytes(forbidden.as_bytes()).is_err());
    }
    let duplicate = POLICY.replace(
        "endpoint_id = \"billing-events\"",
        "endpoint_id = \"billing-events\"\nendpoint_id = \"other\"",
    );
    assert!(PushPolicy::parse_bytes(duplicate.as_bytes()).is_err());
    assert_eq!(policy.worker_count(), 4);
    assert_eq!(policy.claim_lease_ms(), 30_000);
    assert_eq!(policy.max_response_bytes(), 4_096);
    assert_eq!(policy.retry_policy().full_jitter_ms(1, 0), Some(0));
    let rendered = format!("{policy:?} {:?}", policy.enrollments()[0]);
    for sensitive in [
        "callbacks.example.com",
        "/a2a/task",
        "/run/secrets",
        "caller-secret",
    ] {
        assert!(!rendered.contains(sensitive));
    }
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn debug_static_dns_map_is_explicit_private_and_pins_original_host() {
    use std::{io::Write as _, os::unix::fs::PermissionsExt as _};
    let root = std::env::temp_dir().join(format!("smesh-push-dns-{}", rand::random::<u64>()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let map = root.join("dns.json");
    let mut file = std::fs::File::create(&map).unwrap();
    file.write_all(br#"{"callback.test":["127.0.0.1"]}"#)
        .unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    let policy = PushPolicy::parse_bytes(POLICY.as_bytes()).unwrap();
    assert!(SecureCallbackTransport::from_policy_test_dns_map(&policy, &map, false).is_err());
    let transport = SecureCallbackTransport::from_policy_test_dns_map(&policy, &map, true).unwrap();
    let target = CanonicalCallbackUrl::parse("https://callback.test:8443/a2a/task").unwrap();
    assert_eq!(
        transport.resolve_attempt(&target).await.unwrap(),
        "127.0.0.1:8443".parse().unwrap()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(all(debug_assertions, unix))]
mod wire_matrix {
    use super::*;
    use http_body_util::{BodyExt as _, Full};
    use hyper::{
        Request, Response,
        body::{Bytes, Incoming},
        service::service_fn,
    };
    use hyper_util::rt::TokioIo;
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;

    const BODY: &[u8] = br#"{"status":"completed","sequence":17}"#;
    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[derive(Clone)]
    struct CertPair {
        cert_pem: String,
        key_pem: String,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    }

    struct Pki {
        ca_pem: String,
        server: CertPair,
        wrong_name: CertPair,
        expired: CertPair,
        client: CertPair,
        client_ca_pem: String,
        wrong_client: CertPair,
    }

    fn ca() -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    }

    fn signed_pair(
        names: &[&str],
        issuer: &rcgen::Certificate,
        issuer_key: &KeyPair,
        client: bool,
        expired: bool,
    ) -> CertPair {
        let mut params =
            CertificateParams::new(names.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>())
                .unwrap();
        if client {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        if expired {
            params.not_before = rcgen::date_time_ymd(2018, 1, 1);
            params.not_after = rcgen::date_time_ymd(2019, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, issuer, issuer_key).unwrap();
        CertPair {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().as_ref().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    fn pki() -> Pki {
        let (server_ca, server_ca_key) = ca();
        let (client_ca, client_ca_key) = ca();
        let (wrong_client_ca, wrong_client_ca_key) = ca();
        Pki {
            ca_pem: server_ca.pem(),
            server: signed_pair(&["callback.test"], &server_ca, &server_ca_key, false, false),
            wrong_name: signed_pair(&["other.test"], &server_ca, &server_ca_key, false, false),
            expired: signed_pair(&["callback.test"], &server_ca, &server_ca_key, false, true),
            client: signed_pair(&["push-client"], &client_ca, &client_ca_key, true, false),
            client_ca_pem: client_ca.pem(),
            wrong_client: signed_pair(
                &["wrong-client"],
                &wrong_client_ca,
                &wrong_client_ca_key,
                true,
                false,
            ),
        }
    }

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("smesh-push-wire-{}", rand::random::<u64>()));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { root }
        }
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
        fn enrollment(
            &self,
            port: u16,
            ca: &Path,
            identity: Option<(&Path, &Path)>,
        ) -> (PushPolicy, PathBuf) {
            let secret = self.write("secret.key", SECRET);
            let dns = self.write("dns.json", br#"{"callback.test":["127.0.0.1"]}"#);
            let identity_fields = identity.map_or_else(String::new, |(cert, key)| {
                format!(
                    "mtls_cert_file = \"{}\"\nmtls_key_file = \"{}\"\n",
                    cert.display(),
                    key.display()
                )
            });
            let policy = format!(
                r#"
schema = "smesh-push/1"
enabled = true
policy_id = "wire-matrix"
policy_revision = 1
policy_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
max_pending = 10
max_configs_per_task = 1
max_configs_per_tenant = 10
worker_count = 1
claim_batch = 1
claim_lease_ms = 1000
dns_timeout_ms = 500
max_dns_answers = 8
connect_timeout_ms = 500
request_timeout_ms = 1500
max_response_bytes = 4096
max_attempts = 2
base_retry_ms = 10
max_retry_ms = 100
max_delivery_age_ms = 1000
[[enrollments]]
tenant = "tenant-a"
endpoint_id = "endpoint-a"
url = "https://callback.test:{port}/a2a/callback"
event = "terminal"
auth = "hmac-sha256"
key_generation = "generation-7"
secret_file = "{}"
ca_file = "{}"
{identity_fields}"#,
                secret.display(),
                ca.display()
            );
            let path = self.write("push.toml", policy.as_bytes());
            (PushPolicy::load(&path).unwrap(), dns)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Clone)]
    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        hang: bool,
    }
    impl Reply {
        fn status(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: Vec::new(),
                hang: false,
            }
        }
    }

    #[derive(Clone, Debug)]
    struct Seen {
        host: String,
        headers: hyper::HeaderMap,
        body: Vec<u8>,
        peer_cert: bool,
    }

    struct TestServer {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<Seen>>>,
        connections: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn server_config(pair: &CertPair, client_ca: Option<&str>) -> ServerConfig {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let builder = ServerConfig::builder();
        let builder = if let Some(pem) = client_ca {
            use rustls::pki_types::pem::PemObject as _;
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                roots.add(cert.unwrap()).unwrap();
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };
        builder
            .with_single_cert(
                vec![CertificateDer::from(pair.cert_der.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pair.key_der.clone())),
            )
            .unwrap()
    }

    async fn start_server(config: ServerConfig, reply: Reply) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let seen_out = requests.clone();
        let connection_out = connections.clone();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                connection_out.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let seen_out = seen_out.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let peer_cert = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .is_some_and(|v| !v.is_empty());
                    let service = service_fn(move |request: Request<Incoming>| {
                        let seen_out = seen_out.clone();
                        let reply = reply.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body.collect().await.unwrap().to_bytes().to_vec();
                            seen_out.lock().unwrap().push(Seen {
                                host: parts
                                    .headers
                                    .get("host")
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                                    .to_owned(),
                                headers: parts.headers,
                                body,
                                peer_cert,
                            });
                            if reply.hang {
                                std::future::pending::<()>().await;
                            }
                            let mut response = Response::builder().status(reply.status);
                            for (name, value) in &reply.headers {
                                response = response.header(*name, value);
                            }
                            Ok::<_, std::convert::Infallible>(
                                response.body(Full::new(Bytes::from(reply.body))).unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        TestServer {
            address,
            requests,
            connections,
            task,
        }
    }

    async fn send(
        fixture: &Fixture,
        pki: &Pki,
        server: &TestServer,
        identity: Option<&CertPair>,
        max: usize,
    ) -> Result<smesh_a2a::push::CallbackResponse, CallbackTransportError> {
        let ca = fixture.write("server-ca.pem", pki.ca_pem.as_bytes());
        let identity_paths = identity.map(|pair| {
            (
                fixture.write("client.pem", pair.cert_pem.as_bytes()),
                fixture.write("client.key", pair.key_pem.as_bytes()),
            )
        });
        let refs = identity_paths
            .as_ref()
            .map(|(a, b)| (a.as_path(), b.as_path()));
        let (policy, dns) = fixture.enrollment(server.address.port(), &ca, refs);
        let transport =
            SecureCallbackTransport::from_policy_test_dns_map(&policy, &dns, true).unwrap();
        transport
            .send_enrollment(
                &policy.enrollments()[0],
                "event-17",
                1_788_080_400,
                2,
                BODY,
                max,
            )
            .await
    }

    #[tokio::test]
    async fn real_https_pin_sni_host_and_signed_wire_succeed() {
        let fixture = Fixture::new();
        let pki = pki();
        let server = start_server(server_config(&pki.server, None), Reply::status(204)).await;
        let response = send(&fixture, &pki, &server, None, 4096).await.unwrap();
        assert_eq!(response.disposition(), DeliveryDisposition::Delivered);
        let seen = server.requests.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let seen = &seen[0];
        assert_eq!(
            seen.host,
            format!("callback.test:{}", server.address.port())
        );
        assert_eq!(seen.body, BODY);
        assert_eq!(
            seen.headers["content-digest"],
            smesh_a2a::push::content_digest_header(BODY)
        );
        assert_eq!(seen.headers["idempotency-key"], "event-17");
        assert_eq!(seen.headers["x-smesh-callback-attempt"], "2");
        let signer = CallbackSigner::new(SECRET).unwrap();
        assert!(signer.verify(
            &format!(
                "https://callback.test:{}/a2a/callback",
                server.address.port()
            ),
            "endpoint-a",
            "event-17",
            1_788_080_400,
            2,
            "generation-7",
            BODY,
            seen.headers["x-smesh-callback-signature"].to_str().unwrap()
        ));
    }

    #[tokio::test]
    async fn tls_name_expiry_trust_and_mtls_fail_before_http_application() {
        let fixture = Fixture::new();
        let pki = pki();
        let wrong_ca = {
            let (wrong, _) = ca();
            wrong.pem()
        };
        for (case, pair, ca_pem, client_ca, identity) in [
            ("wrong CA", &pki.server, wrong_ca.as_str(), None, None),
            (
                "wrong name",
                &pki.wrong_name,
                pki.ca_pem.as_str(),
                None,
                None,
            ),
            ("expired", &pki.expired, pki.ca_pem.as_str(), None, None),
            (
                "missing mTLS",
                &pki.server,
                pki.ca_pem.as_str(),
                Some(pki.client_ca_pem.as_str()),
                None,
            ),
            (
                "wrong client CA",
                &pki.server,
                pki.ca_pem.as_str(),
                Some(pki.client_ca_pem.as_str()),
                Some(&pki.wrong_client),
            ),
        ] {
            let server = start_server(server_config(pair, client_ca), Reply::status(204)).await;
            let custom = Pki {
                ca_pem: ca_pem.to_owned(),
                server: pki.server.clone(),
                wrong_name: pki.wrong_name.clone(),
                expired: pki.expired.clone(),
                client: pki.client.clone(),
                client_ca_pem: pki.client_ca_pem.clone(),
                wrong_client: pki.wrong_client.clone(),
            };
            assert_eq!(
                send(&fixture, &custom, &server, identity, 4096).await,
                Err(CallbackTransportError::Tls),
                "{case}"
            );
            assert!(server.requests.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn correct_mtls_identity_reaches_application_and_peer_is_observed() {
        let fixture = Fixture::new();
        let pki = pki();
        let server = start_server(
            server_config(&pki.server, Some(&pki.client_ca_pem)),
            Reply::status(200),
        )
        .await;
        assert_eq!(
            send(&fixture, &pki, &server, Some(&pki.client), 4096)
                .await
                .unwrap()
                .disposition(),
            DeliveryDisposition::Delivered
        );
        let seen = server.requests.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].peer_cert);
    }

    #[tokio::test]
    async fn every_redirect_is_permanent_and_never_followed() {
        let fixture = Fixture::new();
        let pki = pki();
        for status in [301, 302, 303, 307, 308] {
            for location in [
                "/same-origin",
                "https://other.test:443/cross",
                "https://127.0.0.1:9/private",
            ] {
                let mut reply = Reply::status(status);
                reply.headers.push(("location", location.to_owned()));
                let server = start_server(server_config(&pki.server, None), reply).await;
                let response = send(&fixture, &pki, &server, None, 4096).await.unwrap();
                assert_eq!(response.disposition(), DeliveryDisposition::Permanent);
                assert_eq!(server.requests.lock().unwrap().len(), 1);
                assert_eq!(server.connections.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[tokio::test]
    async fn wire_status_retry_after_and_response_bounds_matrix() {
        let fixture = Fixture::new();
        let pki = pki();
        for (status, expected) in [
            (200, DeliveryDisposition::Delivered),
            (299, DeliveryDisposition::Delivered),
            (408, DeliveryDisposition::Retry),
            (425, DeliveryDisposition::Retry),
            (429, DeliveryDisposition::Retry),
            (500, DeliveryDisposition::Retry),
            (502, DeliveryDisposition::Retry),
            (503, DeliveryDisposition::Retry),
            (504, DeliveryDisposition::Retry),
            (400, DeliveryDisposition::Permanent),
            (418, DeliveryDisposition::Permanent),
            (501, DeliveryDisposition::Permanent),
        ] {
            let server =
                start_server(server_config(&pki.server, None), Reply::status(status)).await;
            assert_eq!(
                send(&fixture, &pki, &server, None, 4096)
                    .await
                    .unwrap()
                    .disposition(),
                expected,
                "status {status}"
            );
        }
        let mut reply = Reply::status(429);
        reply.headers.push(("retry-after", "99999".to_owned()));
        let server = start_server(server_config(&pki.server, None), reply).await;
        assert_eq!(
            send(&fixture, &pki, &server, None, 4096)
                .await
                .unwrap()
                .retry_after_seconds(),
            Some(99_999)
        );
        let mut oversized = Reply::status(200);
        oversized.body = vec![b'x'; 128];
        let server = start_server(server_config(&pki.server, None), oversized).await;
        assert_eq!(
            send(&fixture, &pki, &server, None, 64).await,
            Err(CallbackTransportError::ResponseTooLarge)
        );
        let mut hang = Reply::status(200);
        hang.hang = true;
        let server = start_server(server_config(&pki.server, None), hang).await;
        assert_eq!(
            send(&fixture, &pki, &server, None, 4096).await,
            Err(CallbackTransportError::Timeout)
        );
    }

    #[tokio::test]
    async fn malformed_tls_material_fails_before_dns_or_connect() {
        struct CountingResolver(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl CallbackResolver for CountingResolver {
            async fn resolve(
                &self,
                _: &str,
            ) -> Result<Vec<IpAddr>, smesh_a2a::push::PushSecurityError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec!["8.8.8.8".parse().unwrap()])
            }
        }
        let fixture = Fixture::new();
        let bad_ca = fixture.write("bad-ca.pem", b"not a certificate");
        let secret = fixture.write("secret.key", SECRET);
        let policy_text = POLICY
            .replace(
                "https://callbacks.example.com:443/a2a/task",
                "https://callback.test:443/a2a/callback",
            )
            .replace("/run/secrets/billing-events.key", secret.to_str().unwrap())
            .replace(
                "event = \"terminal\"",
                &format!("event = \"terminal\"\nca_file = {bad_ca:?}"),
            );
        let policy = PushPolicy::parse_bytes(policy_text.as_bytes()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let transport =
            SecureCallbackTransport::new(Arc::new(CountingResolver(calls.clone())), 8).unwrap();
        assert_eq!(
            transport
                .send_enrollment(&policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                .await,
            Err(CallbackTransportError::Configuration)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        std::fs::write(&bad_ca, vec![b'x'; 256 * 1024 + 1]).unwrap();
        std::fs::set_permissions(&bad_ca, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            transport
                .send_enrollment(&policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                .await,
            Err(CallbackTransportError::Configuration)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let valid_ca = fixture.write("valid-ca.pem", pki().ca_pem.as_bytes());
        std::fs::remove_file(&bad_ca).unwrap();
        std::os::unix::fs::symlink(&valid_ca, &bad_ca).unwrap();
        assert_eq!(
            transport
                .send_enrollment(&policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                .await,
            Err(CallbackTransportError::Configuration)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        std::fs::remove_file(&bad_ca).unwrap();
        std::fs::copy(&valid_ca, &bad_ca).unwrap();
        std::fs::set_permissions(&bad_ca, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            transport
                .send_enrollment(&policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                .await,
            Err(CallbackTransportError::Configuration)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct ScriptedResolver {
        answers: Vec<Vec<IpAddr>>,
        call: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl CallbackResolver for ScriptedResolver {
        async fn resolve(
            &self,
            _: &str,
        ) -> Result<Vec<IpAddr>, smesh_a2a::push::PushSecurityError> {
            let call = self.call.fetch_add(1, Ordering::SeqCst);
            Ok(self.answers[call.min(self.answers.len() - 1)].clone())
        }
    }

    #[tokio::test]
    async fn synthetic_public_pins_are_recorded_and_fresh_on_each_real_connection() {
        let fixture = Fixture::new();
        let pki = pki();
        let server = start_server(server_config(&pki.server, None), Reply::status(204)).await;
        let ca = fixture.write("server-ca.pem", pki.ca_pem.as_bytes());
        let (policy, _) = fixture.enrollment(server.address.port(), &ca, None);
        let a: IpAddr = "8.8.8.8".parse().unwrap();
        let b: IpAddr = "1.1.1.1".parse().unwrap();
        let resolver = Arc::new(ScriptedResolver {
            answers: vec![vec![a], vec![b]],
            call: AtomicUsize::new(0),
        });
        let map = BTreeMap::from([
            (a, "127.0.0.1".parse().unwrap()),
            (b, "127.0.0.1".parse().unwrap()),
        ]);
        let transport =
            SecureCallbackTransport::new_test_mapped(resolver, 8, map, None, true).unwrap();
        for attempt in 1..=2 {
            assert_eq!(
                transport
                    .send_enrollment(&policy.enrollments()[0], "event-17", 1, attempt, BODY, 4096)
                    .await
                    .unwrap()
                    .disposition(),
                DeliveryDisposition::Delivered
            );
        }
        assert_eq!(
            transport.test_requested_pins(),
            [
                SocketAddr::new(a, server.address.port()),
                SocketAddr::new(b, server.address.port())
            ]
        );
        assert_eq!(server.connections.load(Ordering::SeqCst), 2);
        let seen = server.requests.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let signer = CallbackSigner::new(SECRET).unwrap();
        let target = format!(
            "https://callback.test:{}/a2a/callback",
            server.address.port()
        );
        let mut accepted = BTreeMap::<String, Vec<u8>>::new();
        let mut effects = 0;
        for request in seen.iter() {
            let event = request.headers["x-smesh-callback-event-id"]
                .to_str()
                .unwrap();
            let attempt = request.headers["x-smesh-callback-attempt"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                request.headers["content-digest"],
                smesh_a2a::push::content_digest_header(&request.body)
            );
            assert!(
                signer.verify(
                    &target,
                    "endpoint-a",
                    event,
                    1,
                    attempt,
                    "generation-7",
                    &request.body,
                    request.headers["x-smesh-callback-signature"]
                        .to_str()
                        .unwrap(),
                )
            );
            match accepted.get(event) {
                None => {
                    accepted.insert(event.to_owned(), request.body.clone());
                    effects += 1;
                }
                Some(original) => assert_eq!(original, &request.body),
            }
        }
        assert_eq!(effects, 1);
        assert_ne!(accepted["event-17"], b"conflicting callback bytes");
    }

    #[tokio::test]
    async fn dns_change_after_validation_cannot_change_the_pinned_snapshot() {
        struct MutableResolver(Arc<AtomicUsize>);
        #[async_trait::async_trait]
        impl CallbackResolver for MutableResolver {
            async fn resolve(
                &self,
                _: &str,
            ) -> Result<Vec<IpAddr>, smesh_a2a::push::PushSecurityError> {
                Ok(vec![
                    if self.0.load(Ordering::SeqCst) == 0 {
                        "8.8.8.8"
                    } else {
                        "1.1.1.1"
                    }
                    .parse()
                    .unwrap(),
                ])
            }
        }
        let fixture = Fixture::new();
        let pki = pki();
        let server = start_server(server_config(&pki.server, None), Reply::status(204)).await;
        let ca = fixture.write("server-ca.pem", pki.ca_pem.as_bytes());
        let (policy, _) = fixture.enrollment(server.address.port(), &ca, None);
        let state = Arc::new(AtomicUsize::new(0));
        let validated = Arc::new(tokio::sync::Barrier::new(2));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let a: IpAddr = "8.8.8.8".parse().unwrap();
        let b: IpAddr = "1.1.1.1".parse().unwrap();
        let transport = Arc::new(
            SecureCallbackTransport::new_test_mapped(
                Arc::new(MutableResolver(state.clone())),
                8,
                BTreeMap::from([
                    (a, "127.0.0.1".parse().unwrap()),
                    (b, "127.0.0.1".parse().unwrap()),
                ]),
                Some((validated.clone(), release.clone())),
                true,
            )
            .unwrap(),
        );
        let policy = Arc::new(policy);
        let attempt = tokio::spawn({
            let transport = transport.clone();
            let policy = policy.clone();
            async move {
                transport
                    .send_enrollment(&policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                    .await
            }
        });
        validated.wait().await;
        state.store(1, Ordering::SeqCst);
        release.wait().await;
        assert_eq!(
            attempt.await.unwrap().unwrap().disposition(),
            DeliveryDisposition::Delivered
        );
        assert_eq!(
            transport.test_requested_pins(),
            [SocketAddr::new(a, server.address.port())]
        );
    }

    #[tokio::test]
    async fn empty_mixed_and_too_many_dns_snapshots_make_zero_connections() {
        let fixture = Fixture::new();
        let pki = pki();
        let server = start_server(server_config(&pki.server, None), Reply::status(204)).await;
        let ca = fixture.write("server-ca.pem", pki.ca_pem.as_bytes());
        let (policy, _) = fixture.enrollment(server.address.port(), &ca, None);
        for answers in [
            vec![],
            vec!["8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            vec!["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()],
        ] {
            let resolver = Arc::new(ScriptedResolver {
                answers: vec![answers],
                call: AtomicUsize::new(0),
            });
            let transport = SecureCallbackTransport::new_test_mapped(
                resolver,
                1,
                BTreeMap::from([("8.8.8.8".parse().unwrap(), "127.0.0.1".parse().unwrap())]),
                None,
                true,
            )
            .unwrap();
            assert_eq!(
                transport
                    .send_enrollment(&policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                    .await,
                Err(CallbackTransportError::DnsUnsafe)
            );
        }
        assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dns_unavailable_refused_reset_and_malformed_response_are_closed_categories() {
        struct Unavailable;
        #[async_trait::async_trait]
        impl CallbackResolver for Unavailable {
            async fn resolve(
                &self,
                _: &str,
            ) -> Result<Vec<IpAddr>, smesh_a2a::push::PushSecurityError> {
                Err(smesh_a2a::push::PushSecurityError::DnsUnavailable)
            }
        }
        let fixture = Fixture::new();
        let pki = pki();
        let ca = fixture.write("server-ca.pem", pki.ca_pem.as_bytes());

        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let (refused_policy, _) = fixture.enrollment(refused_port, &ca, None);
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let map = BTreeMap::from([(public, "127.0.0.1".parse().unwrap())]);
        let unavailable = SecureCallbackTransport::new_test_mapped(
            Arc::new(Unavailable),
            8,
            map.clone(),
            None,
            true,
        )
        .unwrap();
        assert_eq!(
            unavailable
                .send_enrollment(&refused_policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                .await,
            Err(CallbackTransportError::DnsUnavailable)
        );
        let refused = SecureCallbackTransport::new_test_mapped(
            Arc::new(ScriptedResolver {
                answers: vec![vec![public]],
                call: AtomicUsize::new(0),
            }),
            8,
            map.clone(),
            None,
            true,
        )
        .unwrap();
        assert_eq!(
            refused
                .send_enrollment(&refused_policy.enrollments()[0], "event", 1, 1, BODY, 4096)
                .await,
            Err(CallbackTransportError::Connect)
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let malformed_port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(Arc::new(server_config(&pki.server, None)));
        let raw = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut request = vec![0_u8; 4096];
            let _ = tls.read(&mut request).await.unwrap();
            tls.write_all(b"not-http\r\n\r\n").await.unwrap();
        });
        let (malformed_policy, _) = fixture.enrollment(malformed_port, &ca, None);
        let malformed = SecureCallbackTransport::new_test_mapped(
            Arc::new(ScriptedResolver {
                answers: vec![vec![public]],
                call: AtomicUsize::new(0),
            }),
            8,
            map,
            None,
            true,
        )
        .unwrap();
        assert_eq!(
            malformed
                .send_enrollment(
                    &malformed_policy.enrollments()[0],
                    "event",
                    1,
                    1,
                    BODY,
                    4096
                )
                .await,
            Err(CallbackTransportError::Reset)
        );
        raw.await.unwrap();
    }

    #[tokio::test]
    async fn ambient_proxy_variables_never_receive_callback_traffic() {
        const CHILD_MARKER: &str = "SMESH_PUSH_PROXY_MATRIX_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let fixture = Fixture::new();
            let pki = pki();
            let server = start_server(server_config(&pki.server, None), Reply::status(204)).await;
            assert_eq!(
                send(&fixture, &pki, &server, None, 4096)
                    .await
                    .unwrap()
                    .disposition(),
                DeliveryDisposition::Delivered
            );
            return;
        }
        let canary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        canary.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", canary.local_addr().unwrap());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("wire_matrix::ambient_proxy_variables_never_receive_callback_traffic")
            .arg("--test-threads=1")
            .env(CHILD_MARKER, "1")
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("ALL_PROXY", &proxy)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(
            matches!(canary.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

const POLICY: &str = r#"
schema = "smesh-push/1"
enabled = true
policy_id = "production-callbacks"
policy_revision = 7
policy_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
max_pending = 10000
max_configs_per_task = 4
max_configs_per_tenant = 1000
worker_count = 4
claim_batch = 32
claim_lease_ms = 30000
dns_timeout_ms = 1000
max_dns_answers = 8
connect_timeout_ms = 2000
request_timeout_ms = 5000
max_response_bytes = 4096
max_attempts = 6
base_retry_ms = 500
max_retry_ms = 300000
max_delivery_age_ms = 86400000

[[enrollments]]
tenant = "tenant-a"
endpoint_id = "billing-events"
url = "https://callbacks.example.com:443/a2a/task"
event = "terminal"
auth = "hmac-sha256"
key_generation = "generation-7"
secret_file = "/run/secrets/billing-events.key"
"#;
