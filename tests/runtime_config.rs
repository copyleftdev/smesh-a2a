use smesh_a2a::{GatewayMode, RuntimeModeConfig};

#[test]
fn gateway_mode_is_explicit_and_runtime_addresses_fail_closed() {
    assert_eq!(
        GatewayMode::parse(None, None, None).unwrap(),
        GatewayMode::Loopback
    );
    assert_eq!(
        GatewayMode::parse(
            Some("runtime"),
            Some("127.0.0.1:0"),
            Some("127.0.0.1:4101,127.0.0.1:4102"),
        )
        .unwrap(),
        GatewayMode::Runtime(RuntimeModeConfig {
            mesh_bind: "127.0.0.1:0".parse().unwrap(),
            bootstrap: vec![
                "127.0.0.1:4101".parse().unwrap(),
                "127.0.0.1:4102".parse().unwrap(),
            ],
        })
    );
    assert!(GatewayMode::parse(Some("unknown"), None, None).is_err());
    assert!(GatewayMode::parse(Some("runtime"), Some("not-an-address"), None).is_err());
    assert!(GatewayMode::parse(Some("runtime"), None, Some("bad-peer")).is_err());
    assert!(GatewayMode::parse(Some("runtime"), Some("0.0.0.0:4100"), None).is_err());
    assert!(GatewayMode::parse(Some("runtime"), None, Some("192.0.2.1:4100")).is_err());
}
