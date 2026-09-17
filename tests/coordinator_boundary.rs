#[test]
fn driver_uses_authority_owned_coordinator_and_keeps_completed_dispatch_result() {
    let driver = include_str!("../src/outbox_driver.rs");
    assert!(driver.contains("coordinator: Arc<DurableCoordinator>"));
    assert!(!driver.contains("let dispatch = if shutdown_requested || sender_renewal_failed"));
}

#[test]
fn production_builder_accepts_runtime_adapter_without_loopback_fallback() {
    let runtime = include_str!("../src/durable_runtime.rs");
    let coordinator = include_str!("../src/durable_dispatch.rs");
    let driver = include_str!("../src/outbox_driver.rs");
    let server = include_str!("../src/server.rs");
    assert!(!runtime.contains("permits_loopback_development_context"));
    assert!(!coordinator.contains("self.adapter.permits_loopback_development_context"));
    assert!(coordinator.contains("enum DurableCoordinatorMode"));
    assert!(driver.contains("DurableCoordinatorMode::Runtime(adapter)"));
    assert!(driver.contains("DurableCoordinatorMode::Loopback(endpoint)"));
    assert!(server.contains("build_authorized_postgres_runtime_gateway"));
    assert!(server.contains("adapter: Arc<dyn DurableRuntimeAdapter>"));
    let builder = &server[server
        .find("pub fn build_authorized_postgres_runtime_gateway")
        .expect("production runtime builder")..];
    let builder = &builder[..builder.find("\n}\n").expect("builder end") + 3];
    assert!(!builder.contains("DurableLoopbackEndpoint"));
}
