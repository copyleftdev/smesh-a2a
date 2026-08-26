use std::net::SocketAddr;
use std::sync::Arc;

use smesh_a2a::{
    GatewayConfig, GatewayMode, LoopbackDispatcher, RuntimeAdmissionProcessor, RuntimeModeConfig,
    RuntimeWorker, build_router,
};
use smesh_core::{Network, Node};
use smesh_runtime::{MeshConfig, RuntimeConfig, SmeshRuntime};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let bind: SocketAddr = std::env::var("SMESH_A2A_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()?;
    let public_base_url =
        std::env::var("SMESH_A2A_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind}"));
    let allow_public = std::env::var("SMESH_A2A_UNSAFE_PUBLIC").as_deref() == Ok("1");
    if !bind.ip().is_loopback() && !allow_public {
        return Err(
            "refusing non-loopback bind; set SMESH_A2A_UNSAFE_PUBLIC=1 after adding authentication and TLS"
                .into(),
        );
    }
    let gateway_node_id =
        std::env::var("SMESH_A2A_NODE_ID").unwrap_or_else(|_| "smesh-a2a-gateway".to_owned());
    let mode = std::env::var("SMESH_A2A_MODE").ok();
    let mesh_bind = std::env::var("SMESH_A2A_MESH_BIND").ok();
    let bootstrap = std::env::var("SMESH_A2A_BOOTSTRAP").ok();
    let mode = GatewayMode::parse(mode.as_deref(), mesh_bind.as_deref(), bootstrap.as_deref())?;

    match mode {
        GatewayMode::Loopback => {
            let app = build_router(
                GatewayConfig::new(&public_base_url, &gateway_node_id),
                LoopbackDispatcher,
            );
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!(%bind, %public_base_url, mode = "loopback", "SMESH A2A gateway listening");
            axum::serve(listener, app).await?;
        }
        GatewayMode::Runtime(runtime_config) => {
            run_runtime_gateway(bind, public_base_url, gateway_node_id, runtime_config).await?;
        }
    }
    Ok(())
}

async fn run_runtime_gateway(
    bind: SocketAddr,
    public_base_url: String,
    gateway_node_id: String,
    runtime_config: RuntimeModeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut network = Network::new();
    network.add_node(Node::named(&gateway_node_id));
    let mut runtime_value = SmeshRuntime::with_network(network, RuntimeConfig::default());
    let mut runtime_events = runtime_value
        .take_events()
        .ok_or("SMESH runtime event receiver was already taken")?;
    let runtime = Arc::new(runtime_value);
    let mut runtime_loop = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.run().await })
    };
    let event_drain = tokio::spawn(async move {
        while let Some(event) = runtime_events.recv().await {
            tracing::debug!(?event, "SMESH runtime event");
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
        RuntimeAdmissionProcessor,
        64,
    )
    .await?;
    let app = build_router(
        GatewayConfig::new(&public_base_url, &gateway_node_id),
        dispatcher,
    );
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        %public_base_url,
        %mesh_listen,
        mode = "runtime",
        "SMESH A2A gateway listening"
    );
    let serve_result = axum::serve(listener, app).await;
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
    event_drain.abort();
    let _ = event_drain.await;
    worker_result?;
    serve_result?;
    Ok(())
}
