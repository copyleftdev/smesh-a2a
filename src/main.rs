use std::net::SocketAddr;

use smesh_a2a::{GatewayConfig, LoopbackDispatcher, build_router};

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

    let app = build_router(
        GatewayConfig::new(&public_base_url, gateway_node_id),
        LoopbackDispatcher,
    );
    let listener = tokio::net::TcpListener::bind(bind).await?;

    tracing::info!(%bind, %public_base_url, "SMESH A2A gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}
