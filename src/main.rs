use std::net::SocketAddr;
use std::sync::Arc;

use smesh_a2a::{
    CorrelatingRuntimeProcessor, GatewayConfig, GatewayMode, LoopbackDispatcher,
    RuntimeAdmissionProcessor, RuntimeEventCapture, RuntimeModeConfig, RuntimeWorker, build_router,
    build_router_with_trace,
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

#[allow(clippy::too_many_lines)] // Keep runtime startup, trace supervision, and shutdown ownership linear.
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
    let capture = Arc::new(RuntimeEventCapture::new(65_536, 1_024));
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
                        if let Err(error) = event_capture.record(event).await {
                            tracing::error!(%error, "required SMESH runtime trace capture failed");
                            return;
                        }
                    }
                    return;
                }
            };
            let Some(event) = event else {
                return;
            };
            if let Err(error) = event_capture.record(event).await {
                tracing::error!(%error, "required SMESH runtime trace capture failed");
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
    let app = build_router_with_trace(
        GatewayConfig::new(&public_base_url, &gateway_node_id),
        dispatcher,
        Arc::clone(&capture),
    );
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        %public_base_url,
        %mesh_listen,
        mode = "runtime",
        "SMESH A2A gateway listening"
    );
    let mut event_drain_finished = false;
    let serve_result = tokio::select! {
        result = axum::serve(listener, app) => result,
        signal = tokio::signal::ctrl_c() => signal.map_err(std::io::Error::other),
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
