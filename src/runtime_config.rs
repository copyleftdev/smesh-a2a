use std::net::SocketAddr;

use thiserror::Error;

/// Runtime selection for the standalone gateway binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayMode {
    Loopback,
    Runtime(RuntimeModeConfig),
}

/// Network configuration required by real runtime mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeModeConfig {
    pub mesh_bind: SocketAddr,
    pub bootstrap: Vec<SocketAddr>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatewayModeError {
    #[error("unsupported SMESH_A2A_MODE: {0}")]
    UnsupportedMode(String),
    #[error("invalid SMESH_A2A_MESH_BIND address: {0}")]
    InvalidMeshBind(String),
    #[error("invalid SMESH_A2A_BOOTSTRAP address: {0}")]
    InvalidBootstrap(String),
    #[error("SMESH_A2A_MESH_BIND must be loopback for this milestone: {0}")]
    NonLoopbackMeshBind(String),
    #[error("SMESH_A2A_BOOTSTRAP peer must be loopback for this milestone: {0}")]
    NonLoopbackBootstrap(String),
}

impl GatewayMode {
    /// Parse standalone mode values without reading process-global environment state.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported modes or malformed runtime socket addresses.
    pub fn parse(
        mode: Option<&str>,
        mesh_bind: Option<&str>,
        bootstrap: Option<&str>,
    ) -> Result<Self, GatewayModeError> {
        match mode.unwrap_or("loopback") {
            "loopback" => Ok(Self::Loopback),
            "runtime" => {
                let mesh_bind_value = mesh_bind.unwrap_or("127.0.0.1:0");
                let mesh_bind: SocketAddr = mesh_bind_value
                    .parse()
                    .map_err(|_| GatewayModeError::InvalidMeshBind(mesh_bind_value.to_owned()))?;
                if !mesh_bind.ip().is_loopback() {
                    return Err(GatewayModeError::NonLoopbackMeshBind(
                        mesh_bind_value.to_owned(),
                    ));
                }
                let bootstrap = bootstrap
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .map(|address| {
                                address.parse::<SocketAddr>().map_err(|_| {
                                    GatewayModeError::InvalidBootstrap(address.to_owned())
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                if let Some(address) = bootstrap.iter().find(|address| !address.ip().is_loopback())
                {
                    return Err(GatewayModeError::NonLoopbackBootstrap(address.to_string()));
                }
                Ok(Self::Runtime(RuntimeModeConfig {
                    mesh_bind,
                    bootstrap,
                }))
            }
            other => Err(GatewayModeError::UnsupportedMode(other.to_owned())),
        }
    }
}
