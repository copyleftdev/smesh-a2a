//! A2A v1 interoperability gateway for SMESH swarms.

mod bridge;
mod card;
mod channel;
mod executor;
mod guard;
mod input;
mod lifeline;
mod loopback;
mod server;
mod store;

pub use bridge::{DispatchError, MeshDispatcher, MeshEvent, MeshRequest};
pub use card::build_agent_card;
pub use channel::{ChannelDispatcher, DispatchCommand};
pub use executor::{ExecutionLimits, SmeshExecutor};
pub use input::{InputError, InputLimits, extract_text};
pub use lifeline::{
    TraceError, TraceEvent, generate_lifeline_trace, verify_trace, write_lifeline_trace,
};
pub use loopback::LoopbackDispatcher;
pub use server::{GatewayConfig, build_router, build_router_with_store};
pub use store::BoundedTaskStore;
