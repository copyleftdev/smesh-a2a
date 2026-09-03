use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use a2a::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill,
    TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC,
};

pub const LIFELINE_TOPOLOGY_SCHEMA_VERSION: &str = "1.0.0";
pub const LIFELINE_DISCOVERY_DISCLAIMER: &str = "Fictional simulation capability metadata only; not authorization, medical advice, clinical validation, or evidence of trust.";
const APPROVED_PUBLIC_PROFILES: &str = include_str!("../deploy/lifeline-topology.json");

#[derive(Debug, Error)]
pub enum LifelineTopologyError {
    #[error("topology JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("topology invariant failed: {0}")]
    Invariant(String),
    #[error("topology listener {listener_id} failed: {source}")]
    Listener {
        listener_id: String,
        #[source]
        source: std::io::Error,
    },
    #[error("topology server failed: {0}")]
    Server(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifelineEndpoint {
    gateway_id: String,
    listener_id: String,
    base_url: String,
    fallback: bool,
}

pub struct RunningLifelineTopology {
    endpoints: Vec<LifelineEndpoint>,
    cards: Vec<(String, AgentCard)>,
    cancellation: tokio_util::sync::CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
}

struct OwnedServerTasks {
    tasks: std::collections::VecDeque<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
}

impl OwnedServerTasks {
    fn new(tasks: Vec<tokio::task::JoinHandle<Result<(), std::io::Error>>>) -> Self {
        Self {
            tasks: tasks.into(),
        }
    }

    async fn abort_and_join(mut self) {
        for task in &self.tasks {
            task.abort();
        }
        while let Some(task) = self.tasks.pop_front() {
            let _ = task.await;
        }
    }
}

impl Drop for OwnedServerTasks {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineTopologyManifest {
    schema_version: String,
    fictional: bool,
    disclaimer: String,
    gateways: Vec<LifelineGateway>,
    logistics: LifelineLogisticsRoute,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineGateway {
    id: String,
    organization: String,
    agent_name: String,
    description: String,
    geography: LifelineGeography,
    authentication: LifelineAuthentication,
    listeners: Vec<LifelineListener>,
    skill: LifelineSkill,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineGeography {
    city: String,
    country: String,
    latitude: f64,
    longitude: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifelineAuthentication {
    LocalNone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineListener {
    id: String,
    bind: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineSkill {
    id: String,
    name: String,
    description: String,
    tags: Vec<String>,
    example: String,
    input_modes: Vec<String>,
    output_modes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifelineLogisticsRoute {
    primary_gateway_id: String,
    fallback_gateway_id: String,
}

impl LifelineTopologyManifest {
    /// Parses and validates the closed local LIFELINE deployment manifest.
    ///
    /// # Errors
    /// Returns an error when JSON decoding or a topology invariant fails.
    pub fn from_json(input: &str) -> Result<Self, LifelineTopologyError> {
        if input.len() > 64 * 1024 {
            return Err(LifelineTopologyError::Invariant(
                "manifest exceeds 64 KiB".to_owned(),
            ));
        }
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), LifelineTopologyError> {
        require(
            self.schema_version == LIFELINE_TOPOLOGY_SCHEMA_VERSION,
            "unsupported schemaVersion",
        )?;
        require(self.fictional, "topology must be explicitly fictional")?;
        require(
            self.disclaimer == LIFELINE_DISCOVERY_DISCLAIMER,
            "disclaimer must match the reviewed discovery boundary",
        )?;
        require(
            self.gateways.len() == 6,
            "exactly six gateways are required",
        )?;

        let mut gateway_ids = HashSet::new();
        let mut organizations = HashSet::new();
        let mut listener_ids = HashSet::new();
        for gateway in &self.gateways {
            require_identifier(&gateway.id, "gateway id")?;
            require(
                gateway_ids.insert(gateway.id.as_str()),
                "gateway ids must be unique",
            )?;
            organizations.insert(gateway.organization.as_str());
            require_text(&gateway.organization, 128, "organization")?;
            require_text(&gateway.agent_name, 128, "agent name")?;
            require_text(&gateway.description, 512, "agent description")?;
            require_text(&gateway.geography.city, 128, "city")?;
            require_text(&gateway.geography.country, 128, "country")?;
            require(
                (-90.0..=90.0).contains(&gateway.geography.latitude),
                "latitude is out of range",
            )?;
            require(
                (-180.0..=180.0).contains(&gateway.geography.longitude),
                "longitude is out of range",
            )?;
            require(
                gateway.listeners.len() == 1,
                "every independently addressed gateway requires one listener",
            )?;
            for listener in &gateway.listeners {
                require_identifier(&listener.id, "listener id")?;
                require(
                    listener_ids.insert(listener.id.as_str()),
                    "listener ids must be unique",
                )?;
                require(
                    listener.bind.ip().is_loopback(),
                    "local topology listeners must bind loopback",
                )?;
            }
            gateway.skill.validate()?;
        }
        require(
            self.listener_count() == 6,
            "exactly six listener addresses are required",
        )?;
        require(
            organizations.len() == 5,
            "six remote gateways must represent five organizations",
        )?;

        let primary = self
            .gateways
            .iter()
            .find(|gateway| gateway.id == self.logistics.primary_gateway_id)
            .ok_or_else(|| invariant("primary logistics gateway does not exist"))?;
        let fallback = self
            .gateways
            .iter()
            .find(|gateway| gateway.id == self.logistics.fallback_gateway_id)
            .ok_or_else(|| invariant("fallback logistics gateway does not exist"))?;
        require(
            primary.id != fallback.id,
            "logistics primary and fallback gateway ids must differ",
        )?;
        require(
            primary.organization == fallback.organization,
            "logistics primary and fallback must share one organization",
        )?;
        require(
            primary.skill == fallback.skill,
            "logistics primary and fallback must expose the same bounded skill",
        )?;
        self.validate_approved_public_profiles()?;
        Ok(())
    }

    fn validate_approved_public_profiles(&self) -> Result<(), LifelineTopologyError> {
        let approved: Self = serde_json::from_str(APPROVED_PUBLIC_PROFILES)
            .map_err(|_| invariant("built-in public profile catalog is invalid"))?;
        let mut candidate = self.clone();
        for (candidate_gateway, approved_gateway) in
            candidate.gateways.iter_mut().zip(&approved.gateways)
        {
            for (candidate_listener, approved_listener) in candidate_gateway
                .listeners
                .iter_mut()
                .zip(&approved_gateway.listeners)
            {
                candidate_listener
                    .bind
                    .set_port(approved_listener.bind.port());
            }
        }
        require(
            candidate == approved,
            "public profiles must match the reviewed LIFELINE catalog",
        )
    }

    #[must_use]
    pub fn gateways(&self) -> &[LifelineGateway] {
        &self.gateways
    }

    #[must_use]
    pub fn listener_count(&self) -> usize {
        self.gateways
            .iter()
            .map(|gateway| gateway.listeners.len())
            .sum()
    }

    #[must_use]
    pub fn is_fictional(&self) -> bool {
        self.fictional
    }

    #[must_use]
    pub fn logistics(&self) -> &LifelineLogisticsRoute {
        &self.logistics
    }

    /// Builds the A2A v1 public discovery card for one logical gateway.
    ///
    /// # Errors
    /// Returns an error when the requested gateway is not in the closed manifest.
    pub fn agent_card(&self, gateway_id: &str) -> Result<AgentCard, LifelineTopologyError> {
        let gateway = self
            .gateways
            .iter()
            .find(|gateway| gateway.id == gateway_id)
            .ok_or_else(|| invariant("gateway does not exist"))?;
        let mut supported_interfaces = Vec::with_capacity(gateway.listeners.len() * 2);
        for listener in &gateway.listeners {
            let base = format!("http://{}", listener.bind);
            supported_interfaces.push(AgentInterface::new(
                format!("{base}/jsonrpc"),
                TRANSPORT_PROTOCOL_JSONRPC,
            ));
            supported_interfaces.push(AgentInterface::new(
                format!("{base}/rest"),
                TRANSPORT_PROTOCOL_HTTP_JSON,
            ));
        }
        let skill = &gateway.skill;
        Ok(AgentCard {
            name: gateway.agent_name.clone(),
            description: format!("{} {}", gateway.description, self.disclaimer),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_interfaces,
            capabilities: AgentCapabilities {
                streaming: Some(true),
                push_notifications: Some(false),
                extensions: None,
                extended_agent_card: Some(false),
            },
            default_input_modes: skill.input_modes.clone(),
            default_output_modes: skill.output_modes.clone(),
            skills: vec![AgentSkill {
                id: skill.id.clone(),
                name: skill.name.clone(),
                description: skill.description.clone(),
                tags: skill.tags.clone(),
                examples: Some(vec![skill.example.clone()]),
                input_modes: Some(skill.input_modes.clone()),
                output_modes: Some(skill.output_modes.clone()),
                security_requirements: None,
            }],
            provider: Some(AgentProvider {
                organization: gateway.organization.clone(),
                url: format!(
                    "https://{}.lifeline.invalid",
                    organization_slug(&gateway.organization)
                ),
            }),
            documentation_url: None,
            icon_url: None,
            security_schemes: None,
            security_requirements: None,
            signatures: None,
        })
    }

    #[doc(hidden)]
    #[must_use]
    pub fn with_ephemeral_loopback_ports(mut self) -> Self {
        for gateway in &mut self.gateways {
            for listener in &mut gateway.listeners {
                listener.bind.set_port(0);
            }
        }
        self
    }

    /// Binds every declared listener before publishing any topology server.
    ///
    /// # Errors
    /// Returns an error if validation, binding, card construction, or server
    /// ownership setup fails. Partially bound listeners are dropped on error.
    pub async fn launch(self) -> Result<RunningLifelineTopology, LifelineTopologyError> {
        self.launch_with_dispatcher(crate::LoopbackDispatcher).await
    }

    #[doc(hidden)]
    pub async fn launch_with_dispatcher<D>(
        self,
        dispatcher: D,
    ) -> Result<RunningLifelineTopology, LifelineTopologyError>
    where
        D: crate::MeshDispatcher + Clone,
    {
        let dispatchers = self
            .gateways
            .iter()
            .map(|gateway| (gateway.id.clone(), dispatcher.clone()))
            .collect();
        self.launch_with_dispatchers(dispatchers).await
    }

    pub(crate) async fn launch_with_dispatchers<D>(
        mut self,
        dispatchers: HashMap<String, D>,
    ) -> Result<RunningLifelineTopology, LifelineTopologyError>
    where
        D: crate::MeshDispatcher + Clone,
    {
        let expected: HashSet<_> = self
            .gateways
            .iter()
            .map(|gateway| gateway.id.as_str())
            .collect();
        let actual: HashSet<_> = dispatchers.keys().map(String::as_str).collect();
        require(
            actual == expected,
            "dispatcher map must exactly match topology gateways",
        )?;
        self.validate()?;
        let mut listeners = Vec::with_capacity(self.listener_count());
        for (gateway_index, gateway) in self.gateways.iter_mut().enumerate() {
            for (listener_index, listener) in gateway.listeners.iter_mut().enumerate() {
                let socket =
                    tokio::net::TcpListener::bind(listener.bind)
                        .await
                        .map_err(|source| LifelineTopologyError::Listener {
                            listener_id: listener.id.clone(),
                            source,
                        })?;
                listener.bind =
                    socket
                        .local_addr()
                        .map_err(|source| LifelineTopologyError::Listener {
                            listener_id: listener.id.clone(),
                            source,
                        })?;
                listeners.push((gateway_index, listener_index, socket));
            }
        }

        let mut cards = Vec::with_capacity(self.gateways.len());
        let mut routers = Vec::with_capacity(self.gateways.len());
        for gateway in &self.gateways {
            let card = self.agent_card(&gateway.id)?;
            let primary = gateway
                .listeners
                .first()
                .ok_or_else(|| invariant("gateway has no primary listener"))?;
            let config =
                crate::GatewayConfig::new(format!("http://{}", primary.bind), gateway.id.clone());
            let dispatcher = dispatchers
                .get(&gateway.id)
                .ok_or_else(|| invariant("gateway dispatcher is missing"))?
                .clone();
            routers.push(crate::server::build_router_with_agent_card(
                config,
                dispatcher,
                card.clone(),
            ));
            cards.push((gateway.id.clone(), card));
        }

        let cancellation = tokio_util::sync::CancellationToken::new();
        let mut endpoints = Vec::with_capacity(listeners.len());
        let mut tasks = Vec::with_capacity(listeners.len());
        for (gateway_index, listener_index, socket) in listeners {
            let gateway = &self.gateways[gateway_index];
            let listener = &gateway.listeners[listener_index];
            let fallback = gateway.id == self.logistics.fallback_gateway_id;
            endpoints.push(LifelineEndpoint {
                gateway_id: gateway.id.clone(),
                listener_id: listener.id.clone(),
                base_url: format!("http://{}", listener.bind),
                fallback,
            });
            let router = routers[gateway_index].clone();
            let stop = cancellation.clone();
            tasks.push(tokio::spawn(async move {
                axum::serve(socket, router)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await
            }));
        }
        Ok(RunningLifelineTopology {
            endpoints,
            cards,
            cancellation,
            tasks,
        })
    }
}

impl LifelineEndpoint {
    #[must_use]
    pub fn gateway_id(&self) -> &str {
        &self.gateway_id
    }

    #[must_use]
    pub fn listener_id(&self) -> &str {
        &self.listener_id
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn is_fallback(&self) -> bool {
        self.fallback
    }
}

impl RunningLifelineTopology {
    #[must_use]
    pub fn endpoints(&self) -> &[LifelineEndpoint] {
        &self.endpoints
    }

    #[must_use]
    pub fn card(&self, gateway_id: &str) -> Option<&AgentCard> {
        self.cards
            .iter()
            .find_map(|(id, card)| (id == gateway_id).then_some(card))
    }

    /// Gracefully stops and joins every listener.
    ///
    /// # Errors
    /// Returns an error if a server fails, panics, or misses the shutdown deadline.
    pub async fn shutdown(mut self) -> Result<(), LifelineTopologyError> {
        self.cancellation.cancel();
        let mut tasks = OwnedServerTasks::new(std::mem::take(&mut self.tasks));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while let Some(task) = tasks.tasks.front_mut() {
            let outcome = tokio::time::timeout_at(deadline, task).await;
            match outcome {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    tasks.tasks.pop_front();
                    tasks.abort_and_join().await;
                    return Err(LifelineTopologyError::Server(error.to_string()));
                }
                Ok(Err(error)) => {
                    tasks.tasks.pop_front();
                    tasks.abort_and_join().await;
                    return Err(LifelineTopologyError::Server(error.to_string()));
                }
                Err(_) => {
                    tasks.abort_and_join().await;
                    return Err(LifelineTopologyError::Server(
                        "shutdown deadline exceeded".to_owned(),
                    ));
                }
            }
            tasks.tasks.pop_front();
        }
        Ok(())
    }
}

impl Drop for RunningLifelineTopology {
    fn drop(&mut self) {
        self.cancellation.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl LifelineGateway {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl LifelineSkill {
    fn validate(&self) -> Result<(), LifelineTopologyError> {
        require_identifier(&self.id, "skill id")?;
        require_text(&self.name, 128, "skill name")?;
        require_text(&self.description, 512, "skill description")?;
        require(!self.tags.is_empty(), "skill tags must not be empty")?;
        require_text(&self.example, 512, "skill example")?;
        require(
            !self.input_modes.is_empty(),
            "input modes must not be empty",
        )?;
        require(
            !self.output_modes.is_empty(),
            "output modes must not be empty",
        )?;
        Ok(())
    }
}

impl LifelineLogisticsRoute {
    #[must_use]
    pub fn primary_gateway_id(&self) -> &str {
        &self.primary_gateway_id
    }

    #[must_use]
    pub fn fallback_gateway_id(&self) -> &str {
        &self.fallback_gateway_id
    }
}

fn require(condition: bool, message: &str) -> Result<(), LifelineTopologyError> {
    if condition {
        Ok(())
    } else {
        Err(invariant(message))
    }
}

fn require_identifier(value: &str, label: &str) -> Result<(), LifelineTopologyError> {
    require_text(value, 128, label)?;
    require(
        value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        }),
        &format!("{label} must be a lowercase ASCII identifier"),
    )
}

fn require_text(value: &str, max: usize, label: &str) -> Result<(), LifelineTopologyError> {
    require(
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control),
        &format!("{label} violates bounds"),
    )
}

fn invariant(message: impl Into<String>) -> LifelineTopologyError {
    LifelineTopologyError::Invariant(message.into())
}

fn organization_slug(organization: &str) -> String {
    let mut slug = String::with_capacity(organization.len());
    for character in organization.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{LifelineTopologyError, RunningLifelineTopology};

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn canceled_shutdown_future_aborts_owned_server_tasks() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let started = Arc::new(tokio::sync::Notify::new());
        let task_started = Arc::clone(&started);
        let task = tokio::spawn(async move {
            let _dropped = Dropped(task_dropped);
            task_started.notify_one();
            std::future::pending::<Result<(), std::io::Error>>().await
        });
        started.notified().await;
        let topology = RunningLifelineTopology {
            endpoints: Vec::new(),
            cards: Vec::new(),
            cancellation: tokio_util::sync::CancellationToken::new(),
            tasks: vec![task],
        };

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), topology.shutdown())
                .await
                .is_err()
        );
        tokio::task::yield_now().await;

        assert!(
            dropped.load(Ordering::SeqCst),
            "canceling shutdown detached its owned server task"
        );
    }

    #[tokio::test]
    async fn shutdown_error_aborts_and_reaps_remaining_server_tasks() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let started = Arc::new(tokio::sync::Notify::new());
        let task_started = Arc::clone(&started);
        let failed =
            tokio::spawn(async { Err(std::io::Error::other("injected listener failure")) });
        let pending = tokio::spawn(async move {
            let _dropped = Dropped(task_dropped);
            task_started.notify_one();
            std::future::pending::<Result<(), std::io::Error>>().await
        });
        started.notified().await;
        let topology = RunningLifelineTopology {
            endpoints: Vec::new(),
            cards: Vec::new(),
            cancellation: tokio_util::sync::CancellationToken::new(),
            tasks: vec![failed, pending],
        };

        let error = topology.shutdown().await.unwrap_err();

        assert!(
            matches!(error, LifelineTopologyError::Server(message) if message == "injected listener failure")
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "task after failed listener was detached instead of reaped"
        );
    }

    #[tokio::test]
    async fn shutdown_timeout_aborts_and_reaps_every_server_task() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let started = Arc::new(tokio::sync::Notify::new());
        let task_started = Arc::clone(&started);
        let task = tokio::spawn(async move {
            let _dropped = Dropped(task_dropped);
            task_started.notify_one();
            std::future::pending::<Result<(), std::io::Error>>().await
        });
        started.notified().await;
        let topology = RunningLifelineTopology {
            endpoints: Vec::new(),
            cards: Vec::new(),
            cancellation: tokio_util::sync::CancellationToken::new(),
            tasks: vec![task],
        };

        let error = topology.shutdown().await.unwrap_err();

        assert!(
            matches!(error, LifelineTopologyError::Server(message) if message == "shutdown deadline exceeded")
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "timed-out task was detached instead of reaped"
        );
    }
}
