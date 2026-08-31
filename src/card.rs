use a2a::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill,
    HttpAuthSecurityScheme, MutualTlsSecurityScheme, SecurityScheme, TRANSPORT_PROTOCOL_HTTP_JSON,
    TRANSPORT_PROTOCOL_JSONRPC,
};

use a2a_server::AgentCardProducer;

/// Dynamic card producer backed by the gateway generation's sticky readiness.
pub struct LiveAgentCard {
    base: AgentCard,
    readiness: std::sync::Arc<crate::push::PushReadiness>,
}

impl LiveAgentCard {
    #[must_use]
    pub fn new(base: AgentCard, readiness: std::sync::Arc<crate::push::PushReadiness>) -> Self {
        Self { base, readiness }
    }
}

impl AgentCardProducer for LiveAgentCard {
    fn card(&self) -> AgentCard {
        let mut card = self.base.clone();
        let ready = self.readiness.is_ready();
        card.capabilities.push_notifications = Some(ready);
        card.capabilities.extended_agent_card = Some(false);
        card
    }
}

/// Build the public A2A v1 card for a SMESH swarm gateway.
#[must_use]
pub fn build_agent_card(base_url: &str) -> AgentCard {
    let base = base_url.trim_end_matches('/');

    AgentCard {
        name: "SMESH Swarm".to_owned(),
        description: "A decentralized, trust-weighted agent swarm exposed through A2A v1."
            .to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        supported_interfaces: vec![
            AgentInterface::new(format!("{base}/jsonrpc"), TRANSPORT_PROTOCOL_JSONRPC),
            AgentInterface::new(format!("{base}/rest"), TRANSPORT_PROTOCOL_HTTP_JSON),
        ],
        capabilities: AgentCapabilities {
            streaming: Some(true),
            push_notifications: Some(false),
            extensions: None,
            extended_agent_card: Some(false),
        },
        default_input_modes: vec!["text/plain".to_owned()],
        default_output_modes: vec!["text/plain".to_owned(), "application/json".to_owned()],
        skills: vec![AgentSkill {
            id: "smesh.collaborative-task".to_owned(),
            name: "Collaborative swarm task".to_owned(),
            description:
                "Coordinates specialist agents through SMESH and returns an accepted artifact."
                    .to_owned(),
            tags: vec![
                "multi-agent".to_owned(),
                "coordination".to_owned(),
                "review".to_owned(),
                "testing".to_owned(),
            ],
            examples: Some(vec![
                "Review this Rust repository for correctness, security, and performance."
                    .to_owned(),
            ]),
            input_modes: Some(vec!["text/plain".to_owned()]),
            output_modes: Some(vec!["text/plain".to_owned(), "application/json".to_owned()]),
            security_requirements: None,
        }],
        provider: Some(AgentProvider {
            organization: "copyleftdev".to_owned(),
            url: "https://github.com/copyleftdev/smesh-a2a".to_owned(),
        }),
        documentation_url: Some("https://github.com/copyleftdev/smesh-a2a".to_owned()),
        icon_url: None,
        security_schemes: None,
        security_requirements: None,
        signatures: None,
    }
}

/// Build a card whose push capability reflects the complete live callback
/// subsystem readiness snapshot.
#[must_use]
pub fn build_agent_card_with_push_readiness(
    base_url: &str,
    readiness: &crate::push::PushReadiness,
) -> AgentCard {
    let mut card = build_agent_card(base_url);
    let ready = readiness.is_ready();
    card.capabilities.push_notifications = Some(ready);
    card.capabilities.extended_agent_card = Some(false);
    card
}

/// Build a public discovery card whose advertised interfaces require OIDC bearer JWTs.
#[must_use]
pub fn build_authenticated_agent_card(base_url: &str) -> AgentCard {
    build_secured_agent_card(base_url, true, false)
}

/// Advertise exactly the credential alternatives accepted at the HTTP boundary.
#[must_use]
pub fn build_secured_agent_card(base_url: &str, oidc: bool, mutual_tls: bool) -> AgentCard {
    build_secured_agent_card_with_policy(base_url, oidc, mutual_tls, false)
}

/// Advertise exact credential alternatives, including handshake-required mTLS.
#[must_use]
pub fn build_secured_agent_card_with_policy(
    base_url: &str,
    oidc: bool,
    mutual_tls: bool,
    mutual_tls_required: bool,
) -> AgentCard {
    let mut card = build_agent_card(base_url);
    let mut schemes = std::collections::HashMap::new();
    let mut requirements = Vec::new();
    if oidc {
        let name = "oidc_bearer".to_owned();
        schemes.insert(
            name.clone(),
            SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
                scheme: "bearer".to_owned(),
                description: Some("OIDC RFC 9068 JWT access token".to_owned()),
                bearer_format: Some("JWT".to_owned()),
            }),
        );
        if !mutual_tls_required {
            requirements.push(std::collections::HashMap::from([(name, Vec::new())]));
        }
    }
    if mutual_tls {
        let name = "mutual_tls".to_owned();
        schemes.insert(
            name.clone(),
            SecurityScheme::MutualTls(MutualTlsSecurityScheme {
                description: Some(
                    "Verified client certificate mapped by SHA-256 leaf fingerprint".to_owned(),
                ),
            }),
        );
        requirements.push(std::collections::HashMap::from([(name, Vec::new())]));
    }
    card.security_schemes = Some(schemes);
    card.security_requirements = Some(requirements);
    card
}
