use a2a::{
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill,
    TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC,
};

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
            extended_agent_card: None,
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
