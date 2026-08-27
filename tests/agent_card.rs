use a2a::{TRANSPORT_PROTOCOL_HTTP_JSON, TRANSPORT_PROTOCOL_JSONRPC};
use smesh_a2a::build_agent_card;

#[test]
fn agent_card_advertises_supported_bindings_and_streaming() {
    let card = build_agent_card("http://127.0.0.1:3000");

    assert_eq!(card.name, "SMESH Swarm");
    assert_eq!(card.capabilities.streaming, Some(true));
    assert_eq!(card.capabilities.push_notifications, Some(false));
    assert_eq!(card.skills.len(), 1);
    assert_eq!(card.skills[0].id, "smesh.collaborative-task");
    assert_eq!(
        card.default_output_modes,
        ["text/plain", "application/json"]
    );
    assert_eq!(
        card.skills[0].output_modes.as_deref(),
        Some(["text/plain".to_owned(), "application/json".to_owned()].as_slice())
    );

    let bindings: Vec<_> = card
        .supported_interfaces
        .iter()
        .map(|interface| interface.protocol_binding.as_str())
        .collect();
    assert!(bindings.contains(&TRANSPORT_PROTOCOL_JSONRPC));
    assert!(bindings.contains(&TRANSPORT_PROTOCOL_HTTP_JSON));
    assert!(
        card.supported_interfaces
            .iter()
            .all(|interface| interface.protocol_version == "1.0")
    );
}
