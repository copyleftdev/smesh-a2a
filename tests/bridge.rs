use a2a::{Message, Part, Role};
use smesh_a2a::{DispatchError, InputLimits, MeshRequest};
use smesh_core::SignalType;

#[test]
fn a2a_message_becomes_a_smesh_query_signal() {
    let message = Message::new(Role::User, vec![Part::text("review the crate")]);

    let request = MeshRequest::from_a2a(
        "task-1".into(),
        "context-1".into(),
        &message,
        InputLimits::default(),
    )
    .unwrap();
    let signal = request.to_signal("gateway-node");

    assert_eq!(signal.signal_type, SignalType::Query);
    assert_eq!(signal.origin_node_id, "gateway-node");
    assert!(signal.attestations.is_empty());

    let payload: serde_json::Value = serde_json::from_slice(&signal.payload).unwrap();
    assert_eq!(payload["protocol"], "a2a-v1");
    assert_eq!(payload["task_id"], "task-1");
    assert_eq!(payload["context_id"], "context-1");
    assert_eq!(payload["text"], "review the crate");
    assert!(payload.get("trust").is_none());
    assert!(payload.get("confidence").is_none());
}

#[test]
fn external_dispatchers_can_construct_message_errors() {
    let error = DispatchError::message("external dispatcher failure");
    assert!(error.to_string().contains("external dispatcher failure"));
}
