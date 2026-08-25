# SMESH A2A Gateway Plan

## Mission

Expose a SMESH swarm as one standards-compliant A2A v1 agent without leaking or replacing SMESH's decentralized coordination model.

## MVP acceptance criteria

1. Publish a valid A2A v1 Agent Card at `/.well-known/agent-card.json`.
2. Support JSON-RPC and HTTP+JSON/REST bindings through the official `a2a-rs` SDK.
3. Accept a text `SendMessage` request and create an A2A task.
4. Translate the request into a typed SMESH coordination signal.
5. Stream `Working`, artifact, and `Completed` events in order.
6. Persist task state independently from ephemeral SMESH signals for the server lifetime.
7. Support `GetTask`, `ListTasks`, `SubscribeToTask`, and `CancelTask` through the SDK handler.
8. Reject empty, non-text, and oversized inputs before they enter the mesh.
9. Demonstrate cancellation with a dispatcher that observes cancellation.
10. Pass unit, integration, formatting, Clippy, and documentation tests.

## Deliberate MVP limits

- Single-tenant, localhost-first server. Multi-tenant authorization is not claimed.
- In-memory A2A task store. Restart persistence is a subsequent SQLite adapter.
- No push notifications: outbound webhook delivery introduces SSRF and credential-forwarding risk.
- No fetching URL/file parts. Only inline text enters the mesh.
- The included loopback worker proves protocol translation. Production deployments inject a real SMESH worker over the same dispatcher boundary.

## Vertical TDD slices

1. Agent Card describes a streaming SMESH code-review capability.
2. Input validator accepts bounded text and rejects unsupported parts.
3. A2A message maps to a SMESH `SignalType::Query` carrying a typed task envelope.
4. Loopback dispatcher returns progress and an artifact; executor emits ordered A2A events.
5. Cancellation reaches the dispatcher and yields `Canceled`.
6. Axum router serves the Agent Card and both protocol bindings.
7. End-to-end HTTP test drives Agent Card and JSON-RPC through the official A2A client or wire shape.

## Quality gates

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- `cargo doc --no-deps`
- independent security and code review
