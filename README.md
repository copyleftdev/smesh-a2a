# SMESH A2A

A2A v1 interoperability gateway for decentralized [SMESH](https://github.com/copyleftdev/smesh-rust) agent swarms.

SMESH remains the internal coordination substrate: signals diffuse, decay, reinforce, and accumulate attestations. A2A is the public contract for discovery, durable task lifecycle, streaming progress, cancellation, and artifacts.

## What works

- Official A2A v1 Rust types and server/client SDKs
- Public Agent Card at `/.well-known/agent-card.json`
- JSON-RPC endpoint at `/jsonrpc`
- HTTP+JSON/REST endpoint at `/rest`
- Synchronous and SSE streaming task execution
- `GetTask`, `ListTasks`, `SubscribeToTask`, and `CancelTask` through `a2a-rs`
- Strict inline-text validation with a 64 KiB default limit
- Translation to a real `smesh_core::SignalType::Query`
- Injectable `MeshDispatcher` boundary for a production SMESH runtime
- Deterministic loopback worker for demos and interoperability tests
- Bounded task retention, execution concurrency, event/artifact counts, and output bytes
- Worker inactivity, cancellation, and command-channel deadlines
- Terminal-state and task-ID reuse guards

## Architecture

```text
A2A client
   |
   v
Agent Card + JSON-RPC/REST/SSE
   |
   v
SmeshExecutor -- validates and translates
   |
   v
MeshDispatcher
   |-- LoopbackDispatcher (demo/tests)
   `-- ChannelDispatcher  (real SMESH worker boundary)
   |
   v
SMESH Query signal -> claims/review/tests/consensus -> MeshEvent stream
```

See:

- [`docs/PLAN.md`](docs/PLAN.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/PROTOCOL_MAPPING.md`](docs/PROTOCOL_MAPPING.md)
- [`docs/ULTIMATE_DEMO.md`](docs/ULTIMATE_DEMO.md)
- [`docs/TRACE_CAPTURE.md`](docs/TRACE_CAPTURE.md)

## LIFELINE cinematic demo

`LIFELINE // 47 MINUTES` is the proposed ultimate use case: six fictional organizations coordinate a medication-safety response without pooling private memory or granting an AI authority to act. The 47-minute fictional response is compressed into a three-minute replay. A2A carries accountable work between organizations; SMESH coordinates uncertain work inside each organization; a human ratifies the final response package.

![LIFELINE cinematic replay showing the human-authorization gate](demo/poster.jpg)

The repository includes a deterministic cinematic fixture and replay surface:

- `demo/lifeline.trace.jsonl`: 55 append-only, hash-chained events
- `demo/trace.schema.json`: the replay schema
- `demo/index.html`: interactive Three.js/WebGL globe, timeline, scrubber, and trace inspector
- `demo/STORYBOARD.md`: the 16:9 film plan
- `demo/NARRATION.md`: timed ElevenLabs-ready narration
- `demo/export-film.mjs`: deterministic frame-by-frame exporter
- `demo/record-film.mjs`: real-time 1920×1080 recorder and audio muxer

Generate and validate the trace:

```bash
cargo run --bin lifeline-trace -- demo/lifeline.trace.jsonl
cargo test --test lifeline_trace
```

Preview the WebGL film:

```bash
cd demo
npm ci
npm run serve
# open http://127.0.0.1:43130/
```

The checked-in JSONL is a deterministic synthetic fixture for replay, design, and conformance work. The nominal visual timeline is three minutes; the current narrated master is approximately 2:55 because export stops at the end of the narration track. It does not claim that six production organizations or six live SMESH runtimes executed the incident. The operational version must replace fixture emission with captured A2A requests, real `SignalType::Query` diffusion, dispatcher acknowledgements, task-ledger transitions, and human approval events. The film is permanently labeled `SIMULATION · NOT MEDICAL ADVICE · NO ACTIONS EXECUTED`.

## Run the gateway

Requires Rust 1.85 or newer.

```bash
cargo run --bin smesh-a2a-gateway
```

Defaults:

- bind: `127.0.0.1:3000`
- public URL: `http://127.0.0.1:3000`
- node ID: `smesh-a2a-gateway`

Configuration:

```bash
SMESH_A2A_BIND=127.0.0.1:4000 \
SMESH_A2A_PUBLIC_URL=http://127.0.0.1:4000 \
SMESH_A2A_NODE_ID=gateway-west \
cargo run --bin smesh-a2a-gateway
```

Inspect the Agent Card:

```bash
curl http://127.0.0.1:3000/.well-known/agent-card.json
```

Use the official A2A CLI:

```bash
cargo install a2a-cli
a2acli --base-url http://127.0.0.1:3000 card
a2acli --base-url http://127.0.0.1:3000 send "review this Rust crate"
a2acli --base-url http://127.0.0.1:3000 stream "review this Rust crate"
```

## Embed a real SMESH worker

Create a `ChannelDispatcher` and consume its commands in the runtime that owns the mesh:

```rust,no_run
use smesh_a2a::{ChannelDispatcher, DispatchCommand};

# async fn example() {
let (commands_tx, mut commands_rx) = tokio::sync::mpsc::channel(32);
let dispatcher = ChannelDispatcher::new(commands_tx, "gateway-node");

while let Some(command) = commands_rx.recv().await {
    match command {
        DispatchCommand::Execute { request, signal, events } => {
            // Emit `signal` into SMESH. Translate accepted internal output into
            // MeshEvent values and send them through `events`.
            let _ = (request, signal, events);
        }
        DispatchCommand::Cancel { task_id, ack } => {
            // Stop internal work for task_id, then acknowledge.
            let _ = task_id;
            let _ = ack.send(Ok(()));
        }
    }
}
# let _ = dispatcher;
# }
```

## Security posture

The MVP is intentionally localhost-first and single-tenant.

- URL and raw file parts are rejected; the gateway never dereferences user-provided URLs.
- Push notifications are disabled to avoid an unaudited outbound webhook/SSRF surface.
- External metadata cannot set SMESH trust, confidence, reinforcement, or node identity.
- Agent Card data is discovery metadata, not an attestation.
- Input is bounded before entering the mesh (128 KiB HTTP body, 64 KiB text).
- The local store has a hard 1,024-task ceiling; active execution defaults to 64 tasks.
- Worker output is limited to 16 events, 16 artifacts, and 1 MiB per task.
- Worker inactivity, total task duration, and cancellation have deadlines; cancellation wakes active streams.
- The binary refuses non-loopback binds unless `SMESH_A2A_UNSAFE_PUBLIC=1` is explicit.

Do not expose the MVP directly to an untrusted network. `SMESH_A2A_UNSAFE_PUBLIC=1` only disables the bind guard; it does not add security. Production deployment still requires authenticated principals, tenant-aware authorization, a persistent task store, TLS, distributed quotas, and observability.

## Test and verify

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
```

The integration suite starts real Axum listeners and drives them with the official A2A Rust client over both JSON-RPC and REST. It also verifies streaming order and cancellation propagation.

## License

MIT OR Apache-2.0.
