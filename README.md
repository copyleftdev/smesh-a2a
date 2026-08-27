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
- Mandatory versioned completion policy with buffered candidate artifacts, contradiction veto,
  deterministic receipt claims, and optional signed human ratification
- HMAC sealing and read-path validation for accepted completion receipts; SQLite mode persists the
  sealing key with the task ledger so receipts remain verifiable after restart

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
   `-- ChannelDispatcher -> RuntimeWorker -> SmeshRuntime/QUIC
   |
   v
SMESH Query signal -> claims/review/tests/consensus -> MeshEvent stream
```

See:

- [`docs/PLAN.md`](docs/PLAN.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/ADR-0001-RUNTIME-PROCESS-OWNERSHIP.md`](docs/ADR-0001-RUNTIME-PROCESS-OWNERSHIP.md)
- [`docs/PROTOCOL_MAPPING.md`](docs/PROTOCOL_MAPPING.md)
- [`docs/RUNTIME_E2E_HARNESS.md`](docs/RUNTIME_E2E_HARNESS.md)
- [`docs/RUNTIME_EVENT_CAPTURE.md`](docs/RUNTIME_EVENT_CAPTURE.md)
- [`docs/RUNTIME_TERMINAL_RACES.md`](docs/RUNTIME_TERMINAL_RACES.md)
- [`docs/ULTIMATE_DEMO.md`](docs/ULTIMATE_DEMO.md)
- [`docs/TRACE_CAPTURE.md`](docs/TRACE_CAPTURE.md)
- [`evidence/m1/README.md`](evidence/m1/README.md)

## LIFELINE cinematic demo

`LIFELINE // 47 MINUTES` is the proposed ultimate use case: six fictional organizations coordinate a medication-safety response without pooling private memory or granting an AI authority to act. The 47-minute fictional response is compressed into a three-minute replay. A2A carries accountable work between organizations; SMESH coordinates uncertain work inside each organization; a human ratifies the final response package.

![LIFELINE cinematic replay showing the human-authorization gate](demo/poster.jpg)

- [Open the interactive WebGL replay](https://copyleftdev.github.io/smesh-a2a/)
- [Download the narrated film and ElevenLabs master](https://github.com/copyleftdev/smesh-a2a/releases/tag/lifeline-demo-v0.1)

The repository includes a deterministic cinematic fixture and replay surface:

- `demo/lifeline.trace.jsonl`: 55 append-only, hash-chained events
- `demo/trace.schema.json`: the replay schema
- `demo/index.html`: interactive Three.js/WebGL globe, timeline, scrubber, and trace inspector
- `demo/STORYBOARD.md`: the 16:9 film plan
- `demo/NARRATION.md`: timed ElevenLabs-ready narration
- `demo/lifeline-voiceover.mp3`: bundled narration used by the interactive Play control
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

Requires Rust 1.88 or newer.

```bash
cargo run --bin smesh-a2a-gateway
```

Defaults:

- bind: `127.0.0.1:3000`
- public URL: `http://127.0.0.1:3000`
- node ID: `smesh-a2a-gateway`
- mode: `loopback`

Configuration:

```bash
mkdir -p "$HOME/.local/state/smesh-a2a"
chmod 700 "$HOME/.local/state/smesh-a2a"
SMESH_A2A_BIND=127.0.0.1:4000 \
SMESH_A2A_PUBLIC_URL=http://127.0.0.1:4000 \
SMESH_A2A_NODE_ID=gateway-west \
SMESH_A2A_SQLITE_PATH="$HOME/.local/state/smesh-a2a/tasks.sqlite3" \
cargo run --bin smesh-a2a-gateway
```

`SMESH_A2A_SQLITE_PATH` enables repository-owned durable admission, dispatch, receiver deduplication,
and exact unary/stream replay **only when `SMESH_A2A_MODE=loopback`** (the default). Persistent
SQLite mode is supported on Unix platforms only and enforces exactly one open writer per database
with a nonblocking lifetime file lock; a second gateway/store open fails before restart recovery and
cannot terminalize live work. On non-Unix platforms persistent open fails explicitly. The path must
be absolute and its existing parent directory must be owned by the gateway user with no group or
world permissions (normally mode `0700`). The database and SQLite sidecars are held at `0600`.
On SIGINT, durable loopback stops HTTP admission gracefully, joins its outbox driver and real-time
retry ticker within bounded deadlines, then closes shared SQLite state and releases the lock.

`SMESH_A2A_MODE=runtime` combined with `SMESH_A2A_SQLITE_PATH` fails closed before opening SQLite,
starting the runtime/event drain or worker, or binding/joining the mesh. Durable runtime routing is not
supported until a repository-owned runtime effect-idempotency adapter can durably deduplicate stable
dispatch IDs and replay receiver effects. The generic library function `build_router_with_sqlite`
(and its traced variant) remains a compatibility/task-snapshot API around the upstream
`DefaultRequestHandler`; it is not durable dispatch and must not be used to claim effect replay.

Run the built-in real runtime worker with a live QUIC endpoint:

```bash
SMESH_A2A_MODE=runtime \
SMESH_A2A_MESH_BIND=127.0.0.1:4100 \
SMESH_A2A_BOOTSTRAP=127.0.0.1:4101,127.0.0.1:4102 \
cargo run --bin smesh-a2a-gateway
```

`SMESH_A2A_BOOTSTRAP` may be omitted for the first mesh node. Runtime mode creates a genuine
`SmeshRuntime`, joins its QUIC mesh, emits each validated request as `SignalType::Query`, and uses
the gateway completion policy as the only authority that can publish artifacts or `Completed`.
The bundled `RuntimeAdmissionProcessor` deliberately supplies no semantic review/test evidence, so
an arbitrary request ends `Failed` with no public artifact after proving real ingress. A trusted
application processor and independent evidence sources are required before semantic completion.

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

## Embed a custom runtime task processor

`RuntimeWorker` owns `ChannelDispatcher` commands and the genuine SMESH ingress path. Inject a
processor only for application-specific Query→candidate work; its events remain untrusted policy
inputs:

```rust,no_run
use std::sync::Arc;
use smesh_a2a::{RuntimeAdmissionProcessor, RuntimeWorker};
use smesh_runtime::SmeshRuntime;

# async fn example(runtime: Arc<SmeshRuntime>) -> Result<(), Box<dyn std::error::Error>> {
let (dispatcher, worker) = RuntimeWorker::spawn(
    runtime,
    "gateway-node",
    RuntimeAdmissionProcessor,
    64,
).await?;
# let _ = dispatcher;
# let _ = worker;
# Ok(())
# }
```

The bundled processor proves structural runtime ingress and binding only. It does not claim the
requested work is semantically correct or independently reviewed.

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
- Worker `Completed` events are proposals: candidate artifacts remain private until the
  gateway's locally configured completion policy accepts a sealed evidence snapshot.
- The binary refuses non-loopback binds unless `SMESH_A2A_UNSAFE_PUBLIC=1` is explicit.

Do not expose the MVP directly to an untrusted network. `SMESH_A2A_UNSAFE_PUBLIC=1` only disables the bind guard; it does not add security. Production deployment still requires authenticated principals, tenant-aware authorization, TLS, tenant-aware persistence, distributed quotas, and observability.

## Test and verify

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
```

The integration suite starts real Axum and QUIC listeners and drives the gateway with the official
A2A Rust client. It verifies real runtime Query ingress, fail-closed admission-only output,
streaming order, and cancellation acknowledgement after runtime processing stops.

## License

MIT OR Apache-2.0.
