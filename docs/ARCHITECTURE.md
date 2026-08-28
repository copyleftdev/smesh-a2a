# Architecture

## Boundary

A2A is the durable external contract. SMESH signals are the ephemeral internal coordination mechanism.

```text
A2A client
   |
   | Agent Card / Send / Stream / Get / List / Cancel
   v
A2A SDK routers + GuardedRequestHandler
   | preflight + terminal-state guard
   v
BoundedTaskStore + SmeshExecutor
   | validates and translates
   v
MeshDispatcher trait
   |
   +-- LoopbackDispatcher (tests/demo)
   +-- ChannelDispatcher -> RuntimeWorker -> SmeshRuntime/QUIC
   |
   v
SMESH Query signal -> claims/reinforcement/work -> MeshEvent stream
```

## Components

### `card`

Builds the public Agent Card. It advertises only externally supported capabilities, not every internal node role.

### `input`

Accepts inline text parts only and applies a byte bound. It never dereferences URLs or trusts metadata as instructions.

### `bridge`

Defines `MeshRequest`, `MeshEvent`, and the `MeshDispatcher` trait. It creates real `smesh_core::Signal` values but keeps transport and worker policy behind an interface.

### `executor`

Implements the official `a2a_server::AgentExecutor`. It enforces active-task, event, artifact, output-byte, inactivity, and cancellation budgets, then maps:

- dispatch accepted -> `Working`;
- mesh progress -> `Working` status message;
- mesh artifact -> private candidate output;
- sealed policy acceptance -> candidate artifacts plus terminal A2A task;
- human-required policy -> `InputRequired`;
- mesh failure -> `Failed`;
- cancellation -> `Canceled`.

### `runtime_worker`

Consumes `ChannelDispatcher` commands, emits each genuine `SignalType::Query` through
`SmeshRuntime`, and invokes a bounded application processor. Processor events remain untrusted:
runtime ingress, an artifact, or a worker completion proposal cannot directly publish A2A
`Completed`. The processor sink cannot submit policy evidence; independent authority adapters must do
that separately. Cancellation acknowledgement is sent only after the processor task exits or is
aborted after its bounded grace period.

### `store` and `guard`

`BoundedTaskStore` gives the process-local ledger a hard capacity and makes terminal states absorbing. `GuardedRequestHandler` rejects caller-supplied tenants in the single-tenant MVP and blocks new messages for terminal task IDs before the official handler starts execution.

### `durable_authority`, `sqlite_store`, and durable runtime

`DurableAuthority` is an object-safe umbrella over required narrow capabilities:
scoped reads/frozen pages, admission/replay/continuation, lifecycle and cancellation
arbitration, outbox/receiver fencing, transcripts/subscriptions, authorization
audit/key material, bounded change observation, diagnostics, and shutdown. Every
production method is required; a blank backend cannot compile as a durable
authority. Production durable handlers, the outbox driver, loopback receiver,
authorization middleware, and the owned gateway hold `Arc<dyn DurableAuthority>`;
SQLite construction, migration, schema administration, and test fault injection
remain concrete.

Authenticated routes receive only scoped capabilities. Global get/list/replay,
cancel, and transcript operations are absent from `DurableAuthority`; a sealed,
crate-private SQLite adapter preserves explicit local-development compatibility.

Change notifications are hints. `ChangeObservation` contains a validated
`PollInterval` in `10ms..=5s` and bounds periodic durable re-reads by drivers and
streams, so correctness does not depend on an in-process `Notify` or `watch`
reaching the consumer. A process-wide panic hook is installed once before the
first driver spawn and preserves the previous hook. A poll wrapper sets a
thread-local redaction flag only while synchronously polling the driver future,
restoring it on return or unwind. Driver panic payloads and locations therefore
do not reach process stderr, while unrelated panics still delegate to the prior
hook. The worker publishes one generic fatal state and wakes attached consumers.
Gateway shutdown first joins its owned driver and then calls the backend-neutral
authority shutdown contract. The SQLite adapter intentionally retains its
pre-existing shared-clone close behavior pending multi-replica work.

Backend-neutral evidence is the reusable command-level harness in
`tests/support/durable_authority_conformance.rs`. It accepts
`Arc<dyn DurableAuthority>` through a watchdog-bounded fixture factory/cleanup
runner, directly exercises every required scoped capability, and runs against
both a fully recording fake and real SQLite state. The separate full JSON-RPC
gateway lifecycle remains SQLite/local compatibility evidence; it is not
described as backend-neutral conformance.

Issue #61 intentionally exposes no lease-renewal API. Issue #63 will add renewal
only as a negotiated capability together with runtime calls and atomic fencing;
SQLite remains exclusive-open and reports no dormant renewal surface.

### `server`

Composes the official JSON-RPC, REST, Agent Card, task store, and executor into one Axum router. It binds to loopback by default.

## Invariants

1. A terminal A2A task never returns to a non-terminal state.
2. Every artifact belongs to exactly one A2A task and context.
3. A2A task IDs remain durable even after their SMESH signals expire.
4. External metadata cannot set trust, confidence, reinforcement, or internal node identity.
5. Agent Card metadata is discovery information, never an attestation.
6. The first accepted cancellation is visible to the dispatcher; later cancellation requests cannot alter the terminal state.
7. Only validated inline text crosses the public-to-mesh boundary in the MVP.
8. The gateway emits one final terminal event for every accepted request.
9. Successful runtime Query ingress is progress, never completion authority.

## Production extensions

- SQLite/Postgres `TaskStore` with tenant-aware authorization and cursor pagination.
- Bearer/OAuth/mTLS interceptor.
- Bounded push notifications with an allowlist and SSRF defenses.
- Application-specific semantic work processors and authenticated evidence issuers.
- gRPC listener.
- OpenTelemetry tracing and per-principal quotas.
