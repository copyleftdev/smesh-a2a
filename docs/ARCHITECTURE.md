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
