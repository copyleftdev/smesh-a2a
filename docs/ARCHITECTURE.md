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

### `artifact`

Defines the closed `ContentDigestV1`, `ArtifactManifestV1`, classification, encryption-domain,
producer, policy, chunk, and sorted provenance-edge contracts. Content identity is SHA-256 of exact
logical plaintext. Manifest identity is domain-separated SHA-256 of deterministic canonical JSON.
Opaque artifact IDs—not digests—are the authorization keys.

`PosixArtifactBlobStore` accepts only an absolute, owner-private, non-symlink root. It writes 0600
same-filesystem staging files, syncs file and directories, atomically promotes immutable random
object generations, and never derives a path from caller input. AES-256-GCM AAD binds tenant,
encryption domain, classification, content digest, plaintext length, and key generation. Reads spool
and verify ciphertext digest, AEAD, plaintext length, and plaintext digest before returning bytes.

PostgreSQL revision 5 is the production metadata/reference/retention authority. The filesystem is
bytes-only and cannot grant visibility. Resolver admission must use the scoped
`(tenant, owner/task visibility, opaque artifact ID)` join before any blob lookup. Read leases and
legal holds fence the live → tombstoned → deleting → deleted lifecycle; GC batches are bounded to
1..=1000 and generation-fenced. URL parts remain inert metadata and are never fetched.

SQLite intentionally does not claim external-artifact production parity. Existing inline history
remains replay-compatible pending the explicit, restartable PostgreSQL backfill/cutover operation.

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

PostgreSQL negotiates lease renewal and quota policy snapshots as explicit
capabilities; SQLite remains exclusive-open and reports neither distributed
capability.

### Distributed quota authority

`QuotaPolicy` is a strict canonical startup snapshot with a policy ID, revision,
and digest. Closed `QuotaOperation`, `QuotaDimension`, `QuotaScopeKind`, and
`QuotaAlgorithm` enums prevent free-form production accounting keys. The server
derives a keyed principal scope from the verified issuer/subject and builds a
bounded `QuotaIntent`; no A2A field, header, JSON-RPC correlation ID, caller
clock, or metadata map is accepted as quota authority.

PostgreSQL revision 4 persists immutable policy/intent/receipt evidence and
mutable tenant/account/principal fixed-window and gauge buckets under forced RLS. Initial
admission and every continuation reserve one shared per-execution output-byte and event-count
budget against all three aggregate scopes in the same transaction as task/event/idempotency/outbox
audit state. The private reservation identity/version, policy digest, and strict
minimum execution ceiling travel through the outbox, sender envelope, receiver
inbox, and fully fenced leases; they are never copied to A2A metadata.

The channel/runtime boundary receives a trusted `ExecutionBudget` before runtime,
model, or tool work and clamps canonical serialized `MeshEvent` UTF-8 bytes and
event count. Receiver completion repeats the canonical measurement before its
effect marker, frames, transcript, task, or response can commit. Completion,
cancellation, interruption, failure, dead letter, supersession, and recovery
settle one reservation transactionally: actual use remains charged and unused
capacity is refunded. Receiver-completed/sender-uncommitted recovery reuses the
stored measurement and settlement row. Exact replay verifies the original
reservation and never reserves or settles twice.

Active-work allocations survive process death and a database trigger settles
them once on terminal or paused task state. Static operator overrides are
bounded to one named scope/operation/dimension and database-time interval; actor,
reason, and target are digest-audited. Public-egress replay charging remains a
separate `PublicEgress` operation: it limits bytes crossing the public transport
and is not execution-output settlement, so the two ledgers are not combined or
double-counted.

The checked-in `a2a-lf` boundary patch reserves JSON-RPC `-32010`/HTTP 429 for
renewable quota exhaustion and `-32011`/HTTP 503 for authority unavailability.
Issue #14 is implemented through PostgreSQL revision 4: materialized retained-authority
accounting, bounded replay-safe GC, tenant-fair claiming, multi-scope quota policy,
execution reservations, stream/reconnect leases, audited reconciliation/overrides, and
the production abuse/fairness/failover matrix are documented in `evidence/m2/issue-14.md`.

### `telemetry` and audit projection

`telemetry` is a closed schema: static span/log/metric names, bounded attributes, closed outcomes,
no raw error bodies, at most eight metric attributes, 2,000 series per instrument, and 10,000
process-wide series. Correlation IDs are span/log-only. The outer production router generates a
random 128-bit request ID and removes inbound `x-request-id`, `traceparent`, `tracestate`, and
`baggage` before handlers run.

Durable authority rows and the bounded recent-window `runtime-trace/3` remain required evidence. `OtlpOwner` is a distinct,
bounded, drop-newest optional projection on an isolated OS thread. HTTP protobuf and gRPC log
exports are exercised against real decoding collectors; network export is never awaited by request,
worker, or authority transaction paths. Configuration is parsed before binding, but exporter
startup occurs only after listener reservation. HTTP uses no ambient proxy and no redirects.

`AuditProjector` claims a bounded leased durable outbox with per-row pending/leased/delivered/dead delivery state. It emits a stable domain-separated digest `event.id` and marks only the fenced row delivered after sink queue acceptance. There is no monotonic global cursor, so out-of-order commits cannot be skipped. It is an optional backend-neutral capability rather than a new `DurableAuthority` requirement.
There is no audit-read HTTP API in this release; the operator projection is OTLP-only. The concrete
SQLite/PostgreSQL ledgers remain authoritative and are not dual-written from handlers.

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
- Retained quota accounting/GC and deployment-specific telemetry backend retention.
