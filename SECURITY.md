# Security Policy

## Supported version

The `0.1.x` line is an MVP intended for local development and integration testing.

## Deployment boundary

The bundled binary binds to loopback by default. Do not expose it directly to an untrusted network. It does not yet implement authentication, tenant authorization, tenant-aware persistence, request quotas, or TLS termination.

Current controls:

- 128 KiB HTTP request-body limit
- 64 KiB validated inline-text limit
- URL and raw-file parts rejected without dereferencing
- outbound A2A push notifications disabled
- external metadata excluded from SMESH trust, confidence, reinforcement, and identity
- bounded async channels between the A2A executor and embedded worker
- bounded local task retention and active execution concurrency
- per-task event, artifact, and output-byte budgets
- worker inactivity, cancellation, and command-channel deadlines
- cancellation tokens that wake active executor streams
- absorbing terminal states in the task store
- terminal failure when a worker stream closes without completion
- worker completion treated as an untrusted proposal; candidate artifacts remain buffered until
  a versioned, bounded, deterministic policy accepts the sealed evidence snapshot
- blocking-contradiction veto and signed, allowlisted ratification for human-required profiles
- HMAC seals on ratification checkpoints and accepted completion receipts, verified with
  task/context/policy and recomputed artifact bindings before stored tasks are exposed; SQLite mode
  stores the receipt key in the owner-only ledger so pre-restart receipts remain verifiable
- bounded dispatcher cancellation after local deadlines, inactivity, resource-budget failures,
  policy rejection, and abandoned response streams
- explicit `loopback`/`runtime` mode selection; malformed runtime or bootstrap addresses fail startup
- bounded runtime command channels and cancellation acknowledgement only after processor shutdown
- refusal to bind outside loopback unless an explicit unsafe override is set

Completion-policy review/test payload hashes are recomputed by the gateway and issuer labels must
appear in the locally configured policy profile, but those labels are not authenticated identities.
A review/test record proves only that the policy received a structurally valid claim bound to exact
artifact, request, task, context, and policy hashes. Cryptographic attestations must match a locally
configured key and prove possession of that key, not real-world authority. Human ratification proves configured-key possession,
but durable freshness, revocation, and cross-restart replay prevention still require persistent
identity and ledger work. The loopback worker emits explicitly synthetic evidence fixtures.
The bundled runtime admission processor emits a private candidate receipt and completion proposal but
no review, test, contradiction, or ratification evidence. Runtime ingress therefore fails closed
under the default completion policy and cannot masquerade as semantically completed work.
The SQLite task ledger is Unix-only, owner-only, single-writer, crash-durable after transaction
commit, and persists its cursor and completion-receipt keys. It is not a tenant boundary or a general
key-management system: key rotation, revocation, identity binding, rollback-resistant freshness, and
cross-host coordination remain production work. In-memory mode retains process-local keys and ledger
state.

## Known dependency warning

`cargo audit` reports `RUSTSEC-2025-0141`: `bincode 1.3.3` is unmaintained. It is pulled transitively by the pinned `smesh-core` revision. This is an unmaintained-package warning rather than a reported vulnerability. The gateway does not invoke bincode directly. It should be removed by upgrading SMESH serialization or narrowing the integration dependency when an upstream revision is available.

Adding the pinned runtime initially resolved `time 0.3.45`, affected by
`RUSTSEC-2026-0009`. The lockfile is upgraded to `time 0.3.47`; that security update raises the
gateway MSRV to Rust 1.88.

## Production requirements

Before internet or multi-tenant deployment, add:

- authenticated principals and tenant-scoped authorization on every task operation;
- tenant-aware persistence and key management;
- TLS or a trusted reverse proxy;
- per-principal rate, concurrency, task-duration, history, and artifact quotas;
- structured audit logs and distributed tracing;
- cancellation on client disconnect and execution deadlines;
- outbound URL allowlists and DNS/IP revalidation before enabling push notifications;
- signed release provenance and dependency policy enforcement.

## Reporting

Open a private security advisory on the GitHub repository when available. Do not include live credentials, private task data, or exploit payloads in a public issue.
