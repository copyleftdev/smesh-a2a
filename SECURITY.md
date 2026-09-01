# Security Policy

## Supported version

The `0.1.x` line is pre-stable and defaults to local development. Internet or multi-tenant deployment
is supported only inside the reviewed transport/authentication/PostgreSQL boundary and accepted
residual risks in `docs/GATEWAY_THREAT_MODEL.md`; it is not a general production-readiness claim.

## Deployment boundary

The bundled binary defaults to loopback and OIDC bearer authentication. It also supports direct
rustls termination and optional/required mTLS with exact verified-leaf fingerprint mapping.
Non-loopback exposure fails closed unless direct TLS, an HTTPS public URL, and OIDC and/or required
mTLS are configured and all material validates before listener, SQLite, runtime, or mesh startup.
Explicit authentication disablement is reserved for loopback development or direct TLS with required
mTLS. `SMESH_A2A_UNSAFE_PUBLIC` is ignored.

Current controls:

- 128 KiB HTTP request-body limit
- 64 KiB validated inline-text limit
- URL and raw-file parts rejected without dereferencing
- outbound A2A push callbacks disabled by default; production enablement requires an enrolled, canonical,
  bounded HTTPS DNS policy with fresh all-answer IP validation, TLS/mTLS, signing, quotas, retry/fencing,
  and stable idempotency
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
- bounded runtime command channels; cancellation acknowledgement is emitted only after cooperative
  processor stop or bounded local reap, and the trace distinguishes cooperative stop from forced abort
- forced local abort fails the public task and does not claim containment of model, tool, network, or
  storage effects that were already issued outside the canceled future
- typed `loopback-plain`, `reverse-proxy-loopback`, and `direct-tls` transport policy;
  non-loopback binds require direct TLS and reviewed authentication
- rustls ALPN (`h2`, `http/1.1`), zero early data, no key logging, bounded handshakes and connections
- required/optional WebPKI client verification and exact SHA-256 leaf-fingerprint principal mapping;
  CN, SAN, metadata, and forwarding headers do not establish identity
- atomic SIGHUP reload of the complete certificate/key/client-roots/principal-map generation

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
commit, and persists its cursor and completion-receipt keys. It is the local compatibility authority.
Production multi-replica durability uses PostgreSQL with separate migrator/runtime roles, forced RLS,
sealed append-only migrations, database-time leases/fences, tenant authorization, distributed quotas,
callbacks, artifact metadata, and audit projection. Authenticated serving requires an authorized durable
mode; policy-only, authentication-only, and invalid backend/runtime combinations fail closed.
Authentication-only compatibility builders are development-only. Managed cross-deployment policy/key
coordination and external control-plane lifecycle remain operator work. In-memory mode retains
process-local keys and ledger state.

## Known dependency warning

`cargo audit` reports `RUSTSEC-2025-0141`: `bincode 1.3.3` is unmaintained. It is pulled transitively by the pinned `smesh-core` revision. This is an unmaintained-package warning rather than a reported vulnerability. The gateway does not invoke bincode directly. It should be removed by upgrading SMESH serialization or narrowing the integration dependency when an upstream revision is available.

The audit also reports that transitive `chacha20 0.10.1` is yanked through the pinned QUIC stack
(`quinn-proto`/`quinn`). This is a registry-yank warning, not a RustSec vulnerability advisory in
the locked tree. It must be removed through a reviewed upstream QUIC/runtime dependency update.

Adding the pinned runtime initially resolved `time 0.3.45`, affected by
`RUSTSEC-2026-0009`. The lockfile is upgraded to `time 0.3.47`; that security update raises the
gateway MSRV to Rust 1.88.

## Deployment requirements beyond the bundled boundary

Before internet or multi-tenant deployment, operators must provide:

- managed tenant/OIDC policy enrollment, revocation, rotation, and distributed control-plane coordination;
- managed certificate issuance/revocation and external key/backup custody;
- deployment-specific capacity sizing, alerting, retention scheduling, PostgreSQL TLS/HA/backups, and
  external telemetry retention/tenant ACLs;
- application-specific semantic work processors, authenticated evidence issuers, and idempotency for
  model/tool/network/storage effects outside forced cancellation;
- signed release provenance and an organizational dependency/vulnerability policy;
- explicit acceptance of the residual risks in `docs/GATEWAY_THREAT_MODEL.md`.

## Reporting

Open a private security advisory on the GitHub repository when available. Do not include live credentials, private task data, or exploit payloads in a public issue.
