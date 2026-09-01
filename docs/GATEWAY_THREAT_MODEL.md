# Gateway Threat Model

This document is the aggregate STRIDE and data-flow model for the M2 durable authenticated gateway.
It defines the reviewed deployment boundary established by issues #72-#75 and the evidence required to
change a trust boundary. It is not a claim that optional external services or host infrastructure are
risk-free.

## Scope and security objectives

In scope:

- public Agent Card, JSON-RPC, REST, streaming, pagination, and cancellation bindings;
- bearer and mTLS authentication, server-derived principals, tenant authorization, and quota admission;
- reverse-proxy loopback transport and outbound HTTPS OIDC/JWKS retrieval, caching, and rotation;
- SQLite local durability and PostgreSQL multi-replica authority;
- durable task, event, idempotency, outbox, receiver, transcript, quota, audit, callback, and artifact
  state;
- SMESH runtime/processor ingress and completion-policy evidence;
- encrypted artifact bytes and PostgreSQL artifact metadata;
- outbound callbacks, DNS/TLS/mTLS/signing, retry, and fencing;
- bounded runtime trace and optional OTLP/audit projection;
- migrator/operator maintenance, retention, backup, restore, and reconciliation;
- process crash, restart, load, slow-consumer, and fault-recovery behavior.

Security objectives:

1. A caller cannot select another tenant, account, principal, task, artifact, or authority capability.
2. Public input cannot directly grant completion, quota, cleanup, migration, callback, projection, or
   operator authority.
3. Client-acknowledged durable mutations have RPO 0; unacknowledged mutations are absent or coherent,
   never partial.
4. One tenant/workload cannot cause unbounded memory, FD, audit, trace, pagination, quota, callback, or
   durable-storage growth in a steady-state request path.
5. Secrets, tenant identity, raw payloads, backend locators, and credentials do not escape through
   public errors, telemetry, evidence, or artifacts.
6. Optional telemetry and external delivery cannot block or become the source of durable truth.

Out of scope: host compromise, malicious kernel/hypervisor, physical access, disk-full and cgroup OOM,
host reboot, physical packet corruption, multi-day capacity planning, external IdP/CA/collector
administration, and cryptographic primitive failure. These remain deployment risks rather than hidden
M2 claims.

## Assets

- tenant task content, history, status, and result integrity;
- verified principal/account/tenant bindings and policy snapshots;
- durable task/event/idempotency/outbox/receiver/transcript state;
- quota reservations, retained-byte accounting, authorization decisions, and operator overrides;
- callback policy, endpoint enrollment, signing/mTLS material, delivery fences, and idempotency keys;
- artifact plaintext, encrypted blobs, opaque IDs, manifests, provenance, classifications, keys, legal
  holds, leases, and retention state;
- completion policy, evidence issuers, receipts, and terminal publication authority;
- PostgreSQL migration/projection proofs, runtime role boundaries, backup/restore journals, and audit
  projection rows;
- runtime-trace required evidence and redacted operational telemetry.

## Actors and assumptions

- **Unauthenticated network client:** may discover the public Agent Card and submit arbitrary bytes to
  protected routes, but has no authority.
- **External reverse proxy:** may terminate public TLS only in `reverse-proxy-loopback` mode. It is
  trusted to preserve confidentiality, integrity, availability, source policy, and loopback-only
  reachability on the proxy-to-gateway hop; it does not establish application identity.
- **OIDC identity provider/JWKS endpoint:** controls issuer signing keys and availability for bearer
  verification. Its administration is external, but its bounded HTTPS runtime data flow and cached-key
  authority are in scope.
- **Authenticated hostile tenant:** may submit malformed/ambiguous protocol values, race requests,
  replay semantic IDs, control its own callback DNS/HTTP server, stall streams, and attempt resource
  exhaustion. It cannot set its authoritative account, tenant membership, lease, fence, clock, quota,
  projection proof, or operator capability.
- **Runtime processor or mesh peer:** may emit progress, artifacts, errors, and completion proposals. Its
  output is untrusted until validated and accepted by completion policy and durable authority.
- **Runtime database role:** may execute only the sealed runtime API under forced RLS. Caller-settable
  GUCs are not operator or cleanup authority.
- **Migrator/operator:** trusted for schema migration, retention, offline restore, key rotation, and
  explicitly documented reconciliation. Compromise of this role is outside tenant isolation.
- **Callback endpoint and OTLP collector:** external, fallible, potentially hostile destinations. They
  cannot mutate durable authority by response body or telemetry acceptance.

## Data-flow and trust boundaries

```text
                    TB1 public transport
A2A client -- direct TLS/mTLS ----------------------------+
        \-- external TLS reverse proxy -- loopback HTTP --+
  | Agent Card (public)                                  |
  | JSON-RPC / REST / stream / cancel / list             v
  +--> listener -> TLS/mTLS or bearer verifier -> server principal
                       | TB2 identity/tenant boundary
                       v
       ingress redaction -> authorization -> quota -> strict protocol parser
                       | TB3 transaction authority boundary
                       v
     DurableAuthority (SQLite exclusive local OR PostgreSQL forced-RLS runtime)
       | task/event/idempotency/audit/quota/outbox/receiver/transcript rows
       +--> outbox claim + lease/fence -> dispatcher/runtime worker
                                      | TB4 ephemeral mesh/processor boundary
                                      v
                         untrusted MeshEvent/evidence proposal
                                      |
                           completion policy + canonical limits
                                      v
                         atomic durable terminal/public replay

Durable callback event -> leased callback worker -> DNS policy -> pinned TLS/mTLS endpoint
        TB5 outbound network                     <- bounded response/retry classification

Scoped opaque artifact ID -> PostgreSQL metadata/authorization -> encrypted POSIX blob
        TB6 database/filesystem boundary              -> verify AEAD/length/digests

Durable audit projection row -> bounded leased projector -> bounded OTLP queue -> collector
        TB7 optional telemetry boundary              (durable row remains truth)

Offline operator/migrator -> retention / migration / restore / key rotation
        TB8 administrative boundary -> sealed catalog, fixed search path, offline/exclusive checks

Bearer verifier -> bounded HTTPS/no-proxy/no-redirect JWKS fetch -> external identity provider
        TB9 external identity-key boundary -> validated bounded cache / singleflight rotation
```

### TB1 - public transport

The listener binds loopback by default. Production direct TLS validates certificate/key/root material
before serving, uses bounded capacity and handshake deadlines, and derives mTLS identity from the peer.
`reverse-proxy-loopback` requires a loopback bind and OIDC; the external proxy terminates public TLS and
must protect the proxy-to-loopback hop from nonlocal access, header injection, plaintext observation,
request smuggling, and resource exhaustion. Forwarding headers still do not establish application
identity. Inbound request ID, trace, baggage, and tenant headers cannot become authority. Agent Card
metadata is discovery information, not attestation.

### TB2 - identity and tenant scope

Authentication creates a server-owned principal. Authorization resolves an immutable account and
membership from a strict policy. Tenant selection is rejected in single-tenant mode and checked against
membership in durable mode. Quota scope is a keyed digest of the verified issuer/subject, never request
metadata. Errors and denials are digest-only and canary-tested for leakage.

### TB3 - durable authority

Admission, semantic replay, task/event state, authorization audit, quota reservation, outbox intent, and
idempotency bind in one transaction. PostgreSQL uses forced RLS, separate migrator/runtime roles, sealed
functions/catalog checks, database time, and token/epoch fences. SQLite uses exclusive ownership,
transactional triggers, schema/catalog validation, and startup reconciliation. Change notifications are
hints; correctness re-reads durable state.

### TB4 - runtime and processor

Processor/runtime ingress is progress, never completion authority. Input is bounded inline text; URLs
are not fetched. Event count, serialized bytes, artifacts, inactivity, cancellation, and grace periods
are bounded. Completion requires canonical evidence and a versioned policy receipt. Runtime trace is a
bounded recent window; durable task/outbox/audit/artifact state is recovery authority.
Forced cancellation stops and reaps the owned future but cannot retract model, tool, network, or storage
effects already issued outside it. Durable runtime effect deduplication is not claimed; application
processors and external tools must provide their own idempotency boundary.

### TB5 - callbacks

Enrollment is operator/policy constrained to canonical HTTPS DNS endpoints. Every connection performs
fresh all-answer special-use rejection, pins the validated address while preserving Host/SNI, disables
ambient proxies and redirects, validates TLS and optional mTLS, signs exact bytes, and bounds response,
retry, jitter, attempts, and age. Delivery is fenced and externally at-least-once with a stable
idempotency identity.

### TB6 - artifacts

PostgreSQL metadata and scoped opaque artifact ID authorization precede blob lookup. The filesystem
stores bytes only and cannot grant visibility. Owner-private no-symlink roots, random generations,
0600 staging, fsync/atomic promotion, AES-GCM AAD, ciphertext/plaintext digests, leases, legal holds, and
generation-fenced GC prevent path, substitution, and deletion races. SQLite does not claim external
artifact production parity.

### TB7 - telemetry and audit projection

Telemetry names/outcomes/attributes are closed and bounded. Metric labels reject identifiers. OTLP uses
isolated drop-newest queues, no ambient proxy/redirect, bounded shutdown, and cannot block a request or
transaction. Audit projection is a bounded leased durable outbox with stable `event.id`; queue acceptance
precedes fenced delivered commit, so external delivery is at-least-once and deduplicated downstream.
Missing OTLP is never evidence that no durable event occurred.

### TB8 - administration

Retention cleanup, migration, catalog repair, restore, and key rotation are not public protocol
operations. Operator APIs use explicit configuration, fixed search paths, bounded batches, offline or
exclusive checks, sealed migration revisions, and append-only upgrades. Backup material includes
protected proofs and keys and must be secured as migrator authority.

### TB9 - OIDC identity keys

`HttpJwksProvider` accepts only HTTPS, disables ambient proxies and redirects, bounds streamed bytes,
status, cache freshness, key count, key ID, token/header/claim sizes, lifetime, issuer, audience, and
algorithms. Startup eagerly fetches and validates an initial snapshot before serving. Unknown-key refresh
is rate-limited and singleflight; a failed refresh fails authentication rather than accepting an
unverified token. Cached keys remain bearer authority until their bounded freshness expires. Compromise
of the external issuer/CA or malicious but correctly signed identity remains an IdP governance risk.

## STRIDE analysis and executable controls

| Category | Threat | Enforced control | Repeatable evidence |
|---|---|---|---|
| Spoofing | Forged forwarding, request, trace, bearer, or mTLS identity | Strip caller correlation/forwarding authority; verify bearer or peer cert; server-owned principal | `auth`, `server`, `tls_integration`, `authorized_gateway_process` |
| Spoofing | Malicious/stale JWKS or issuer impersonation grants bearer identity | HTTPS-only no-proxy/no-redirect fetch; issuer/audience/RS256/key validation; bounded freshness; fail-closed refresh | `auth_evidence`, `auth_vertical`, OIDC rotation runbook tests |
| Spoofing | Reverse proxy headers establish identity | Proxy is transport only; loopback+OIDC required; forwarding headers stripped/ignored for principal derivation | `tls_config::reverse_proxy_is_loopback_only_and_requires_oidc`, auth ingress tests |
| Spoofing | Cross-tenant selector/account/task access | Strict policy membership, scoped capabilities, forced RLS, selector ambiguity rejection | `authorization_policy`, `authorized_durable_protocol`, `tenant_persistence`, issue #74 corpus |
| Spoofing | Stale lease/correlation generation impersonates current work | DB-time owner/token/epoch fences; tenant+dispatch+generation telemetry key | `postgres_multi_replica`, `dispatch_correlation_tests`, issue #73 evidence |
| Tampering | Ambiguous/duplicate JSON or REST widening | Exactly-one field-presence unions, duplicate/unknown rejection, invalid REST status failure | `protocol_fuzz_regressions`, `server`, `fuzz/protocol_json` |
| Tampering | Forged page/callback token or cross-scope replay | Bounded base64/MAC parser, query/scope/key-generation binding, uniform errors | issue #74 token corpus, SQLite/PostgreSQL pagination tests |
| Tampering | Partial or corrupt durable state across crash | Atomic admission/lifecycle transactions, sealed migrations, restart validation, exact replay | `atomic_lifecycle`, `sqlite_store`, `postgres_store`, issues #17/#75 process matrices |
| Tampering | Artifact path/blob/manifest substitution | Opaque scoped IDs, no caller path, AEAD AAD, length and digest verification, immutable generations | `artifact_storage`, `postgres_artifact_process`, `ARTIFACT_RUNBOOK.md` |
| Tampering | JWKS response, cache metadata, redirect, proxy, or oversized key set changes verifier authority | Bounded streaming/keys/TTL, strict JOSE fields, no redirects/proxy, singleflight atomic snapshot replacement | `auth_evidence` malformed/rotation/outage tests |
| Repudiation | Tenant denies an authorization/quota/callback/operator action | Digest-only append-only audit facts in causative transaction; policy/revision/digest/actor binding | issues #14/#17/#72 evidence, `telemetry_audit_projection` |
| Repudiation | External projection redelivery appears as distinct action | Stable domain-separated `event.id`; durable pending/leased/delivered/dead state | issue #16 evidence, `postgres_observability_process` |
| Information disclosure | Secrets, tenant names, URLs, DSNs, SQL, errors, artifact locators leak | Closed errors/Debug, canary scans, correlation-only spans, no identifier metric labels, private evidence | `telemetry_schema`, `telemetry_golden`, auth/push/artifact redaction tests, issues #74/#75 validators |
| Information disclosure | Cross-tenant pagination, artifact, transcript, callback, or audit visibility | Scoped authority interfaces, forced RLS, query/scope digests, opaque IDs, no public audit-read API | `authorized_durable_protocol`, `authority_row_parity`, artifact/callback authority tests |
| Denial of service | Oversized bodies, events, outputs, streams, pagination, active work | Pre-parse body bound; event/output/active budgets; frozen snapshot caps; request deadlines | `server`, `executor`, `store`, quota and issue #75 load evidence |
| Denial of service | Malformed-selector audit flood or retained audit growth | O(1) SQLite singleton accounting; exact count/byte caps; operator-only bounded PostgreSQL cleanup | issue #72 evidence and runbook |
| Denial of service | One workload exhausts runtime trace or telemetry correlation | Process and per-workload windows; atomic completed-window retirement; attempt-scoped bounded correlation | issue #73 evidence, `runtime_gateway_shutdown` |
| Denial of service | Slow callback/collector/consumer or network outage blocks healthy work | Isolated bounded queues/workers, transport deadlines, renewals/fences, tenant canaries, fail-open OTLP | issues #17/#75 process matrices, `telemetry_outage` |
| Denial of service | JWKS endpoint outage, unknown-key refresh storm, or reverse-proxy saturation denies service | Eager startup validation, bounded cached freshness, rate-limited singleflight refresh, body/time bounds; deployment proxy capacity/health | `auth_evidence` provider outage/refresh tests, transport startup tests |
| Elevation of privilege | Caller-set tenant GUC grants cleanup/projection/operator capability | Runtime execute revoked; migrator-only API/proof; fixed search path; catalog/grant validation | `postgres_authorization_retention`, `postgres_store`, issue #72 review |
| Elevation of privilege | Runtime event directly publishes completion or evidence | Processor sink cannot grant policy evidence; completion policy independently validates canonical evidence | `executor`, `runtime_worker`, completion-policy tests |
| Elevation of privilege | Filesystem blob or Agent Card metadata grants authority | PostgreSQL metadata/scoped join is authority; Agent Card is discovery only | artifact authority tests, agent-card/auth tests |

## Abuse and recovery qualification

- Issue #72 / PR #76: bounded denial-audit accounting and operator-only retention.
- Issue #73 / PR #77: bounded runtime trace and tenant/attempt-scoped telemetry correlation.
- Issue #74 / PR #78: deterministic protocol/policy/state/token properties, minimized corpora, and four
  nightly fuzz targets.
- Issue #75 / PR #79: synchronized offender/canary load, slow consumers, blackhole/reset/heal, RSS/FD/DB
  bounds, SIGKILL RPO/RTO, PostgreSQL failover/fencing, callback/artifact/observability recovery, dynamic
  evidence, and leak checks.

Client-acknowledged durable mutations have RPO 0. The published qualification RTOs and generated report
schemas are in `docs/CHAOS_QUALIFICATION.md` and `evidence/m2/issue-75.md`.

## Residual-risk register and M2 acceptance

The following are explicitly accepted for M2 and must not be silently upgraded into stronger claims:

1. Runtime trace is a bounded recent-window artifact. SIGKILL may lose the current in-memory capture;
   durable task/outbox/audit/callback/artifact state remains truth.
2. OTLP is bounded and lossy. Audit projection is durable but collector delivery is externally
   at-least-once and requires deduplication by stable `event.id`.
3. Callback delivery is externally at-least-once. Endpoint business effects require the stable
   idempotency identity.
4. PostgreSQL authorization retention is operator-scheduled. Disabled/undersized scheduling remains an
   operational growth risk and must alert.
5. SQLite startup audit reconciliation is O(n), intentionally outside the steady-state request path.
6. PostgreSQL committed-response-loss is represented by ambiguity/failover evidence, not a PostgreSQL
   wire-protocol fault parser.
7. Linux CI RSS/FD/latency and scheduled tests are qualification signals, not production sizing or
   multi-day soak evidence.
8. Host reboot, disk-full/fsync failure, physical packet corruption, kernel/hypervisor compromise,
   cgroup OOM, and external IdP/CA/DNS/collector administration remain deployment responsibilities.
9. Reverse-proxy mode trusts the deployment proxy and loopback host boundary for transport confidentiality,
   integrity, availability, request normalization, and source policy. The gateway still derives identity
   only through OIDC.
10. Cached JWKS keys remain bearer authority for their bounded freshness. A compromised issuer or CA can
    issue identities accepted by the configured policy until operator/issuer remediation.
11. Forced runtime cancellation cannot retract model, tool, network, or storage effects already issued;
    durable runtime effect deduplication is not provided by the bundled processor.
12. Task-bound tasks, idempotency, outbox/receiver rows, transcripts, cancellation records, and associated
    quota evidence currently have no deletion lifecycle. Retained-authority capacity and operational
    storage monitoring remain required.
13. A terminal authorization projection state of `dead` permits source cleanup even though export failed;
    the durable dead projection and retention diagnostics are the remaining evidence.
14. No external telemetry-backend retention or tenant ACL configuration is claimed; audit read is
    OTLP-only. Kill-after-downstream-accept ambiguity is composed from authority lease/idempotency tests,
    not one production collector process cut.
15. Full 65,536-row/64 MiB SQLite authorization-audit startup reconciliation timing is unmeasured;
    operators must budget and monitor startup because the deliberate O(n) tamper scan is outside the
    steady-state request path.
16. SQLite is local single-writer compatibility and does not claim PostgreSQL multi-replica, callback,
    or external-artifact production parity.
17. Review/test issuer labels prove configured policy membership and binding, not real-world identity.
    Deployment-specific authenticated evidence issuers, revocation, and durable freshness remain required.
18. Cryptographic security depends on protecting key material/backups and on the stated SHA-256,
    AES-256-GCM, HMAC, TLS, and signature assumptions.

Any change that crosses TB1-TB9, adds a new authority field, widens an enum/schema, creates an unbounded
queue/cardinality source, or changes RPO/RTO requires an updated threat row, executable regression, and
independent exact-tree review.
