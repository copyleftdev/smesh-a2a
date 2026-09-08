# Tenant authorization operator runbook (issues #13 and #27)

## Production startup contract

Authenticated task serving is available only in durable loopback mode with either the SQLite
single-writer authority or the PostgreSQL multi-replica authority. Set:

- `SMESH_A2A_AUTH_MODE=oidc` (or configure required mTLS)
- `SMESH_A2A_AUTHORIZATION_POLICY_PATH=/secure/path/policy.json`
- `SMESH_A2A_DURABLE_BACKEND=sqlite` and
  `SMESH_A2A_SQLITE_PATH=/secure/path/tasks.sqlite3`; or
- `SMESH_A2A_DURABLE_BACKEND=postgres`, distinct TLS
  `SMESH_A2A_POSTGRES_MIGRATOR_URL`/`SMESH_A2A_POSTGRES_RUNTIME_URL`,
  `SMESH_A2A_POSTGRES_SCHEMA`, and `SMESH_A2A_QUOTA_POLICY_PATH`
- `SMESH_A2A_MODE=loopback`

The policy is loaded and completely validated before the listener and durable/runtime resources are acquired. The file is bounded to 256 KiB and rejects symlinks, unknown fields, duplicate identifiers/bindings, disabled or missing memberships, and human/service role confusion. Authentication-only generic handlers remain development-only because upstream spawned execution does not retain explicit tenant context. The production listener is bound before opening the selected durable authority, so an occupied bind cannot migrate or recover it.

The current SQLite authority revision is schema v11 and the PostgreSQL authority revision is v11. Opening an older supported SQLite
database that predates tenant binding requires both:

```text
SMESH_A2A_LEGACY_TENANT_ID=tenant-a
SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID=legacy-owner
```

The tenant/account pair must be an enabled membership in the loaded policy. Supplying only one variable, using an unenrolled pair, or omitting the pair for a legacy database fails closed. Migration binds every legacy task and child record atomically and appends migration evidence. PostgreSQL uses sealed append-only migrations, separate migrator/runtime roles, fixed search paths, and forced RLS; legacy binding variables are not supported for PostgreSQL.

## Policy format

```json
{
  "schemaVersion": "smesh-authz-policy/v1",
  "policyId": "gateway-main",
  "revision": 1,
  "tenants": [{"id": "tenant-a", "enabled": true}],
  "accounts": [{
    "id": "agent-a",
    "kind": "serviceAccount",
    "memberships": [{"tenantId": "tenant-a", "roles": ["taskAgent"]}]
  }],
  "principalBindings": [{
    "principal": {"issuer": "https://issuer.example", "subject": "agent-a"},
    "accountId": "agent-a"
  }]
}
```

Verified bearer and mTLS presentations of the same exact issuer and subject resolve to the same account. Fixed roles are `tenantAdmin`, `humanRatifier`, `taskOperator`, `taskViewer`, `auditor`, `taskAgent`, and `serviceReader`. `humanRatifier` is valid only for a `kind: "human"` account and grants tenant-scoped ratification read/review/decide only; it grants no ordinary task, artifact, push, extended-card, or audit operation. `taskAgent` visibility is owner-only; operator/viewer visibility is tenant-wide subject to the operation matrix.

`X-Smesh-Tenant` is only a selector among enrolled memberships. Duplicate, comma-combined, malformed, inaccessible, and ambiguously omitted selectors receive the same HTTP 403. The header is stripped before protocol parsing. Protocol `tenant` fields and request metadata never grant authority.

## Durable authorization behavior

- New admission writes the resolved tenant and owner and uses a v2 digest/idempotency identity bound to tenant and actor.
- Continuation first performs an owner/tenant-scoped task query, then rechecks the same scope in its write transaction.
- Get, list, cancellation, subscription snapshot, transcript polling, task-event polling, and final-result polling retain explicit scope after the request future returns.
- Foreign and missing tasks return an opaque `TASK_NOT_FOUND`; REST/SSE adapters perform this preflight before opening an event stream.
- List SQL uses separate tenant-wide and owner-only indexed query families and pushes context, status, and inclusive timestamp-after filters into SQLite. The first page atomically materializes a five-minute frozen projection: membership, order (`status_timestamp DESC NULLS LAST, task_id ASC`), revisions, history/artifacts, and `totalSize` cannot change while traversing it.
- Page tokens are 32-byte URL-safe opaque HMAC-derived capabilities. SQLite stores only SHA-256 token hashes. A snapshot metadata HMAC binds the snapshot ID, normalized query/projection, authorization-scope digest, page/total/frozen-byte/version/key-generation/time fields, and every ordered frozen entry identity/digest/revision. Exact token positions are `P, 2P, ... < N`; startup and follow-up recompute the metadata and complete token chain from the durable cursor key in fixed time. Tokens are retry-safe, survive restart, and malformed, expired, cross-scope, cross-query, unknown, or corrupt tokens all return `invalid pageToken`. Expired snapshots are removed transactionally; active snapshot count and frozen UTF-8 bytes are capped.
- Allow audits for admission, continuation, and cancellation commit in the mutation transaction. Read/list decisions are appended before data is returned. Denials use resource digests and never store a resolved foreign task ID.
- Outbox envelopes use the claimed lease tenant. Receiver admission validates the envelope against the durable outbox row and never falls back to a caller/default tenant.

Public agent-card discovery remains public. Extended-card access remains authentication protected. Push notification methods remain unsupported before task lookup.

## Human-ratification authorization boundary

Setting `SMESH_A2A_RATIFICATION_HMAC_KEY_PATH` installs issue #27's public data-free console and
protected ratification API only when the production gateway is authenticated, authorized, durable,
in `loopback` dispatch mode, and bound to an actual loopback IP. SQLite and PostgreSQL are supported.
The protected routes derive actor, tenant, principal, authentication method, and policy identity from
the server-owned authorization context. Authentication and `humanRatifier` authorization run before
Origin, exact content type, opaque actor/view-bound strong ETag precondition, idempotency, and JSON
feedback.

Review and decision must be performed by the same human account. Receipts and authorization audits
are immutable and commit atomically with task/publication effects; PostgreSQL forced RLS still scopes
runtime access by tenant. Public bootstrap does not disclose task existence or tenant data. Exact
enablement, key-file, route/status, stale-tab, restart, migration/rollback, and browser qualification
contracts are in [`HUMAN_RATIFICATION_RUNBOOK.md`](HUMAN_RATIFICATION_RUNBOOK.md). Those contracts are
issue #27/M3 readiness evidence pending merge and CI, not a release or milestone-completion claim.

## Operational checks

Run before deployment:

```bash
cargo test --test authorization_policy
cargo test --test tenant_persistence
cargo test --test authorized_durable_protocol
cargo test --test authorized_gateway_process
cargo test --test human_ratification -- --nocapture
cargo test --test human_ratification_process -- --nocapture
cargo test --test postgres_ratification -- --nocapture
cargo test --test durable_protocol_vertical
cargo test --test tls_integration
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Audit records are append-only by trigger. Capacity or append failure is fail-closed; mutation transactions roll back rather than committing without the corresponding allow decision.

`authorized_gateway_process` is the deployable-boundary check: it uses required mTLS and a real TLS client identity against the production binary, exercises both public protocol bindings, migrates only with an explicit enrolled legacy tenant/owner, sends SIGTERM, and verifies exact SQLite reopen visibility. The query-plan evidence in `tenant_persistence` is the primary timing-path proof (one scoped indexed lookup for foreign and missing IDs); its broad latency-distribution bound is supplemental and is not a constant-time claim.
