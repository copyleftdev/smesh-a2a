# Tenant authorization operator runbook (issue #13)

## Production startup contract

Authenticated task serving is available only in durable SQLite loopback mode. Set:

- `SMESH_A2A_AUTH_MODE=oidc` (or configure required mTLS)
- `SMESH_A2A_AUTHORIZATION_POLICY_PATH=/secure/path/policy.json`
- `SMESH_A2A_SQLITE_PATH=/secure/path/tasks.sqlite3`
- `SMESH_A2A_MODE=loopback`

The policy is loaded and completely validated before the listener and durable/runtime resources are acquired. The file is bounded to 256 KiB and rejects symlinks, unknown fields, duplicate identifiers/bindings, disabled or missing memberships, and human/service role confusion. Authentication-only generic handlers remain development-only because upstream spawned execution does not retain explicit tenant context.

A fresh database is schema v5. Opening an existing v1-v4 database requires both:

```text
SMESH_A2A_LEGACY_TENANT_ID=tenant-a
SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID=legacy-owner
```

The tenant/account pair must be an enabled membership in the loaded policy. Supplying only one variable, using an unenrolled pair, or omitting the pair for a legacy database fails closed. Migration binds every legacy task and child record atomically and appends migration evidence.

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

Verified bearer and mTLS presentations of the same exact issuer and subject resolve to the same account. Fixed roles are `tenantAdmin`, `taskOperator`, `taskViewer`, `auditor`, `taskAgent`, and `serviceReader`. `taskAgent` visibility is owner-only; operator/viewer visibility is tenant-wide subject to the operation matrix.

`X-Smesh-Tenant` is only a selector among enrolled memberships. Duplicate, comma-combined, malformed, inaccessible, and ambiguously omitted selectors receive the same HTTP 403. The header is stripped before protocol parsing. Protocol `tenant` fields and request metadata never grant authority.

## Durable authorization behavior

- New admission writes the resolved tenant and owner and uses a v2 digest/idempotency identity bound to tenant and actor.
- Continuation first performs an owner/tenant-scoped task query, then rechecks the same scope in its write transaction.
- Get, list, cancellation, subscription snapshot, transcript polling, task-event polling, and final-result polling retain explicit scope after the request future returns.
- Foreign and missing tasks return an opaque `TASK_NOT_FOUND`; REST/SSE adapters perform this preflight before opening an event stream.
- List SQL applies tenant/owner scope before filtering and counting. Page tokens are MAC-protected and bind an opaque digest of tenant, account, policy revision/digest, and visibility.
- Allow audits for admission, continuation, and cancellation commit in the mutation transaction. Read/list decisions are appended before data is returned. Denials use resource digests and never store a resolved foreign task ID.
- Outbox envelopes use the claimed lease tenant. Receiver admission validates the envelope against the durable outbox row and never falls back to a caller/default tenant.

Public agent-card discovery remains public. Extended-card access remains authentication protected. Push notification methods remain unsupported before task lookup.

## Operational checks

Run before deployment:

```bash
cargo test --test authorization_policy
cargo test --test tenant_persistence
cargo test --test authorized_durable_protocol
cargo test --test authorized_gateway_process
cargo test --test durable_protocol_vertical
cargo test --test tls_integration
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Audit records are append-only by trigger. Capacity or append failure is fail-closed; mutation transactions roll back rather than committing without the corresponding allow decision.

`authorized_gateway_process` is the deployable-boundary check: it uses required mTLS and a real TLS client identity against the production binary, exercises both public protocol bindings, migrates only with an explicit enrolled legacy tenant/owner, sends SIGTERM, and verifies exact SQLite reopen visibility. The query-plan evidence in `tenant_persistence` is the primary timing-path proof (one scoped indexed lookup for foreign and missing IDs); its broad latency-distribution bound is supplemental and is not a constant-time claim.
