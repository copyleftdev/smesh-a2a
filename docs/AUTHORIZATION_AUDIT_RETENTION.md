# Authorization Audit Retention

This runbook defines the bounded authorization-audit maintenance boundary introduced for issue #72 and required by the issue #18 hostile-load qualification.

## Security model

Authorization decisions remain append-only during their live retention window. Public and normal runtime SQL roles cannot update or delete source decisions. PostgreSQL cleanup is available only through the fixed-search-path `cleanup_authorization_decisions` security-definer routine and the typed `PostgresTaskStore::cleanup_authorization_decisions` maintenance API.

Cleanup is tenant-scoped and requires:

- a retention horizon from 0 through 315,576,000,000 milliseconds;
- a batch size from 1 through 1,000 rows;
- source decision age at or before the database-time cutoff;
- no non-terminal audit projection row for the source decision.

A projection row in `delivered` or `dead` state is terminal. An absent projection row means projection was disabled at insertion or its terminal row was already removed by projection retention. Pending or leased projection rows block source cleanup.

The maintenance API is an in-process operator boundary. It is not exposed as an A2A, REST, or JSON-RPC operation and must not be wired to caller-controlled tenant input without a separate administrative authorization policy.

## SQLite boundary

SQLite schema version 9 adds a singleton authorization-decision accounting row. Triggers maintain exact decision count and encoded UTF-8 byte totals transactionally. Each append performs an indexed singleton lookup and rejects a row before insertion when either limit would be exceeded.

Normal append and count paths do not scan `authorization_decisions`. Startup, migration, and reopen validation deliberately perform a full reconciliation to detect counter or table tampering before readiness.

Limits:

- decisions: 65,536;
- encoded audit identity bytes: 64 MiB.

When the limit is reached, authorization fails closed with no audit-table or accounting mutation. Operators must rotate or replace the bounded SQLite authority rather than deleting append-only decisions.

## PostgreSQL operation

Call cleanup repeatedly until `deleted` is zero:

```rust
let result = store
    .cleanup_authorization_decisions("tenant-a", retention_ms, 1_000)
    .await?;
```

The result reports:

- rows deleted in this call;
- rows blocked by non-terminal projection;
- remaining live rows;
- oldest remaining decision time;
- database-time cutoff.

Per-tenant diagnostics retain run count, total deleted rows, last bounded batch, blocked count, live count, cutoff, and run time. Direct runtime access to diagnostics and source deletion remains denied.

## Scheduling

Revision 9 intentionally does not create an automatic scheduler. The deployment control plane must invoke cleanup per enrolled tenant. Recommended defaults:

- retention horizon: at least the organization audit requirement;
- batch size: 1,000;
- cadence: frequent enough that arrival rate multiplied by cadence cannot exceed the retained-row budget;
- alert when repeated runs delete the maximum batch or `projection_blocked` remains non-zero.

Do not shorten retention merely to satisfy storage pressure. Increase maintenance frequency or durable storage capacity instead.

## Verification

```bash
cargo test --locked --test authorization_policy selector_denials_append_digest_only_durable_audits -- --exact
cargo test --locked --test tenant_persistence
SMESH_POSTGRES_TEST_REQUIRED=1 \
  cargo test --locked --test postgres_authorization_retention -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Required evidence:

- O(1) SQLite query plans use the singleton primary key and never scan the decision table during append/count;
- exact count/byte boundary rejection occurs before mutation;
- v8-to-v9 multibyte counter backfill is exact;
- malformed and duplicate selector floods preserve healthy-tenant progress and contain no raw canaries;
- PostgreSQL cleanup is batch-bounded, tenant-isolated, projection-safe, restart-safe, and catalog-sealed;
- public/runtime mutation attempts fail.

## Residual risks

- PostgreSQL retention is operator-scheduled; a disabled or undersized maintenance schedule can still permit durable growth. This is an operational configuration failure and must be monitored.
- Terminal `dead` projection state permits source cleanup even though export did not succeed. The durable dead state and projection diagnostics are the retained evidence of that accepted export failure.
- SQLite startup reconciliation remains O(n), intentionally outside the hostile steady-state request path. Startup time at maximum capacity is measured in the issue #18 load/chaos track.
