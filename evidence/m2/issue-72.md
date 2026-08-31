# Issue #72 Evidence — Bounded Authorization Denial Auditing

Parent qualification gate: #18

## Closed risks

- SQLite denial appends no longer perform a full `authorization_decisions` count/byte scan per request.
- Count and encoded UTF-8 byte limits reject before source-row mutation.
- PostgreSQL authorization decisions have a tenant-scoped, age-gated, projection-safe, batch-bounded maintenance authority.
- Runtime roles cannot directly update/delete decisions or mutate retention diagnostics.
- Malformed and duplicate selector floods retain digest-only reasons, omit raw selector canaries, and preserve healthy enrolled-tenant canary progress.

## SQLite evidence

Schema version 9 introduces `authorization_decision_accounting`, a singleton count/byte ledger maintained in the same transaction as every authorization-decision insert.

Verified invariants:

- accounting lookups use the singleton integer primary key;
- normal append/count SQL does not scan `authorization_decisions`;
- the 65,536-row and 64 MiB limits reject before insertion;
- trigger and preflight accounting agree on UTF-8 bytes;
- v8-to-v9 migration backfills multibyte rows exactly;
- reopen rejects schema or accounting-value tamper;
- startup/reopen performs the only intentional full reconciliation;
- 128 hostile selector denials plus baseline denials persist exact reason counts with no raw hostile canary;
- healthy `tenant-a` requests complete inside a 250 ms watchdog throughout the flood.

Focused commands:

```bash
cargo test --locked --test authorization_policy selector_denials_append_digest_only_durable_audits -- --exact
cargo test --locked --test tenant_persistence
cargo test --locked --test atomic_lifecycle
```

Observed results:

- selector denial/fairness: 1/1 passed;
- tenant persistence/migration: 14/14 passed;
- atomic lifecycle/migration: 45/45 passed.

## PostgreSQL evidence

Append-only migration revision 9 adds:

- `cleanup_authorization_decisions(retention_ms,max_rows)` with fixed `pg_catalog` search path;
- maximum batch size 1,000;
- database-time cutoff and maximum retention horizon validation;
- tenant context enforcement;
- projection obligation check: pending/leased rows block source deletion;
- terminal `delivered`/`dead` or absent projections permit deletion;
- per-tenant bounded diagnostics;
- explicit PUBLIC revocation and runtime-role execution grant;
- revision/checksum/catalog sealing and privilege-tamper detection.

The deterministic matrix seeds eight tenants with old terminal, absent, pending, and live decisions. Repeated limit-1 cleanup deletes exactly two eligible rows per tenant, preserves pending/live rows, never changes another tenant, survives restart, and records exact diagnostics.

Focused commands:

```bash
SMESH_POSTGRES_TEST_REQUIRED=1 \
  cargo test --locked --test postgres_authorization_retention -- --test-threads=1
SMESH_POSTGRES_TEST_REQUIRED=1 \
  cargo test --locked --test postgres_store -- --test-threads=1
cargo test --locked --test telemetry_audit_projection -- --test-threads=1
```

Observed results:

- authorization retention: 3/3 passed;
- PostgreSQL store: 62/62 passed after the integrated parity fix;
- audit projection: 10/10 passed.

## Quality gates

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo +1.88.0 check --all-targets --all-features
git diff --check
```

Focused formatter, Clippy, and diff hygiene passed before integration. Full exact-tree gates and independent reviews are recorded on the pull request.

## Residual risks

- PostgreSQL cleanup is operator-scheduled, not automatic. Deployments must monitor cleanup cadence, maximum-batch saturation, blocked projection rows, and durable storage growth.
- Terminal projection state `dead` allows source decision cleanup; the durable dead projection and retention diagnostics remain the evidence of failed export.
- SQLite startup reconciliation is O(n) by design and remains outside the hostile request path. Startup-at-capacity timing belongs to issue #75.
