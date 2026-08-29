# Distributed quota operator runbook

## Startup

Distributed enforcement is PostgreSQL-only. Configure authenticated authorized loopback mode plus:

```text
SMESH_A2A_DURABLE_BACKEND=postgres
SMESH_A2A_POSTGRES_MIGRATOR_URL=postgresql://...
SMESH_A2A_POSTGRES_RUNTIME_URL=postgresql://...
SMESH_A2A_POSTGRES_SCHEMA=smesh_authority
SMESH_A2A_QUOTA_POLICY_PATH=/secure/path/quota-policy.json
```

The quota file is opened with no-follow semantics, bounded to 256 KiB, parsed with unknown-field and duplicate rejection, canonicalized, and checked against compiled hard caps before PostgreSQL or gateway resources are acquired. A configured quota file with SQLite fails startup. A PostgreSQL production configuration without the file also fails startup.

## Policy

Use schema `smesh-quota-policy/v1`. Every required limit pair has a tenant and principal positive integer. Request and reconnect windows are positive integer database milliseconds. Limits above hard request/concurrency/byte/event caps, fractional values, duplicate keys, malformed IDs, and ambiguous overrides fail readiness. The checked-in `tests/fixtures/quota-policy.json` is a complete shape example, not a recommended deployment value.

Static overrides must name one override ID, operator actor, bounded reason, scope kind and ID, operation, dimension, old/new limit, effective time, and expiry. They cannot wildcard or exceed hard caps. Activation uses PostgreSQL time. Actor, reason, and target are stored as digests in `quota_override_audits`; policy revision/digest and old/new values remain reviewable.

## Public behavior

- Exhausted renewable quota: JSON-RPC `-32010`, message `quota exceeded`; REST status 429 with bounded integer `Retry-After`; `ErrorInfo.reason=RESOURCE_EXHAUSTED` and typed `retryAfterSeconds`.
- Missing/unavailable authority: JSON-RPC `-32011`, message `quota authority unavailable`; REST status 503; `ErrorInfo.reason=UNAVAILABLE`.
- Streaming JSON-RPC quota preflight uses HTTP 429/503 with a JSON error body before SSE headers; other JSON-RPC application errors retain HTTP 200 semantics.
- Public errors never include tenant, principal, bucket, policy, reservation, or override identifiers.

## Policy revision reconciliation

A persisted policy is immutable. Same-revision/different-digest and revision downgrade startup are refused. A higher revision with any lower baseline limit requires an explicit `QuotaReconciliationPlan::drain` supplied by the server/operator. The plan is bound to the old and new policy digests, a bounded actor and reason, an effective database time, and every exact tenant/scope/dimension being lowered; destructive eviction is not representable.

Startup takes a migration-only advisory fence, reads current materialized usage and bucket/allocation state, and performs zero mutation when the plan is absent, incomplete, not yet effective, or current usage exceeds a new limit (`PostgresStoreError::ReconciliationRequired`). Operators should deny new work and let gauges/leases drain naturally, then retry startup with the same plan. Once usage fits, startup atomically carries fixed-window use and the smaller of old/new token availability into the new digest, preserving refill time/remainder without minting. It marks the old policy `draining`, inserts the active snapshot, and inserts exactly one digest-sealed `quota_policy_reconciliation_audits` row. Old buckets are not deleted: pre-upgrade reservations, allocations, receipts, leases, and replay continue to settle against their original digest. Concurrent replicas serialize and observe one migration. Overrides use the same live bucket capacity fence; expiry returns to baseline without resetting usage.

## Evidence retention and garbage collection

The exact quota replay horizon is 86,400,000 database milliseconds (24 hours). Task-bound intents have `retention_until = NULL`: because tasks, idempotency records, outbox/receiver rows, transcripts, and cancellation records currently have no deletion lifecycle, their intents, receipts, and externally referenced execution reservations are retained. This is intentionally not claimed as task GC. Taskless evidence has an explicit generated retention boundary, but authorization decisions and live leases keep it live.

`gc_quota_authority(max_rows)` accepts only `1..=1000`, uses deterministic child-first `FOR UPDATE SKIP LOCKED` batches, and collects only independently safe rows: expired denial/override audit detail, released/expired stream leases, released allocations, unreferenced settled execution reservations, unreferenced taskless receipts/intents, then stale unreferenced fixed-window or zero gauge buckets. The exact boundary is inclusive (`retention_until <= database time`). Row accounting triggers decrement tenant/principal UTF-8 JSON bytes in the same transaction, so faults roll back deletions and counters together and concurrent collectors are idempotent.

## Operations

Monitor bucket saturation, active allocations, override expiry, PostgreSQL pool/lock timeouts, migration/catalog validation, and hard 64 MiB tenant authority capacity. Never edit migration or policy ledger rows manually. A policy replacement must increase revision and retain a canonical digest; restart does not reset committed buckets or allocations.

Run the deterministic gates:

```sh
cargo test --test quota_policy
cargo test --test postgres_quota -- --test-threads=1
cargo test --test postgres_quota_process -- --test-threads=1
cargo test --test postgres_store -- --test-threads=1
cargo test --test authorized_gateway_process production_binary_selects_postgres_and_replays_after_graceful_restart -- --exact --test-threads=1
```

## Fixture boundary

The checked-in PostgreSQL process suite uses the debug-only loopback plaintext PostgreSQL seam because CI does not provide a trusted PostgreSQL CA fixture. It still uses real mTLS on both public gateway sockets, two independent gateway PIDs/pools/replica owners, and PostgreSQL 17. Release binaries continue to reject plaintext PostgreSQL with `TlsRequired`; this evidence is not mislabeled as release PostgreSQL TLS E2E.
