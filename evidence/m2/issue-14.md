# Issue #14 — distributed quota evidence

## Outcome of this implementation pass

The quota authority now includes pre-dispatch execution reservation/settlement, materialized retained-byte accounting, coordinated evidence-chain retention/GC, tenant-fair bounded claiming, explicit audited lower-limit reconciliation, and a production-wire two-process abuse/outage/fairness/failover matrix. PostgreSQL startup validates the exact catalog, materialized/oracle equality, retained evidence links, execution/lease semantics, policy lineage, and digest-sealed reconciliation audits.

Implemented and exercised:

- Authorized `taskGet` and every first/frozen `taskList` page apply the server-derived quota intent before the indexed read and append the allow/existence-safe deny authorization audit in the same retryable transaction. A conflicting audit proves the list charge rolls back.
- `QuotaLeaseKind::{MessageStream,TaskSubscription}`, backend authority capability, and forced-RLS PostgreSQL `quota_leases` state with opaque lease ID/token/epoch, DB-time expiry, semantic resource digest, scope-leading active index, catalog inclusion, and startup semantic validation.
- Tenant, account, and principal limits are mandatory for every dimension. Every intent emits all three server-derived scopes in canonical order; stream/subscription gauges are acquired atomically across independent pools before any existence read or SSE headers.
- Canonical UTF-8 JSON bytes and event count are charged before unary task/get/list/cancel responses, replay frames, stream frames, and subscription frames leave the handler. Output/event exhaustion fails before that response/frame is yielded.
- Quota exhaustion rolls the quota/workflow/read transaction back and writes one independent digest-only denial record. The decision key is exact-idempotent; conflicting content fails closed; audit failure is converted to quota-authority unavailable.
- `QuotaExceeded` carries a clamped `retryAfterSeconds` value (`1..=3600`), remains JSON-RPC `-32010`, maps REST to 429, and the durable protocol layer adds bounded `Retry-After`. Authority unavailable remains `-32011`/503 in the quota preflight paths.
- Static overrides remain server-only and exact-scope/operation/dimension. Activation rejects a stale `oldLimit`, hard-cap violations, non-visible actor/reason text, and overlapping intervals for the same identity; cross-scope intervals are independent and deterministic.
- `postgres_quota_process` launches two authenticated mTLS gateway binaries with distinct PIDs, sockets, pools, replica IDs, and one shared PostgreSQL authority. Named READY/GO checkpoints prove exact cross-replica request winners, tenant-B bounded progress, spoof resistance, pre-SSE last-slot denial, disconnect release, real 30-second DB-time crash expiry/reclaim, reconnect exhaustion, fail-closed denial-audit outage, digest-only evidence, and stderr redaction.
- Quota-capable streaming replay now preserves `AdmissionOutcome::Replay` when deriving reconnect policy. Both JSON-RPC and REST durable handlers preflight stream errors; vendored `a2a-server-lf` maps only quota preflight codes to HTTP 429/503 before SSE headers.
- Retained-principal accounting now preserves canonical task-owner and quota-intent attribution inside migrator-owned global claim procedures. The root cause was forced RLS hiding the task row during `claim_outbox_bounded`: the outbox lease update changed retained bytes while `retained_principal` temporarily resolved to `NULL`, producing the first 79-byte drift in the minimal claim test (93 bytes in the richer lifecycle) and a later `InvalidSchema` on restart. Two narrow read-only `claim-v1` policies expose only the immutable attribution sources to that bounded procedure.
- The PostgreSQL row-parity regression now independently totals every measured table for tenant and principal scopes, reopens cleanly, then corrupts the principal materialization by one byte and proves startup still rejects it with `InvalidSchema`.
- Reconciliation no longer copies gauges or refundable task output/event reservations into a new policy digest. Current-policy admission locks its own point bucket and derives cross-version live work, nonexpired leases, and unsettled reservations from authoritative rows; old completion settles only the original bucket. The restart regression proves the new policy begins at zero, blocks while the old reservation is live, stays zero after old settlement, and admits afterward.
- The singleton scheduler row was replaced by retained forced-RLS per-tenant rows ordered by virtual finish and monotonic served sequence. Eligible selection uses `FOR UPDATE OF s SKIP LOCKED LIMIT 1`; parallel independent stores claim different tenants, and claim/cursor/attempt state remains one transaction.
- Runtime-role startup validation now recursively checks the actual login and generated role before first migration and after catalog sealing, including PG17 admin/inherit/set edge options, cycles/nesting, and reachable privilege attributes. Nested `BYPASSRLS`, unexpected sealed membership, and admin-option poisoning all fail closed with cleanup.
- Lease expiry maintenance is an explicit validated 100-row operation batch over the `(tenant_scope,state,lease_until,lease_id)` index with ordered `FOR UPDATE SKIP LOCKED LIMIT`; no operation performs an unbounded expired-lease update.
- Populated default-planner EXPLAIN probes assert exact bucket, lease target/reclaim, retained-counter, eligible-scheduler, and within-tenant index names. The reviewed claim procedure is fragment-checked and pinned to canonical SHA-256 `d5ccf89ab192d316fbfb3f9706b3d98147fcbf266a2c718ddf162a8ecea0df6c`.
- Vendored protocol patches cover `a2a-lf` named quota code/status/reason constants, `a2a-server-lf` streaming-preflight JSON-RPC HTTP mapping, and the reviewed in-memory task-list pagination overflow/out-of-range fix. Upstream archives are `a2a-lf 0.3.0` SHA-256 `7fb24275cca126dc3301d272eef07bd4cefd87f9a7dd5d6f27200fe87e8a83d0` and `a2a-server-lf 0.4.1` SHA-256 `c4df08dff9607c4045c892b58f3824bb215262a37bce33f1ab42a72a5c9acd51`. Current patched file SHA-256 values: `a2a-lf/src/errors.rs` `da72256d00d6ced608773e1f72c32155f046840f81484484a2e3b46b1cf66a76`; `a2a-server-lf/src/jsonrpc.rs` `fb418c13dee2f8f86819750cfc906c0b29381ebd662a763d5270d3afbf4a0774`; `a2a-server-lf/src/task_store/inmemory.rs` `3e914b52fc03e37f2f506c1019a303dfc61db130b23f3e8ceb56328413f0ac69`.

## RED → GREEN additions

1. `list_quota_charge_rolls_back_when_the_atomic_audit_write_conflicts`
   - RED: list charge committed before the list/audit transaction (`used_units=1`).
   - GREEN: conflicting audit rolls the list transaction and charge back (`used_units=0`).
2. `two_independent_stores_cannot_oversubscribe_one_stream_lease_and_release_is_fenced`
   - RED: lease types/capability/store methods absent.
   - GREEN: one winner at a one-slot boundary; forged token and duplicate release are stale.
3. `crash_expiry_reclaims_slot_and_stale_holder_cannot_renew_or_release`
   - GREEN: exact injected DB-time expiry permits replacement without sleeps; old holder is fenced.
4. `egress_intent_charges_canonical_bytes_and_events_at_both_scopes`
   - RED: egress operation/intent absent.
   - GREEN: tenant+principal output-byte and event-count charges are closed typed dimensions.
5. `quota_exceeded_retry_after_is_bounded_and_stable_on_the_wire`
   - GREEN: stable `-32010`/429 and clamped typed retry metadata.
6. `expired_override_is_ignored_on_a_live_database_time_decision`
   - GREEN: live override exhausts at the exact effective instant, denial is durable, and baseline capacity resumes at exact expiry.

## Verified commands

```text
cargo test --test quota_policy                                      PASS (10)
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --test postgres_quota -- --test-threads=1  PASS (29, 35.43s)
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --test postgres_store -- --test-threads=1  PASS (48, 61.92s)
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --test postgres_multi_replica -- --test-threads=1  PASS (2, 8.01s)
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --test authorized_gateway_process production_binary_selects_postgres_and_replays_after_graceful_restart -- --exact --test-threads=1  PASS (11.35s)
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --test postgres_quota_process -- --test-threads=1  PASS (2, 37.79s)
cargo test --locked --all-targets --all-features -- --test-threads=1          PASS (explicit PG17 fixture; current PR #67 rerun)
cargo clippy --locked --all-targets --all-features -- -D warnings              PASS
cargo test --release --locked --all-targets --all-features -- --test-threads=1  PASS (current PR #67 rerun)
cargo clippy --all-targets --all-features -- -D warnings             PASS
cargo clippy --release --all-targets --all-features -- -D warnings   PASS
cargo fmt --all -- --check && git diff --check                       PASS
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps        PASS
RUSTDOCFLAGS='-D warnings' cargo test --doc --all-features           PASS
cargo +1.88.0 check --all-targets --all-features                     PASS
cargo audit                                                           PASS (two documented allowed warnings)
npm audit --audit-level=high --prefix demo && npm test --prefix demo PASS
cargo run --quiet --bin lifeline-trace -- /tmp/lifeline.trace.jsonl && cmp /tmp/lifeline.trace.jsonl demo/lifeline.trace.jsonl  PASS
```

The PostgreSQL evidence used a tracked local `postgres:17` container on loopback with separate generated migrator/runtime roles. Tests use barriers, injected DB time, exact expiry boundaries, and watchdogs; no test synchronization sleeps/yields were added.

## B4 process/abuse matrix closure

The checked-in matrix is `tests/postgres_quota_process.rs`; CI runs it serially with required explicit URLs and a five-minute watchdog. The real mTLS protocol/process path directly proves output/event exact-boundary `+1` before effects or frames, configured override apply and database-time expiry, retained-cap denial plus bounded GC recovery and concurrent tenant-B progress, in addition to request/reconnect storms, fairness, denial-audit outage, and crash reclaim. The measured run lasts 35.46 seconds because it observes a killed holder through the real 30-second database-time lease horizon without synchronization sleeps or scheduler yields.

## Issue boundaries

- **#15:** external content-addressed artifact storage, manifests/provenance/encryption, and artifact retention/GC. #14 still owns reservation and quota hooks for existing inline output/authority bytes.
- **#16:** OTLP export, dashboards, SLOs, and audit projection. #14 owns authoritative quota/override decision rows.
- **#17:** push callback SSRF/auth/retry work. Push remains disabled.
- **#18:** broad STRIDE/fuzz/load/chaos qualification. #14 still owns its focused quota abuse/failover evidence above.
