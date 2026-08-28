# Milestone 2 evidence — issue #62

## Delivered

- Executable PostgreSQL logical schema v6 migration with all 17 authority tables, migration ledger, canonical JSON `TEXT`, millisecond `BIGINT`, persisted 32-byte keys, tenant composite relations, checks/indexes, immutable identity and append-only audit triggers.
- Advisory-lock transactional bootstrap plus startup validation of version/checksum, persisted exact catalog manifest (columns, constraints, indexes, trigger/function bodies, RLS, grants, role membership), and semantic task/payload/frame/transcript/snapshot seals.
- Bounded `deadpool-postgres` adapter with separate migrator/runtime URLs. Migration/admin connectivity is dropped before the runtime-only pool is built; the runtime login is attribute-validated and receives only membership in the generated schema role. Fixed-search-path, least-return `SECURITY DEFINER` procedures own global claim/cancellation/diagnostic operations without exposing global rows.
- Exact delivery/receiver/transcript parity hardening: final-attempt expiry is reconciled atomically, delivery fences the causative revision and immutable public prefix, progress is Working-only/idempotent/sealed, receiver admission is authoritatively outbox-bound and interrupted outcomes replay as `ReplayOutcome`, transcript reads validate missing/cursor/count/digest/terminal semantics, and subscription events emit SQLite-equivalent status/artifact deltas.
- Durable HMAC-authenticated frozen pagination with fixed projection/order/revisions/total, token-hash-only storage, restart replay, tamper/query binding, database-clock expiry, independent GC, and bounded snapshot count/bytes.
- Reusable direct-row logical dump parity for all 17 authority tables. Dispatch IDs are compared exactly. Snapshot aliases derive from ordered frozen semantic content, while lease/page/snapshot capabilities use deterministic semantic aliases rather than presence booleans. The scenario now persists and replays an `AuthRequired` termination JSON/`ReplayOutcome`.
- Transaction-scoped advisory capacity locking now begins before every retryable authority operation, and the centralized runner checks the complete tenant aggregate before commit on every tenant-scoped return path, including replay/get/list audits, continuation replay, progress, receiver admission/reclaim/completion, cancellation early returns, and all terminal updates. The aggregate inventories variable-width bytes in every tenant table. Global outbox claim/expiry checks every affected tenant before commit. Independent pools prove exact-one winners at both the task cap and the 64 MiB snapshot/audit aggregate boundary, with the loser fully rolled back.
- Production lease and cancellation arbitration uses one `effective_now` helper backed by `db_millis()` inside the same transaction. Caller time is trusted only by the explicit loopback deterministic-test seam. Outbox claim/finish/delivery and receiver claim/reclaim/completion ignore extreme caller skew in production mode.
- A direct generated-runtime forgery probe sets `diag-v1`, `claim-v1`, and `cancel-v1` after `SET ROLE` and still sees only its tenant (or zero rows with empty tenant context). Internal policies require exact canonical migrator/function-owner identity in addition to the operation GUC. The migration SQL-literal-escapes the new `__MIGRATOR__` placeholder; runtime membership in migrator is rejected. Catalog sealing includes function owners and exact policy expressions, while startup independently validates all SECURITY DEFINER owners and fixed `search_path=pg_catalog`; poisoned owners/policies fail closed.
- A three-attempt whole-transaction runner now owns every retry-safe mutating authority command from its first read through commit: authorization replay/audit, admission, continuation, authorized get/list and snapshot GC/materialization, outbox claim/finish/progress/delivery, receiver begin/complete, and cancellation. Each attempt acquires a fresh pooled client/transaction and reapplies bounded local context; only body errors whose PostgreSQL source SQLSTATE is `40001` or `40P01` retry, while commit ambiguity, validation/conflict/capacity, pool/connect, schema, and JSON encoding errors do not. Deterministic retry, exhaustion, non-retryable, pre-commit ambiguity, and independent-store winner probes remain bounded to three attempts with no backoff. A static allowlist test rejects any new direct mutating `.transaction()` path.
- PostgreSQL 17 CI service; PostgreSQL tests are mandatory only in its dedicated job.

## Repeatable evidence

```sh
SMESH_TEST_POSTGRES_SUPERUSER_URL='postgresql://postgres:<fixture-password>@127.0.0.1:55432/smesh_test' \
SMESH_TEST_POSTGRES_ADMIN_URL='postgresql://smesh_migrator:<migrator-password>@127.0.0.1:55432/smesh_test' \
SMESH_TEST_POSTGRES_RUNTIME_URL='postgresql://smesh_test_runtime:<runtime-password>@127.0.0.1:55432/smesh_test' \
SMESH_POSTGRES_TEST_REQUIRED=1 \
cargo test --locked --test postgres_store -- --test-threads=1
```

The suite exercises:

1. empty-server executable migration and reopen key identity;
2. the shared command-level durable-authority conformance harness;
3. two simultaneous openers under the advisory migration lock;
4. startup rejection after catalog/index or semantic task-event mutation, with the same manifest covering columns, constraints, triggers/functions, policies, grants, and roles;
5. privileged pre-created role poisoning rejection, a real non-superuser migrator, runtime DDL/escalation denial, forced-RLS missing-context failure, transaction-context clearing, and injection-shaped bound context;
6. real migration privilege-fault rollback, outage/redaction and deterministic pool saturation timeout;
7. final-attempt expiry reconciliation, interrupted receiver replay, frozen multi-page restart replay, token/query binding, and populated cancellation/outbox/function `EXPLAIN` assertions;
8. panic-unwind RAII cleanup and a common 30-second watchdog around every PostgreSQL integration test.

Local PostgreSQL 17.11 result after final hardening: **31 passed, 0 failed** (serialized, required fixture), repeated both as the focused PostgreSQL target and inside the full all-target/all-feature gate. `cargo fmt --check`, Clippy `-D warnings`, `git diff --check`, and the full serialized all-target/all-feature suite with PostgreSQL required all passed.

## Honest boundaries

This issue exposes a public, tested adapter but does not wire production gateway selection. TLS is required by production configuration; the local/CI plaintext service uses an explicit loopback-only test switch. Multi-replica driver lease renewal/failover is #63; quota policy is #14; PostgreSQL HA/backup provisioning is external.
