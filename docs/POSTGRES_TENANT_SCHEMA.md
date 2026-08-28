# PostgreSQL schema-v6 durable authority

The executable PostgreSQL authority is implemented by `PostgresTaskStore` and the checked-in migration at `migrations/postgres/0001_authority_schema_v6.sql`. The older `reference/postgres_v2_logical_schema.sql` is retained only as historical design input and must not be applied.

## Physical parity

The migration creates the 17 schema-v6 authority tables plus `schema_migrations`. Canonical JSON is stored as validated `TEXT`, timestamps are signed `BIGINT` milliseconds, cryptographic cursor/receipt keys are 32-byte `BYTEA`, and idempotency remains keyed by `(tenant_scope,message_id)`. Tenant-leading composite keys, foreign keys, immutable-identity triggers, append-only audit triggers, bounded checks, and the eight list query-family indexes are installed transactionally.

`PostgresTaskStore::open` accepts distinct migrator and runtime URLs, validates both before acquisition, takes a transaction-scoped advisory migration lock, applies the baseline atomically, and verifies a migration checksum plus a persisted manifest over relations, exact columns/types/defaults, constraints, indexes, trigger/function bodies, policies, grants, role attributes, and membership. It also scans complete task-event chains (sequence, revision, transitions, typed JSON and current-row equality), task identities/state/timestamps, payload and frame digests, transcript seals, and frozen-snapshot metadata before opening a bounded runtime-only pool. The migrator connection is dropped before the pool is built. Reopen preserves key/store identity. Unexpected or mutated managed catalog or semantic state blocks startup.

Task admission and every aggregate byte/snapshot capacity decision are transaction-advisory-lock serialized across independent pools. Payload-bearing authority rows are checked with PostgreSQL `octet_length` against the 64 MiB UTF-8 budget before mutation commits. Frozen pages persist projected task JSON, revisions, order, total, metadata HMACs, and only SHA-256 hashes of HMAC-derived opaque page capabilities; page replay remains fixed across task mutation and process restart.

## Security and roles

The migration creates a schema-specific `NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION` group role. It grants the bounded runtime login non-admin membership for `SET LOCAL ROLE`, while PostgreSQL records the non-superuser migrator that created the role with admin-option membership so it can validate and retire that generated role. A pre-existing role is accepted only with those exact attributes and those two exact memberships; privileged or unexpectedly linked roles fail before metadata can be sealed. Every tenant-bearing table has `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY`; policies compare `tenant_scope` with `current_setting('smesh.tenant_scope', true)`. Runtime transactions use `SET LOCAL ROLE` and bound `set_config(..., true)`, so missing context fails closed and transaction-pool reuse cannot retain context. Global claiming, cancellation polling and diagnostics are fixed-`search_path` `SECURITY DEFINER` procedures returning only one claim, one boolean, or aggregate counts; the runtime login never receives global table visibility.

Production URLs must require TLS. Plaintext is accepted only by the explicit test-only loopback switch used by the real PostgreSQL fixture. URLs and passwords are never formatted into adapter errors or `Debug` output.

Production outbox and receiver claims, finishes, deliveries, completions, and cancellation/lease arbitration derive the effective milliseconds from `db_millis()` inside the same transaction; caller clocks cannot extend or prematurely invalidate a fence. The explicit loopback-only deterministic test seam retains injected command times so the SQLite/PostgreSQL conformance fixture can compare exact records. Removing that test seam and wiring renewal across replicas remains part of #63.

## Operations runbook

1. Provision PostgreSQL 17 (HA, replication, WAL retention, PITR, and checksums are operator responsibilities).
2. Supply a non-superuser migration credential with `CREATEROLE` plus `CREATE` on the target database, and a distinct bounded runtime login. Construct `PostgresStoreConfig::new(migrator_url, runtime_url, schema)`. The adapter validates the runtime login attributes and grants only generated-role membership.
3. Back up the database, including `store_identity`, `store_metadata`, and migration ledger. Restores must preserve cursor/receipt keys. Never bring a writable restore online beside its source without intentionally changing authority identity and revoking old credentials.
4. Open the adapter during readiness. Any migration checksum/catalog/policy/index drift is a hard failure; repair through a reviewed migration, never by editing the ledger.
5. Monitor pool saturation, the five-second transaction statement/lock watchdogs, serialization/deadlock errors, outbox age, receiver leases, audit/snapshot growth, backups, and PostgreSQL recovery/read-only status.
6. Shutdown stops claims at the runtime owner and closes only that adapter pool. Independent stores/pools remain valid.

Local verification:

```sh
export SMESH_TEST_POSTGRES_SUPERUSER_URL='postgresql://postgres:<fixture-password>@127.0.0.1:55432/smesh_test'
export SMESH_TEST_POSTGRES_ADMIN_URL='postgresql://smesh_migrator:<migrator-password>@127.0.0.1:55432/smesh_test'
export SMESH_TEST_POSTGRES_RUNTIME_URL='postgresql://smesh_test_runtime:<runtime-password>@127.0.0.1:55432/smesh_test'
export SMESH_POSTGRES_TEST_REQUIRED=1
cargo test --locked --test postgres_store -- --test-threads=1
```

Tests create random isolated schemas/roles, wrap each PostgreSQL test in a 30-second watchdog, and remove managed objects. If the migrator URL is absent they print an explicit skip unless `SMESH_POSTGRES_TEST_REQUIRED=1`.

## Non-goals

Production backend selection/wiring, cross-replica lease renewal and gateway driver failover are issue #63. Distributed quota policy is issue #14. PostgreSQL HA provisioning, split-brain prevention, backup retention, and live SQLite/PostgreSQL migration remain external/non-goals.
