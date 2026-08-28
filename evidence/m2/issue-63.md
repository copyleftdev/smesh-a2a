# Issue 63 — PostgreSQL production multi-replica wiring

## Implemented

- Explicit `SMESH_A2A_DURABLE_BACKEND=sqlite|postgres` selection with separate migrator/runtime URLs, validated replica identity, and fail-closed mixed or incomplete configuration.
- `AuthorityCapabilities { lease_renewal, quota_reservations }`. PostgreSQL advertises both; SQLite advertises neither.
- Database-time, fully fenced outbox and receiver renewal. Renewal failure publishes a fatal driver state and suppresses delivery/receiver completion until a new process reconciles expired durable work.
- A backend-neutral bounded `QuotaReservationInput` and `AuthorizedMutation<T>`. The durable handler reads reservations only from the server task-local `current_quota_reservation`; A2A request fields, headers, and metadata never populate it. Issue #14 owns future policy resolution and calls `scope_quota_reservation`.
- PostgreSQL migration revision 2 stores the server reservation key, tenant/account/principal scope, operation/dimension, positive units, task binding, bounded optional JSON metadata, and expiry. Admission, continuation, and cancellation insert or verify that row inside the same transaction as task/event/idempotency/outbox/transcript/audit/cancellation state. Exact replay verifies the same row without another insert; conflicts and trigger faults roll back the whole mutation. Quota bytes participate in authority capacity checks and startup validates task/account binding, bounds, metadata, and expiry semantics. SQLite schema v6 is unchanged and rejects quota-bearing commands before mutation.
- PostgreSQL migration revision 3 binds receiver leases to the exact sender attempt/fence and returns expired final attempts to Rust under one bounded locked claim. The adapter preserves completed reconciliation, waits for live processing, re-fences expired accepted processing receivers under the winning sender lease so cancellation or completion can reconcile cooperatively, and atomically dead-letters only final attempts with no accepted receiver. All paths use database time and full sender/receiver fences.
- Real PostgreSQL max-attempts-one evidence covers an expired accepted receiver with a requested cancellation, two simultaneous sender reclaimers, receiver reclaim, stale old-receiver rejection, cooperative cancellation completion, exact outbox/attempt/task/event/idempotency/transcript/cancellation rows, restart replay/SSE, and zero duplicate effects. A separate no-receiver case preserves atomic Failed dead-lettering; trigger faults at task/event/idempotency/transcript/outbox points prove whole-transaction rollback.
- `tests/postgres_multi_replica.rs` runs real child OS processes with distinct PIDs, replica IDs, independently opened pools/drivers, port-0 Axum JSON-RPC/REST/SSE routers, watchdog-bounded readiness/checkpoint/shutdown protocols, kill/reap guards, and unwind-safe parent-owned schema/role cleanup. Its outage revokes only the generated schema role and terminates only sessions carrying the test's unique application name; it never changes database-global `PUBLIC CONNECT`. The fixture is debug-only because deterministic shortened lease timing and plaintext loopback PostgreSQL are test seams absent from release.
- The process test proves both sender and receiver remain owned by the winner beyond original expiry while a competitor is live, graceful shutdown joins renewal and requeues with the latest fence for immediate sender reclaim, the named after-receiver-complete/before-delivery-commit crash, stale receiver fencing, exact replay through restarted processes (including outage recovery), and fatal/no-effect renewal outage recovery.
- In debug builds, `authorized_gateway_process` spawns the production `smesh-a2a-gateway` binary with the PostgreSQL backend, separate migrator/runtime URLs, explicit replica IDs, real mTLS identity and authorization policy, and a real socket. It exercises JSON-RPC admission/exact replay, REST get/list/streaming SSE, graceful shutdown, migration/startup, and restart. This is explicitly a debug-only full binary E2E because the local PostgreSQL fixture is plaintext.
- Release builds contain no plaintext PostgreSQL escape hatch. A release-only production-binary test holds the candidate listener open and proves the same plaintext configuration fails first with `TlsRequired`; mixed SQLite/PostgreSQL and disabled-auth configurations also fail closed without SQLite or database acquisition. This is fail-closed release evidence, not a claim of a full release PostgreSQL E2E. A deterministic trusted-CA TLS PostgreSQL fixture is not currently provisioned.
- Receiver and sender renewal joins are abort-on-drop owned. Cancelling `ReceiverRenewal::stop` after it takes the join aborts the child and releases its resource. Dropping a gateway requests cooperative root cancellation and transfers the root join to a bounded reaper; a real PostgreSQL regression blocks receiver renewal on an exhausted one-connection pool, then proves drop releases the renewal, pool holder, application sessions, and permits a second store.
- Sender-renewal polling runs inside the poll-scoped panic redactor. A subprocess canary proves payload and PostgreSQL location details are absent from stderr while generic fatal context remains visible.

## Verification

Executed against a tracked local `postgres:17` fixture:

- PostgreSQL authority suite: **41 passed, 0 failed** (including blocked-renewal drop cleanup).
- Independent-process failover suite: **passed three consecutive runs**, then passed with the renewal-outage scenario included.
- Quota admission fault/replay/conflict and quota continuation/cancellation conformance passed.
- SQLite quota rejection and unchanged schema-v6 probe passed.
- CI runs `postgres_store`, `postgres_multi_replica`, and the debug plaintext production PostgreSQL binary E2E as required PostgreSQL jobs under explicit watchdogs. The general job separately runs the exact release all-target/all-feature suite, including release-only fail-closed TLS evidence.

## Boundary with issue #14

Issue #63 supplies only the atomic durable reservation command seam. It does not select dimensions, compute limits, maintain policy counters, expire/refund reservations, or expose operator overrides. Issue #14 must resolve policy from trusted server identity, construct `QuotaReservationInput`, and scope the authorized handler call with `scope_quota_reservation`; it must not derive quota authority from caller-controlled A2A fields.

## Operational notes and non-goals

Migration leadership is transaction-scoped and readiness requires exact revision/catalog/semantic validation. Cutover is explicit; there is no automatic SQLite-to-PostgreSQL migration. PostgreSQL HA provisioning, split-brain prevention, backup policy, and exactly-once effects outside the durable receiver boundary remain operator concerns.
