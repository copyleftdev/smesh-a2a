# Issue #16 — observability and audit projection evidence

## Implemented boundary

- A closed `telemetry` module defines static span/event/metric names, bounded values, closed outcomes,
  correlation-only attributes, metric-label rejection, eight-attribute datapoints, and 2,000/10,000
  series budgets.
- The production ingress generates a server-owned 128-bit request ID and strips inbound
  `x-request-id`, `traceparent`, `tracestate`, and `baggage` as authority.
- `OtlpOwner` owns separate bounded drop-newest trace, metric, and log queues and one isolated worker
  per signal. `try_emit` is synchronous, infallible, and nonblocking. HTTP clients disable ambient
  proxy and redirects. Runtime collector failure and best-effort shutdown cannot alter gateway results.
- OTLP HTTP protobuf and gRPC transport is real for closed spans, cumulative counter/histogram/gauge
  metrics, and unsampled lifecycle logs. Official generated collectors decode all three services in
  `tests/telemetry_multisignal.rs`; trace, parent, and link IDs and closed timestamps are exact.
- Every production gateway mode passes a source-compatible optional `TelemetryHandle` into the live
  ingress middleware, which emits request spans, request counters/duration histograms, and completion
  logs only after a response exists.
- Custom CA, paired client certificate/key, and secret header files are read once with no-follow,
  owner-private, regular-file, and byte bounds. The immutable snapshot configures both reqwest and
  tonic; secret values are redacted from `Debug` and error categories.
- PostgreSQL revision 6 and SQLite schema 7 install gated triggers that append digest-only events to
  `audit_projection_outbox` in the authoritative transaction. The backend-neutral optional authority
  claims bounded leased rows with owner/token/epoch/DB expiry and fences deliver/fail/cleanup.
- `AuditProjectorWorker` starts only with OTLP and authority support, accepts into the bounded log queue
  before committing delivered, retries queue rejection without blocking request paths, and joins before
  authority/OTLP shutdown. Projection explicitly starts at enable; migrations perform no history scan.
- Public URL validation now rejects credentials, query, fragment, controls, unsupported schemes, and
  overlong values in every transport mode. Logs contain only canonical scheme/host/port. Required
  runtime-capture failures use an opaque error category rather than raw error rendering.
- Bootstrap edge-availability objectives and alerts reference only live ingress metrics. Unsupported
  durable/runtime/quota/artifact/PostgreSQL/integrity panels and rules were removed rather than
  presenting absent series as production evidence. A Grafana edge/audit overview, operator runbook,
  exact normalized fixture, and a dedicated CI job are checked in.

## Repeatable evidence

```bash
cargo test --test telemetry_schema
cargo test --test telemetry_outage
cargo test --test telemetry_ingress
cargo test --test telemetry_audit_projection
cargo test --test telemetry_otlp
cargo test --test telemetry_multisignal
cargo test --test telemetry_golden
cargo test --test observability_assets
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --locked --test postgres_observability_process -- --test-threads=1
SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --locked --test postgres_store -- --test-threads=1
promtool check rules observability/prometheus-rules.yml
```

All test network receives, shutdowns, joins, and collector servers use watchdogs; listener binding is
the readiness barrier and no sleep/yield is synchronization. The production required-mTLS SQLite
process test now starts and restarts with an explicitly configured absent OTLP collector, serves real
JSON-RPC/REST traffic, and completes bounded SIGTERM shutdown without changing durable replay.
`postgres_observability_process` additionally starts two required-mTLS production gateway binaries
with distinct replica IDs over one revision-6 PostgreSQL authority. It proves readiness and committed
JSON-RPC work while the collector is absent, decodes process-produced log/trace/metric protobuf after
the collector appears, rejects identifier metric labels, exercises a hanging collector plus
401/403/429/500 responses, terminates one gateway within the watchdog, and observes export recovery at
the same endpoint without restarting the surviving gateway. The focused process test passed three
consecutive serial runs; the full 59-test `postgres_store` gate passed with explicit migrator/runtime
URLs after projection row-parity was added.

## Authority and outage truth

Durable task/outbox/receiver/quota/artifact/authorization records and the current `runtime-trace/3` remain the
required authority. OTLP is bounded and lossy even for lifecycle classes that bypass ordinary trace
sampling. Queue exhaustion or collector loss increments bounded reason counters and drops the newest
optional copy; it never consumes required runtime-trace capacity or enters an authority transaction.
Issue #73 supersedes the earlier process-lifetime trace buffer with an explicit bounded recent-window
RPO and attempt-scoped dispatch-correlation retirement.

## Explicit limitations

The durable projection is at-least-once between queue acceptance and downstream collector receipt;
stable `event.id` is the dedupe key. Exporter loss after queue acceptance is an optional telemetry gap,
not authoritative data loss. No external telemetry backend retention or tenant ACL configuration is
claimed, and audit read remains OTLP-only.
Authorization-denial storage and process-global runtime-trace capacity abuse are closed by issues #72
and #73. Protocol fuzzing and the load/chaos matrix are closed by issues #74 and #75; the aggregate
STRIDE/data-flow model and accepted residuals are maintained in `docs/GATEWAY_THREAT_MODEL.md`.

The process test does not claim a live OIDC issuer/bearer-verifier process, artifact publication from
that same two-gateway fixture, or kill-after-downstream-accept ambiguity. Those production paths are
composed from dedicated evidence rather than duplicated into one bypass-prone giant fixture:
`telemetry_multisignal::grpc_mtls_collector_requires_client_identity_and_secret_header` is a real gRPC
mTLS collector; the auth process suites prove the production verifier/wire boundary; and
`postgres_artifact_process` proves production artifact publication/crash recovery. Projector
at-least-once ambiguity is proven at the authority lease seam with stable digest-only `event.id` as the
downstream dedupe key.

## Restore interaction and final gates

Revision 6 added the sealed singleton `audit_projection_control` row to every freshly bootstrapped
PostgreSQL schema. The artifact restore empty-target scanner treated that optional configuration row as
authoritative occupancy, so both empty and populated restore paths deterministically returned
`ArtifactRestoreTargetNotEmpty`; temporary table/count diagnostics identified
`audit_projection_control count=1 allowed=0` in both isolated and exact serial reproductions.

The restore now distinguishes optional projection state without weakening authority checks. It refuses
active projector leases as busy; refuses any preexisting authoritative task/event/audit/quota/artifact
or operator state; and, only for an otherwise empty target, locks the outbox plus control row, deletes
orphan projection rows, disables projection, and commits the first restore journal in one transaction.
Projection remains disabled through import and is restored to the requested starts-at-enable mode only
in the atomic enable transaction. An enabled gateway open is refused while a restore journal is
`restoring`. The regression also proves refusal paths preserve projection rows/control exactly.

Final explicit PostgreSQL 17 serial evidence on `127.0.0.1:55432`:

- both named regressions passed twice consecutively in exact order;
- `artifact_migration`: **7 passed, 4 helper tests ignored**;
- `postgres_store`: **59 passed**;
- the nine explicit PostgreSQL targets (`artifact_migration`, `postgres_store`,
  `telemetry_audit_projection`, `postgres_quota`, `postgres_multi_replica`,
  `postgres_quota_process`, `postgres_artifact_process`, `postgres_observability_process`, and
  `authorized_gateway_process`): **108 passed, 4 helper tests ignored**;
- `cargo test --locked --all-targets -- --test-threads=1` with required explicit PostgreSQL URLs:
  **531 passed, 4 ignored, 0 failed** across 60 result groups;
- `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, and
  `git diff --check`: **passed**;
- post-gate fixture query: **0 residual `smesh_*` schemas, 0 non-fixture roles, 0 sessions**.

Final artifact hashes:

- `src/artifact_restore_executor.rs` — `1280d13c275c30942f6fa7a3fe08c43ec825dd3fefd990731ce77593e88634f4`
- `src/postgres_store.rs` — `2c5e217e62c3c05a5ef98cb58edb92a45a11b1584a234d0d4913ebac77ab06bd`
- `tests/artifact_migration.rs` — `483c94079408cf171939705e071080e9045b1a8d852e116acbc6159a221e2e6f`
- `docs/ARTIFACT_RUNBOOK.md` — `8715c91f2787bbfdb30a6fa30e729d46df465c1bc96d7133737adde71cd578bc`
- `docs/OBSERVABILITY_RUNBOOK.md` — `a15ef031f3617b4e1843b861b1f612cf431a5f69b9f92f44c9c88554c0d8a6da`

## Independent blocker remediation — 2026-08-29

- Removed the fabricated startup request-completed record; live request logs/spans now carry the server request ID. Admission/replay includes `a2a.message.id`; background dispatch/receiver spans carry a deterministic digest-derived span link.
- Closed attribute values and duplicate-key handling, added request-event shape checks and strict digest/token correlation validation.
- Moved `dispatch.attempted` to the pre-dispatch attempt seam and kept terminal success after `commit_delivery`.
- Replaced the synthetic golden constructor with normalized records captured from the live production SQLite gateway path.
- Shared OTLP closure state now rejects every pre-existing handle after shutdown; dedicated stop channels wake and join workers. Metric workers retain cumulative series state (counter 7→14 with stable start time; cumulative histogram state; replacing gauges).
- Projector cycles emit zero lag on empty backlog and invoke bounded delivered/dead cleanup. SQLite projection digest constraints are exact lowercase SHA-256 checks; PostgreSQL trigger enqueue additionally requires the connection capability, proving enabled and disabled stores can coexist.
- Projector/OTLP shutdown failures are no longer silently discarded; opaque structured stderr is emitted and authority shutdown still completes before the optional projector error is returned.
- Edge SLI now excludes malformed/authentication failures, treats expected denial/not-found/conflict and 429 as eligible-good, and treats 5xx as eligible-bad. Rules, dashboard, runbook, and leased per-row architecture wording match.

Verification from the exact current tree:

- explicit PostgreSQL 17 debug all-target serial gate: **537 passed, 4 ignored, 0 failed across 60 groups**;
- focused telemetry/schema/golden/live-path/OTLP/projection/assets suites: **passed**;
- formatter, Clippy `-D warnings`, Rustdoc, and `git diff --check`: **passed**;
- `cargo audit`: **0 vulnerabilities**, with the existing allowed `bincode` unmaintained and transitive yanked `chacha20` warnings;
- `promtool` was unavailable on this host, so no new promtool claim is made.

Selected current hashes:

- `src/telemetry.rs` — `3d7123212d920092f08a72c0695ca48ebf207d8314a95d6eb7b30bc192810b4b`
- `src/outbox_driver.rs` — `af99fe4e17f9f0253d4bcf7bb85cded0ca819fb76999a097a6385006efb969cc`
- `src/sqlite_store.rs` — `9d625b4eb737e3ed9168adc4c03cf918df5ce96b56582b0dbc1ee1267370bbba`
- `migrations/postgres/0006_audit_projection.sql` — `20701eba69237818b83cfdefa0e754cf3ce89501fd0534e4261fe7ae4b1e763c`
- `tests/telemetry_golden.rs` — `a849809cc2eef8049dfa3e1d7589242852e660a31c74a22621b2ce2f8874f58d`

### Remaining blockers after this pass

This pass is **not a completion verdict**. The following review requirements still need implementation and RED/GREEN evidence before #16 can close:

- OTLP still exports one record at a time and constructs HTTP clients/gRPC channels per record; configured `batch_size`, `schedule`, and `metric_interval` scheduling plus persistent transports are not yet implemented.
- `TelemetryHealthSnapshot` does not yet expose OTLP/projector shutdown timeout/join status.
- PostgreSQL enqueue now gates on the connection GUC, but a normal runtime session can still forge that custom GUC; it needs an unforgeable server-owned per-connection capability.
- Event/span-specific schema allow/required sets are only strict for request completion; the remaining signal descriptors need complete executable shape tables and internal fallback mapping.
- Artifact stage/register/promote/resolve telemetry still needs the complete task/context/artifact/dispatch correlation at every available production seam.
- Release all-target, MSRV, demo, and promtool gates were not run in this pass (`promtool` is not installed).

## Final blocker closure — 2026-08-29

- OTLP log/span workers now collect to `batch_size` or `schedule`, flush partial batches on shutdown,
  and keep one reqwest client or tonic channel for the worker lifetime. A failed transport is discarded
  and recreated only after the bounded circuit permits another attempt. Metric workers aggregate every
  accepted point immediately, export all current cumulative series only at `metric_interval` or shutdown,
  retain dirty state across failures, and preserve one fixed aggregation start.
- `TelemetryHealthSnapshot` now survives owner consumption and exposes shutdown started/completed,
  timeout/join-failure counters, live worker count, and a closed opaque last outcome. Projector timeout
  and join failure feed the same health state; timed-out OTLP workers are still joined rather than detached.
- PostgreSQL revision 6 replaced the forgeable GUC gate with a migrator-protected 256-bit proof,
  per-backend registration, and a backend-local random temporary nonce. Runtime direct table access is
  revoked; wrong proof and forged-GUC callers fail. Disabled pools never register. Temporary capability
  state disappears with the backend and PID reuse replaces the protected registration. Backup, restore,
  exclusion, redaction, and rotation lifecycle are documented.
- Event and span constructors use exhaustive enum matches for shape allowlists, duplicate rejection,
  closed values, and strict IDs/digests. `map_internal_telemetry_fallback` is the single typed fallback
  from internal operation/error classes to closed operation/outcome/reason values.
- Artifact stage/register logs and spans now include artifact/task/context/dispatch from the authoritative
  registration and dispatch-derived span links; resolve/corruption include authoritative artifact/task;
  global promoter work remains artifact-scoped and does not fabricate task correlation.

Final gates from the exact tree:

- debug all-target PostgreSQL 17 serial gate: **539 passed, 4 ignored, 0 failed**;
- release all-target serial gate: **passed** (including the release-valid shutdown ownership regression);
- focused PostgreSQL projection, store (59), artifact migration (7 + 4 helper ignores), telemetry,
  multisignal, schema, live-path, and outage suites: **passed**;
- Rust 1.88 MSRV `cargo check --locked --all-targets --all-features`: **passed**;
- formatter, Clippy `-D warnings`, Rustdoc, and `git diff --check`: **passed**;
- `cargo audit`: **0 vulnerabilities**, with the two pre-existing allowed warnings;
- pinned `prom/prometheus:v3.5.0` promtool container: **3 rules valid**, container removed;
- demo syntax/tests/trace validation: **9 passed; 55 trace events valid**;
- post-gate PostgreSQL cleanup: **0 task schemas, 0 generated roles, 0 task sessions**; parent server left running;
- shared `target/`: **79G**; no repository copy or alternate target was created.

Final selected SHA-256 hashes:

- `src/telemetry.rs` — `df98772e0036799261e6f1b95f59285fe96d2a123f0d36ee5dd6709ae73a530f`
- `src/postgres_store.rs` — `eab431bc9e201a00391b9f31fb59e4f6b13d6dd742971ca707503e971b7aa480`
- `migrations/postgres/0006_audit_projection.sql` — `70efc0847e4a6fc020ea48110fc36126fabebb8006d5415ff6562704f922cc07`
- `src/artifact_restore_executor.rs` — `51dc80c0b3bf0ed911a5a467b7fbf77435c868d8fcd91487b929f3915186070e`
- `tests/telemetry_otlp.rs` — `2ae5263ccc6f87c5efe2409f2942cfe1cd9eeb0003e51eae16ab8ed3afbb0175`
- `tests/telemetry_audit_projection.rs` — `bebfcbd8ea02a6653aebe6c04dc92dd2668991ac908695691811f78a7f7165d6`
- `docs/OBSERVABILITY_RUNBOOK.md` — `39b98e55e61caee8aaa8c8a0e8c4563e36f707b0d376ff4102ed431546a3030c`
- `observability/prometheus-rules.yml` — `a8d4745ebd1e3633ef7eac4a40ec9057041e3bd091604151c14ca0b26533f706`

## Final correlation, batching, retention, and fairness closure — 2026-08-29

- Replaced broad event/span shape groups with exhaustive enum matches, exact per-signal allowlists,
  nonempty semantic requirements, and an all-variant test that removes every required attribute.
- Added a source-compatible authoritative outbox correlation capability. SQLite and PostgreSQL perform
  indexed tenant/dispatch-scoped reads; the driver captures the message/task/context tuple once and a
  private telemetry sidecar propagates it through dispatch, receiver, terminal, and artifact records.
- Dispatch claim now emits the real deterministic background root identity. Child dispatch/receiver/
  artifact spans link to that emitted identity; the live test resolves every link against emitted spans.
- Metric series admission now holds the registry reservation through queue admission and rolls back only
  a newly reserved series on full/disconnected queues. The capacity-one/limit-two poisoning probe passes.
- Shutdown export drains are chunked at configured `batch_size` for logs, spans, and cumulative metrics.
- PostgreSQL operator projection sources are distinct per migration/backup/restore/key-rotation table;
  dead rows have database-time `dead_at` and share the exact retention boundary with delivered rows.
  SQLite v7 has the same dead timestamp semantics and tenant-partitioned fair claim ranking.
- The normalized golden was regenerated only from the live SQLite production path and now proves that
  authoritative message correlation survives admission through dispatch and terminal processing.

Verification on the exact post-fix tree:

- debug `cargo test --all-targets --all-features -- --test-threads=1`: **passed**, including PostgreSQL
  process/store, SQLite conformance, all telemetry, OTLP, projection, golden, and live-path suites;
- release `cargo test --release --all-targets --all-features -- --test-threads=1`: **passed**;
- Rust 1.88 `cargo check --locked --all-targets --all-features`: **passed**;
- `cargo audit`: **0 vulnerabilities**, with the existing allowed `bincode` unmaintained and transitive
  yanked `chacha20` warnings;
- formatter, Clippy `-D warnings`, Rustdoc `-D warnings`, and `git diff --check`: **passed**;
- shared `target/`: **80G**; no repository copy or alternate target was created.

Selected SHA-256 hashes:

- `src/telemetry.rs` — `a819e862cdba00323f6d2bd68d42c3b4a8024577be514f92fb442564d86682b6`
- `src/durable_authority.rs` — `9f57181cd1d525c8d511da23f348b6b32d54e862a25dc08a25d533014d248c74`
- `src/outbox_driver.rs` — `88c59a5fdc3918de5d64a6717abeb6b60ea5aa9af17fb3014144b099a9524c35`
- `src/sqlite_store.rs` — `ced4ba8a6f7ab0db6fae1aca900d01392b09d9d205efc1ec729037ddab0f4ccc`
- `src/postgres_store.rs` — `cbe1ce2a01fd8eee5fccaffe84ae989e0cc15be75ac0573ef03e7579bbe7edc6`
- `migrations/postgres/0006_audit_projection.sql` — `8ccf693b9ddc4743950b019ce90c48e00a9a6f30bd02ada3b3c850d89cb83fd7`
- `tests/telemetry_schema.rs` — `894ea989bbc3cdeb29864b1206346ec6f664b08196b9e5ee76137dcc4b6e3ede`
- `tests/telemetry_live_paths.rs` — `6487f9423cd909c315bc8d320c6d3f90876d124deeec5453f62b5f859064962e`
- `tests/telemetry_otlp.rs` — `cf39bef8fbfb28aa97619bff1169f702b137c3165932bf4e0de265534d27450d`
- `observability/fixtures/normalized-otlp-golden.json` — `1b069b1f60cbf98310d2a4f8901ce3e7c8eb8441565b38f82ad80d8140d25073`

## Linearizable correlation and shutdown closure — 2026-08-29

- Dispatch/receiver/terminal events and outbox/receiver spans now require the complete
  dispatch/task/context/message tuple. Causally tied artifact records require the same complete tuple;
  global artifact-worker records remain an explicit artifact-only shape. `SpanName::ALL` has the same
  exhaustive required-attribute removal coverage as `EventName::ALL`, including partial cross-shape
  identity rejection.
- Missing authoritative outbox correlation no longer emits a weakened record: the optional record is
  dropped, the `invalid_attribute` health counter increments, and stderr receives only an opaque warning.
  Ordinary streaming admission emits only after authority returns, using its task ID, canonical context,
  and canonical message ID; the live no-caller-task/context regression passed.
- A shared emission mutex now linearizes closed-check, metric-series reservation, and nonblocking enqueue
  against shutdown closure. Stop messages carry one absolute deadline. Shutdown drains in configured
  chunks, bypasses circuit retry/cooldown, bounds each final network future by remaining time, counts
  unexported remainder as `shutdown`, waits for worker acknowledgements, and joins exited workers. The
  deterministic precheck/send overlap and a 10s-export-timeout/100ms hung TLS collector regression pass;
  shutdown returns under 300ms with `workers_alive=0` and no network activity after return.
- Inspected `smesh_migrator_99c4dbb154903f90`: it had zero sessions and schemas and only its expected
  database CREATE ACL dependency. The ACL was revoked and the role safely dropped. The non-superuser
  migrator fixture now owns a panic-safe RAII cleanup guard that removes schema, generated runtime role,
  ACLs, and migrator role even when failure occurs after schema creation; the injected-failure regression
  and responsible production test both passed.

Exact final gates from this tree:

- explicit PostgreSQL 17 debug all-target/all-feature serial suite: **545 passed, 4 ignored, 0 failed
  across 60 result groups**;
- explicit PostgreSQL 17 release all-target/all-feature serial suite: **500 passed, 4 ignored, 0 failed
  across 60 result groups**;
- focused schema/live/golden/outage/OTLP/multisignal/projection suites, including release hung shutdown:
  **passed**;
- Rust 1.88 MSRV check, formatter, Clippy `-D warnings`, Rustdoc `-D warnings`, and `git diff --check`:
  **passed**;
- `cargo audit`: **0 vulnerabilities**, with only the two repository-allowed upstream warnings;
- pinned `prom/prometheus:v3.5.0` promtool: **3 rules valid**;
- demo audit/tests/syntax/deterministic trace: **0 high vulnerabilities, 9 tests, 55 valid and identical
  trace events**;
- post-gate cleanup: **0 task schemas, 0 generated roles, 0 generated sessions**; the fixed parent fixture
  roles remain untouched.

Selected final SHA-256 hashes:

- `src/telemetry.rs` — `96b795d768bb748627ce52a895927cbab31c8c292465162babc4774a180cac42`
- `src/durable_handler.rs` — `72cd26bd9647448e111cf32e546074e331084fa8d3b68d58f5413110bf7240f7`
- `tests/telemetry_schema.rs` — `7f56261433c92e5ae20b113e7b7a4f2db22a0bb4cc57065bc825bde473aca3bd`
- `tests/telemetry_live_paths.rs` — `429fe3493339085e8d004263b40bfbf6e960dd464398571c642cdb5f1852483a`
- `tests/telemetry_outage.rs` — `bf84bf596ba3671838d0b876787261559d53d8129fa4633d09d992f4f9e7702f`
- `tests/postgres_store.rs` — `81f7d4010b0d64ae1dc93d0e201e4468e4c5cf3a1a6b28265658b6ba9bdea476`

## Production audit projector record closure — 2026-08-29

- Claimed rows now build schema-valid `smesh.audit.projector.state` logs with digest-only `event.id`,
  closed audit source and operation, `smesh.outcome=ok`, and `smesh.reason=committed`. Here `ok`
  describes projection processing success only; the operation preserves the authoritative fact class
  without fabricating an authorization, quota, task, or artifact effect.
- The event-kind/source mapping is exhaustive and rejects mismatched pairs instead of falling back to a
  raw string. Artifact operator completion is split into migration, backup, restore, and rotation
  operations from its closed source.
- The RED worker regression timed out before the fix because every row failed schema construction. GREEN
  proves queue acceptance precedes commit, queue-full remains retryable, SQLite emits one decoded OTLP
  log and does not duplicate after restart, and an explicit PostgreSQL 17 row reaches delivered (or
  bounded retention cleanup) only after the worker accepted its log.

Focused exact-tree verification:

- `telemetry_audit_projection`: **8 passed** with explicit PostgreSQL URLs;
- `telemetry_schema`: **11 passed**; `telemetry_golden`: **1 passed** with the checked-in live golden
  unchanged; `telemetry_otlp`: **4 passed**;
- explicit PostgreSQL `postgres_store`: **60 passed**; `postgres_observability_process`: **1 passed**;
- exhaustive library mapping regression: **1 passed**;
- formatter, Clippy all-target/all-feature `-D warnings`, and `git diff --check`: **passed**.

Selected SHA-256 hashes:

- `src/telemetry.rs` — `aed77b87e372908b9a56d737ed1eece40ebf16412d170cb31009ef073c323805`
- `tests/telemetry_audit_projection.rs` — `d98c2f34463751abb5e6d383568842a78bd06689eecef3592330f82e8752b510`
- `tests/telemetry_schema.rs` — `9fca76f7fdafe486b5f61209879ec35588876989e901f7c2923c50361bec7ba3`
- `docs/OBSERVABILITY_RUNBOOK.md` — `64e3b67b3b7f02cc9539c9f7bc4845d03ad2b3c82390e7d10b6413d9a70e72e4`
- `observability/fixtures/normalized-otlp-golden.json` — `1b069b1f60cbf98310d2a4f8901ce3e7c8eb8441565b38f82ad80d8140d25073`
## PostgreSQL stream snapshot closure — 2026-08-30

- A repeated production PostgreSQL gateway test exposed a pre-existing snapshot race: terminal
  publication could commit between the transcript-metadata and frame queries, causing one poll to
  combine metadata from an older snapshot with frames from a newer snapshot and reject the stream
  cursor as corrupt.
- `stream_frames_after_scoped` now reads metadata, frames, digest, and terminal result in one
  bounded, query-only `REPEATABLE READ` transaction. A subsequent poll starts a fresh transaction
  and observes later commits.
- A deterministic `ACCESS EXCLUSIVE` test barrier reproduced the old failure and verifies both the
  original consistent snapshot and the later committed frame.
- The production PostgreSQL restart/replay test passed 10 consecutive telemetry-enabled runs and
  three telemetry-disabled isolation runs. The exact PostgreSQL CI sequence passed: artifact
  process 3x, PostgreSQL store 61/61, multi-replica 2/2, target process, quota process 2/2, and
  PostgreSQL quota 29/29.
- Independent review confirmed transaction-local tenant/role context, bounded statement/lock
  watchdogs, rollback on every error path, no lock expansion, and no SQLite change.

Selected SHA-256 hashes:

- `src/postgres_store.rs` — `a9cbfdad31ced7b90c5025415aa3b0159789a734cbf5aad1da067f005d9ec353`
- `tests/postgres_store.rs` — `2023a3c912afa9a582913a7a196e4f74558661c608279529fba0bcf3c728cae6`

## CodeRabbit closure after SSE snapshot fix — 2026-08-30

- Live post-commit telemetry now emits `smesh.durable.commit`; only absorbing successful receiver
  terminations emit `TaskTerminal`. Input/auth interruptions emit one state-bearing
  `TaskTransitioned` plus the state-bearing `ReceiverCompleted` fact. Immediate cancellation omits
  `CancellationStopped`; cooperative cancellation emits it only after the active receiver result is
  joined. Both paths have deterministic production-gateway tests.
- Replica IDs through 128 bytes map to domain-separated, stable, opaque, distinct projector owners no
  longer than 64 bytes. SQLite can combine explicit legacy binding and audit projection, production
  startup selects that API, and telemetry startup rejects an unavailable projector instead of
  discarding `false`.
- The duplicate-projection restart test waits on an observable completed worker cycle (no sleep) and
  verifies the delivered state and attempt count remain unchanged. The live golden shuts down before
  drain and passed 20 consecutive comparisons.
- The artifact prerequisite names PostgreSQL revision 6 and exact catalog/RLS validation. The 99.9%
  edge alert uses fast/slow multi-window burn rates plus a 100-event floor; every rule has summary and
  runbook annotations. Prometheus rules and every Grafana expression are checked against emitted
  metric/label schema, and every panel uses the Prometheus datasource variable.

Verification:

- focused telemetry/schema/audit/golden/asset suites: **26 passed**;
- full non-PostgreSQL all-target/all-feature suite: **passed** (PostgreSQL URLs and both required flags
  explicitly absent);
- explicit PostgreSQL `postgres_store`: **61 passed**; `telemetry_audit_projection`: **9 passed**;
  `postgres_observability_process`: **1 passed**;
- live golden: **20/20 repeated passes**;
- `promtool` v3.5.0: **SUCCESS, 3 rules**;
- formatter, all-target/all-feature Clippy `-D warnings`, rustdoc `-D warnings`, doctest, and diff
  whitespace checks: **passed**.

Selected SHA-256 hashes:

- `src/telemetry.rs` — `6aafb3778cff6bb984582ca3820440a16a55fbbe7e01d8a2aa4eda66bdf7af2f`
- `src/outbox_driver.rs` — `2e482e0d150156e793bcc82edc514ae7cf91a4de810946c2d5b25c8e9cd2dcde`
- `src/durable_handler.rs` — `826f420cfa50228a6dfa7b0e00aa478d9022372ff05cb9c50a01b03c8ede9f77`
- `src/sqlite_store.rs` — `a7a2f9d801b33c4c5b706105bbf7b5d3c80ad045e0be9672f1c4e86d04ce93b6`
- `src/main.rs` — `ada286b50e4bc32ed5f13016e480a39eff8b06ec9ed8658a0c6207c20346bd61`
- `tests/telemetry_live_paths.rs` — `4e8c10d4ded81092bc39463958feaf07f35885af6af050d283b6f9354b4fb199`
- `tests/telemetry_audit_projection.rs` — `bebe62ab9fc024829bf9d7bd26e28d858198b799dc2c91580131fe29401900c8`
- `tests/observability_assets.rs` — `34b4cc891f2c0547c1604b4efc3228d0bec8ccb4bb0ca2691c2c92ae2470c91f`
- `tests/telemetry_schema.rs` — `1ba938b05a00787433e1bd5bd1e4ffe1c4746dde6fc0c176fc6c1246e3870e6b`
- `observability/fixtures/normalized-otlp-golden.json` — `9355adca60a5e5f32c53aa490492d1e5747fb94b03cc31524ab8a557d4945ce8`
- `observability/prometheus-rules.yml` — `1273e16c279a1093b65d6602957652ab3beedb444c37f9151b2475ca5795fc26`
- `observability/grafana/smesh-a2a-overview.json` — `32b7ddb80a47815d723c16c4ee7a3b657b628c307ae5a7961a36d69e1106f56d`

## PromQL aggregation and vector-matching schema closure — 2026-08-30

- Replaced token-prefix scanning with a bounded, fully consuming PromQL lexer/parser for the checked-in
  expression grammar. It extracts selector labels plus every `by`, `without`, `on`, `ignoring`,
  `group_left`, and `group_right` label list; malformed, unsupported, or trailing input is rejected.
- Metric references are closed over the default Prometheus translation of `MetricName::ALL`, including
  counter/unit translation and only the generated histogram `_bucket`, `_sum`, and `_count` series.
  Label references are closed over the Prometheus translation of `AttributeKey::ALL` plus generated
  classic-histogram `le`; unused generated `quantile`, `job`, and `instance` labels are not allowed.
- Strict RED copied `sum by (smesh_outcomm) (smesh_a2a_request_total)` and failed because the old scanner
  returned no grouping labels. GREEN rejects `smesh_outcomm`; valid `smesh_outcome`, `le`, and
  `on(smesh_slo)` cases pass. Matching-label typo and malformed/unparsed probes also fail closed.
- All **3 rule expressions** and **5 dashboard target expressions** are parsed and schema-validated. The
  existing three alert annotations and every dashboard Prometheus datasource assertion remain checked.

Focused exact-tree verification:

- `cargo test --test observability_assets`: **6 passed**;
- `cargo clippy --locked --test observability_assets -- -D warnings`: **passed**;
- `cargo fmt --all -- --check` and `git diff --check`: **passed**;
- pinned `prom/prometheus:v3.5.0` promtool: **SUCCESS, 3 rules**;
- the broader all-target Clippy attempt reached an unrelated existing `too_many_lines` failure in
  `tests/atomic_lifecycle.rs`; the focused observability target is warning-clean.

Selected SHA-256 hashes:

- `tests/observability_assets.rs` — `fbd15d76f83235abcd2e1af17c982a1a6f1208c49ce38260688ba3a6f06d00fa`
- `observability/prometheus-rules.yml` — `1273e16c279a1093b65d6602957652ab3beedb444c37f9151b2475ca5795fc26`
- `observability/grafana/smesh-a2a-overview.json` — `32b7ddb80a47815d723c16c4ee7a3b657b628c307ae5a7961a36d69e1106f56d`
## Final asset and lint closure — 2026-08-30

- The observability asset validator now fully parses all checked-in PromQL and validates metric
  selectors, selector labels, aggregation labels, and vector-matching/group labels against the
  emitted telemetry schema. Malformed or partially parsed expressions fail closed.
- The complete v1-to-v7 migration fixture carries a narrow, documented `too_many_lines` allowance
  so its schema, keys, task state, and projection migration remain auditable as one fixture.
- Full all-target/all-feature Clippy with `-D warnings`, formatter, and `git diff --check` pass.

Selected SHA-256 hashes:

- `tests/observability_assets.rs` — `fbd15d76f83235abcd2e1af17c982a1a6f1208c49ce38260688ba3a6f06d00fa`
- `tests/atomic_lifecycle.rs` — `3b6efafa8945aea25baee8122c49f0e4383d1752940efbc33664c55e7350a114`
## Immediate-cancellation span closure — 2026-08-30

- Immediate durable cancellation now maps its post-commit `terminal_commit` span to
  `smesh.durable.commit`, matching the terminal log and the ordinary outbox commit path.
- A strict RED/GREEN regression first observed the incorrect `smesh.durable.admission` span and
  now verifies `SpanName::DurableCommit` while retaining the immediate-cancel rule that no receiver
  `CancellationStopped` fact is emitted.
- Focused live-path, formatter, all-target Clippy, and diff gates pass.

Selected SHA-256 hashes:

- `src/telemetry.rs` — `6a36550d81be283356eb66f318a03c10f23250b44e38fc524022a96e55aacc5a`
- `tests/telemetry_live_paths.rs` — `2c0e9dce6af6bc538ad41859594205d58690c92ea021de280c3b2db7f398a324`
