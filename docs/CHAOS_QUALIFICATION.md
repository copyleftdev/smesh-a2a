# Hostile Load and Chaos Qualification

Issue #75 closes the process/load/chaos slice of the M2 aggregate gate in issue #18. The suite combines
new process-level measurements with existing deterministic PostgreSQL, callback, artifact, runtime, and
observability crash matrices. It does not use external fault services or touch non-fixture infrastructure.

## Stable process qualification

```bash
cargo test --locked --test hostile_load_process -- --test-threads=1
cargo test --locked --test production_durable_gateway \
  acknowledged_completion_survives_sigkill_with_zero_rpo_and_bounded_rto \
  -- --exact --test-threads=1
cargo test --locked --test runtime_gateway_shutdown \
  saturated_runtime_trace_keeps_gateway_alive_and_healthy_work_bounded \
  -- --exact --test-threads=1
python3 scripts/validate_hostile_load_evidence.py \
  target/hostile-load/sqlite-process.json
```

The Linux process test runs three synchronized epochs. Each epoch contains 128 malformed offender
requests and eight healthy canaries while 16 slow partial HTTP consumers remain connected. A test-owned
TCP proxy injects explicit pass, blackhole, reset, and heal states. No timing race decides whether the
fault is active: new connections read the controller's current mode.

Thresholds:

- every request future: 2 second watchdog;
- canary p95: at most 500 ms;
- canary maximum: at most 1 second;
- 24/24 canaries succeed across three epochs;
- gateway RSS: at most 256 MiB absolute and 64 MiB above warm baseline;
- third-epoch RSS: at most 16 MiB above the second epoch;
- FD peak: no more than the synchronized workload plus 32 harness/server descriptors;
- quiescent FDs: at most warm baseline plus eight;
- checkpointed SQLite growth: at most 2 MiB for the committed test workload;
- acknowledged durable mutation RPO: zero after SIGKILL;
- listener readiness after SIGKILL: at most 5 seconds;
- first recovery canary: at most 2 seconds;
- graceful shutdown and process reap: at most 10 seconds;
- released ports, absent PIDs, SQLite `quick_check=ok`, and removable fixture roots.

The report is written atomically by the test to `target/hostile-load/sqlite-process.json` in a private
0700 directory with a 0600 file. `evidence/hostile-load.schema.json` is closed to unknown fields, and the
dependency-free validator rejects missing metrics, nonzero RPO, incomplete cleanup, or a non-pass
verdict. Reports deliberately omit request bodies, credentials, certificates, DSNs, SQL, and raw errors.
RSS and FD peaks are sampled every two milliseconds from before barrier release until all epoch futures
join. The report includes all three epoch peaks and canary distributions so plateau claims are
machine-verifiable. Canary latency uses one end-to-end watchdog covering headers and body decoding.

## PostgreSQL and dependent-surface matrix

The scheduled/manual `scheduled-postgres-chaos` job provisions an isolated PostgreSQL 17 database with
separate migrator and runtime roles and requires the fixture rather than allowing skip paths. It runs:

- `postgres_multi_replica`: process failover, receiver/outbox barriers, DB-time lease expiry, renewal,
  stale-fence rejection, completion-before-delivery-commit recovery, session/schema/role cleanup;
- `postgres_quota_process`: synchronized offender and healthy-tenant canaries, replica crash reclaim,
  quota fencing, and bounded progress;
- `postgres_push_process`: callback slow/downstream behavior and crash after HTTP 2xx before authority
  commit with stable idempotency evidence;
- `postgres_artifact_process`: production artifact checkpoint crash matrix and recovery;
- `postgres_observability_process`: optional telemetry outage/restart behavior and durable audit
  projection recovery.

Every command has a TERM/KILL watchdog. The job is serial because the tests share PostgreSQL fixture
roles and process resources. `run_postgres_chaos_matrix.py` records every command's observed duration,
watchdog, and RTO target, then requires zero fixture schemas and sessions. Its private atomic report is
validated and uploaded for 14 days. The job cap is 65 minutes and no credentials are uploaded as
evidence.

## RPO and RTO interpretation

- Client-acknowledged durable task mutations: RPO 0. The new SIGKILL tests recover the exact task and
  then complete a healthy canary.
- Unacknowledged mutations at a crash boundary: may be absent or coherently committed; partial authority
  state is forbidden by the existing atomic lifecycle and PostgreSQL transaction matrices.
- Receiver/outbox failover: bounded by the explicit test lease, polling interval, and watchdog in the
  multi-replica suite; published qualification RTO <= 20 seconds.
- PostgreSQL healthy-tenant quota recovery: RTO <= 15 seconds.
- Callback crash/failover recovery: RTO <= 20 seconds.
- Artifact checkpoint recovery: RTO <= 90 seconds.
- Observability/audit projection recovery: RTO <= 20 seconds.
- Callback delivery: externally at-least-once; stable event/idempotency identifiers are the deduplication
  boundary. Durable callback authority remains RPO 0.
- Optional OTLP export: lossy by design and never authority. Durable audit projection remains the replay
  source.
- Runtime trace: a bounded recent-window artifact, not durable authority. SIGKILL may lose the current
  in-memory capture because persistence is graceful-shutdown-owned. This does not weaken durable task,
  outbox, audit, callback, or artifact RPO claims.

## Residual risks

- GitHub-hosted RSS and latency are qualification signals, not production capacity planning.
- `/proc` RSS/FD metrics are Linux-specific.
- The deterministic TCP proxy covers application-visible blackhole/reset/recovery, not kernel packet
  corruption, host reboot, disk-full, cgroup OOM, or physical network partitions.
- PostgreSQL packet-level committed-response-loss remains represented by transaction ambiguity and
  process failover tests rather than a PostgreSQL wire-protocol parser.
- A scheduled suite does not establish multi-day allocator, autovacuum, filesystem, or callback-endpoint
  behavior.
- SQLite is intentionally single-writer and does not claim PostgreSQL deployment parity.
