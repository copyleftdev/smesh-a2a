# Issue #75 Evidence - Local Reliability, Load, and Recovery

Parent aggregate gate: #18

This is authorized local validation of the repository's own gateway. Faults are injected only into
test-owned child processes, loopback sockets, SQLite fixtures, and CI-owned PostgreSQL schemas.

## New deterministic evidence

### Process load and network recovery

```bash
cargo test --locked --test hostile_load_process -- --test-threads=1
python3 scripts/validate_hostile_load_evidence.py \
  target/hostile-load/sqlite-process.json
```

The process test executes three synchronized epochs totaling 384 malformed offender requests and 24
healthy canaries while 16 partial HTTP consumers remain connected. The test-owned TCP proxy proves
pass, blackhole, reset, and recovery behavior. It samples Linux RSS and FD state, checkpoints SQLite,
SIGKILLs the process after an acknowledged mutation, restarts on the same address/database, recovers the
acknowledged task, completes a recovery canary, and verifies process/port/database cleanup.

Acceptance is executable in `tests/hostile_load_process.rs` and summarized in
`docs/CHAOS_QUALIFICATION.md`. The generated report conforms to the closed
`evidence/hostile-load.schema.json` contract and contains no request bodies, tokens, DSNs, certificates,
SQL, or raw errors.
Peak RSS/FD sampling runs every two milliseconds for each complete synchronized epoch. The report
contains three per-epoch peak/latency records, and canary latency covers HTTP response body decoding
inside the same two-second deadline.

### Official-client acknowledged-mutation RPO

```bash
cargo test --locked --test production_durable_gateway \
  acknowledged_completion_survives_sigkill_with_zero_rpo_and_bounded_rto \
  -- --exact --test-threads=1
```

A terminal task acknowledged through the official A2A JSON-RPC client survives immediate SIGKILL. A
fresh production gateway process reopens the same SQLite authority, returns the exact task, completes a
healthy canary within the five-second restart RTO, releases the port, and leaves `PRAGMA quick_check=ok`.

## Existing deterministic matrix promoted into the gate

`evidence/m2/issue-75-matrix.json` is the machine-readable scenario index. The new workflow runs the
stable process slice on pull requests and main pushes. Daily/manual PostgreSQL qualification serially
runs existing process matrices for:

- multi-replica failover, DB-time leases, renewals, stale fences, and effect-once recovery;
- synchronized offender/healthy-tenant quota isolation and crash reclaim;
- callback slow/downstream handling and 2xx-before-authority-commit recovery;
- artifact production checkpoint crash recovery;
- observability outage and durable audit-projection recovery.

The PostgreSQL fixture is mandatory (`SMESH_POSTGRES_TEST_REQUIRED=1`) and uses separate test migrator,
runtime, and superuser URLs. Every command and job has bounded TERM/KILL watchdogs.

Local PostgreSQL 17 qualification executed serially against one task-owned loopback fixture:

- multi-replica: 2/2;
- quota process: 2/2;
- callback process: 2/2;
- artifact process: 2/2;
- observability process: 1/1;
- post-suite fixture schemas: 0;
- post-suite migrator/runtime sessions: 0.

The scheduled runner writes `target/hostile-load/postgres-process.json` with observed command durations,
command watchdogs, published RTO targets, scenario pass/fail state, and measured schema/session cleanup.
The report is validated against `evidence/chaos-matrix-result.schema.json` and uploaded on every run.

## Explicit RTO/RPO

| Surface | Gate |
|---|---|
| Client-acknowledged durable task mutations | RPO 0 |
| SQLite SIGKILL listener readiness | <= 5 seconds |
| First post-restart canary | <= 2 seconds |
| Stable request watchdog | <= 2 seconds each |
| Healthy canary p95 / max | <= 500 ms / <= 1 second |
| Graceful process reap | <= 10 seconds |
| Runtime required trace window | bounded recent-window RPO from issue #73 |
| Callback external delivery | at-least-once with stable deduplication identity |
| PostgreSQL receiver/outbox failover | <= 20 seconds |
| PostgreSQL healthy-tenant quota recovery | <= 15 seconds |
| Callback crash/failover recovery | <= 20 seconds |
| Artifact checkpoint recovery | <= 90 seconds |
| Observability/audit projection recovery | <= 20 seconds |
| Optional OTLP | lossy, never authority |

Unacknowledged operations may be absent or coherently committed after a crash, but the existing atomic
lifecycle/transaction suites forbid partially committed authority state.

## Resource and cleanup gates

- peak RSS <= 256 MiB and <= warm baseline + 64 MiB;
- third-epoch RSS <= second-epoch RSS + 16 MiB;
- peak FDs bounded by the synchronized workload plus 32 fixed descriptors;
- quiescent FDs <= warm baseline + 8;
- checkpointed SQLite retained growth <= 2 MiB for the test workload;
- old and restarted PIDs absent after reap;
- gateway/proxy ports released;
- SQLite `quick_check=ok`;
- PostgreSQL scheduled fixtures require zero run-scoped sessions and fixture cleanup through their
  existing guards.

## Residual-risk register

- Runtime trace persistence is graceful-shutdown-owned. SIGKILL may lose the current in-memory trace;
  durable task/outbox/audit/callback/artifact authorities remain the RPO source.
- The TCP proxy qualifies application-visible blackhole/reset/heal behavior, not kernel packet
  corruption, physical partitions, host reboot, disk-full, or cgroup OOM.
- PostgreSQL committed-response-loss is represented by ambiguity/failover qualification rather than a
  PostgreSQL wire-protocol parser.
- GitHub-hosted RSS/latency are reliability qualification signals, not production sizing data.
- Scheduled tests do not establish multi-day allocator, autovacuum, filesystem, callback endpoint, or
  collector behavior.
