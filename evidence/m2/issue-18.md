# Issue #18 Aggregate Evidence - Threat Model, Fuzz, Load, and Chaos

Milestone: M2 - Durable, Authenticated Gateway

## Deliverable closure

| Deliverable | Status | Evidence |
|---|---|---|
| STRIDE/data-flow model | complete | `docs/GATEWAY_THREAT_MODEL.md` |
| Protocol/state/page-token fuzzing | complete | issue #74, PR #78, `docs/FUZZING.md`, `fuzz/` |
| Critical-route hostile load | complete | issue #75, PR #79, generated `smesh.hostile-load-evidence/1` report |
| Kill/restart/network/slow-consumer chaos | complete | issue #75 matrix and `docs/CHAOS_QUALIFICATION.md` |
| Residual-risk register | complete | threat model and issues #72-#75 evidence |

## Issue-sized tracks

- #72 / PR #76: SQLite O(1) denial-audit accounting, exact count/UTF-8 byte caps, PostgreSQL
  operator-only bounded retention, projection obligations, populated migration/restart/catalog evidence.
- #73 / PR #77: `runtime-trace/3` bounded recent-window RPO, per-workload isolation, atomic completed
  retirement, reused-hash safety, tenant/attempt-scoped telemetry correlation and nonblocking retirement.
- #74 / PR #78: strict JSON-RPC/A2A ambiguity handling, fixed-seed properties, minimized corpus,
  protocol/policy/page-token/state targets, PR/push/daily fuzz CI.
- #75 / PR #79: synchronized load and slow consumers, deterministic blackhole/reset/heal, continuous
  RSS/FD sampling, retained SQLite bytes, acknowledged-mutation SIGKILL RPO 0, explicit RTOs,
  PostgreSQL failover/tenant/callback/artifact/observability process matrix, machine evidence and cleanup.

All four issues and PRs are closed/merged. Read-only independent Hermes reviewers examined exact local
binary diffs; these are local review records, not formal GitHub reviews or PR comments. Verdicts,
reviewed heads, hashes, and remediation lineage are summarized in `evidence/m2/independent-reviews.md`.
Automatic CodeRabbit reviews remain disabled; manual invocation remains available and was not required.

## Acceptance closure

### No unbounded resource growth

- Authorization-denial append/count is O(1) in SQLite with exact hard caps.
- PostgreSQL authorization cleanup is operator-only, batch-bounded, and projection-safe.
- Runtime trace and telemetry correlation have process and per-workload/attempt bounds.
- Protocol inputs, parser bytes, event/output counts, pagination snapshots, quota reservations,
  callback responses/retries, audit projection, telemetry series/queues, artifact GC, and chaos
  commands have explicit limits/watchdogs.
- Issue #75 stable process evidence measures three complete load epochs and enforces RSS, FD, SQLite,
  latency, and cleanup thresholds.

### No secret or tenant leakage

- Identity and tenant scope are server-derived; spoofable forwarding/correlation/tenant inputs cannot
  grant authority.
- Exact union/token/policy corpora reject ambiguous and cross-scope values.
- Errors, telemetry, evidence, and artifacts are closed/redacted and canary-tested.
- Machine evidence omits bodies, credentials, DSNs, certificates, SQL, and raw errors.

### Recovery meets RTO/RPO

- Client-acknowledged durable mutations: RPO 0.
- SQLite process readiness after SIGKILL: <= 5 seconds; first canary <= 2 seconds.
- PostgreSQL receiver/outbox failover: <= 20 seconds.
- Healthy-tenant quota recovery: <= 15 seconds.
- Callback recovery: <= 20 seconds.
- Artifact checkpoint recovery: <= 90 seconds.
- Observability/audit projection recovery: <= 20 seconds.
- Generated reports require zero leaked process/port/temp/schema/session resources.

### High findings closed or accepted

Closed findings include denial-audit growth, forged cleanup authority, unbounded cleanup diagnostics,
projection-obligation loss, runtime trace exhaustion, cross-workload/tenant correlation, stale generation
retirement, protocol union ambiguity, REST widening, page-token scope/parity, in-memory state regression,
slow-consumer/network isolation, fixture leaks, sparse peak measurement, and CI skip/credential/watchdog
gaps.

Accepted residuals are enumerated in `docs/GATEWAY_THREAT_MODEL.md`; this M2 gate is not a general
production-readiness claim. Runtime trace and OTLP are not durable authority, external
callback/projection delivery is at-least-once, task-bound durable/quota evidence lacks a deletion
lifecycle, forced cancellation cannot retract already issued external effects, full-capacity SQLite
audit startup timing is unmeasured, retention scheduling is operational, reverse-proxy/OIDC governance
is deployment-owned, and host-level reboot/disk/OOM/kernel risks remain deployment responsibilities.

## Repeatable aggregate commands

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo +1.88.0 check --all-targets --all-features
cargo test --all-targets --all-features
cargo test --release --locked --all-targets --all-features -- --test-threads=1
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
cargo audit

cargo test --locked --test protocol_fuzz_regressions -- --test-threads=1
cargo test --locked --test hostile_load_process -- --test-threads=1
python3 scripts/validate_hostile_load_evidence.py target/hostile-load/sqlite-process.json
```

PostgreSQL/fuzz scheduled commands and mandatory fixture setup are executable in
`.github/workflows/chaos.yml` and `.github/workflows/fuzz.yml`.
