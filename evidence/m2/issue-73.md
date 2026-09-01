# Issue #73 Evidence - Runtime Trace and Correlation Isolation

Parent qualification gate: #18

## Closed risks

- Required runtime events no longer form a process-lifetime vector whose exhaustion cancels the gateway.
- One signal/task workload cannot retain more than its configured share of required trace history.
- Runtime task/context correlation applies only to `SignalEmitted` and retires at public terminal publication; delayed events on a reused/ambiguous hash are conservatively retired and cannot alias identity.
- OTLP dispatch correlations are no longer keyed by `dispatch_id` alone.
- OTLP dispatch correlations are bounded, tenant-scoped, lease-generation-fenced, and retired by an attempt-owned RAII guard on every exit.
- A stale attempt guard cannot remove a newer generation, and a retired correlation cannot be reused to emit another tenant's identity.

## Runtime trace RPO

`runtime-trace/3` is a bounded recent-window artifact:

- process required-event window: 768 events by default in the standalone runtime gateway;
- per-workload required-event window: 256 events;
- optional tick window: 256 events by default;
- required plus optional configuration is capped at 1,024 total events and verified at maximum field sizes against the 16 MiB replay limit.

When one workload exceeds its share, its oldest intermediate event is retired first while admission and terminal anchors remain. When many workloads collectively exceed the process bound, the oldest completed workload window retires first. The retained artifact is sequence-rebased and remains replayable. Durable task/outbox/audit/artifact state remains the recovery authority; this trace RPO does not claim durable full-history retention.

Admission (`SignalEmitted`) and terminal output are protected anchors inside each retained workload
window; intermediate events retire first. Completed workload windows retire oldest-first at global
turnover. The healthy process fixture requires both anchors to remain after offender saturation.

An opaque domain-separated task-plus-context key unifies correlated admission, hash-only lifecycle,
and terminal events for retention accounting. Bounded hash aliases are pruned with retained history;
identical task IDs in different contexts have independent shares. Completed windows retire atomically.

Cross-workload hash rebinding is rejected while the old retained alias/window exists. After atomic
window retirement, a repeated hash can admit a new `SignalEmitted`, but generation-ambiguous
intermediate events are counted as retired rather than charged to old or new evidence. Seen-hash state
is fixed at 1,024 entries; saturation applies the same conservative policy without growing memory.
The regression also delays an old expiry until after alias retirement and proves two healthy admission
anchors remain byte-for-byte present.

## OTLP correlation lifecycle

The in-memory key is `(tenant_scope, dispatch_id, lease_generation)`. The value carries the authoritative message/task/context. A guard is created after each authoritative outbox claim and dropped on retry, terminal commit, dead-letter, cancellation, shutdown, panic/error unwind, or any other attempt exit. Stale and current attempts cannot read or remove one another's state.

Guard drop is non-blocking: an atomic retired bit makes identity inaccessible immediately, `try_lock`
performs best-effort physical removal, and the next successful registration prunes retired entries.

The production correlation cap equals the bounded OTLP log queue. Saturation increments the existing optional queue-full drop counter and does not block durable work.

## Deterministic qualification

```bash
cargo test --locked --test runtime_event_capture -- --test-threads=1
cargo test --locked --test runtime_gateway_shutdown -- --test-threads=1
cargo test --locked --test telemetry_live_paths -- --test-threads=1
cargo test --locked --test telemetry_schema -- --test-threads=1
cargo test --locked --lib dispatch_correlation_tests -- --test-threads=1
```

The runtime saturation fixture records 64 required offender events into an eight-event process window with a two-event workload share, then records a healthy workload terminal event. It asserts:

- capture remains valid and the failure token is not canceled;
- offender retention never exceeds two events;
- the healthy terminal remains present;
- correlations retire to zero;
- retirement is counted;
- the bounded trace round-trips through offline replay.

A real subprocess fixture starts the runtime gateway with the same eight/two limits, completes 24
offender requests, then requires a healthy canary to finish within one second while the process remains
alive. SIGINT must still exit cleanly and persist a replayable trace with at most eight required events
and the healthy admission/terminal anchors retained.

The OTLP fixture holds two scoped active correlations, attempts 10,000 additional offender insertions, and asserts:

- map size remains exactly two;
- saturation completes under a 250 ms watchdog;
- duplicate dispatch IDs in different tenants remain distinct;
- overlapping stale/current lease generations emit only their own authoritative identity;
- identical dispatch IDs in different tenants derive different span roots/links;
- artifact registered events carry the complete task/context/message/dispatch set, while corruption/resolution events omit the causal set rather than emit a partial identity;
- retirement remains non-blocking while the physical registry mutex is deliberately held;
- capacity recovers immediately after retirement;
- healthy authoritative identity is emitted after recovery;
- post-retirement emission is rejected;
- stale generation guards cannot remove replacement state.

The production SQLite gateway fixture additionally asserts that a completed live dispatch leaves zero retained dispatch correlations.

## Residual risk

Runtime trace history is intentionally a bounded recent window, not a durable full-history ledger. Operators requiring longer history must persist snapshots before their configured window turns over or rely on durable authority/audit data. OTLP remains optional and lossy; collector or correlation saturation may create telemetry gaps without affecting durable service.