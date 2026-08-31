# ADR-0002: Bounded runtime trace and attempt-scoped correlation

Status: accepted

## Context

The original runtime capture retained required events and signal correlations for the process lifetime.
Exhaustion canceled one process-global failure token and stopped the gateway. Optional OTLP dispatch
correlations were also process-lifetime state keyed only by `dispatch_id`.

That design allowed offender churn to terminate runtime mode, grow memory indefinitely, and risk
cross-tenant or cross-attempt identity reuse.

## Decision

Runtime capture uses `runtime-trace/3` with:

- a bounded process required-event window;
- a bounded per-workload share;
- protected `SignalEmitted` and `TerminalOutput` anchors within retained workload windows;
- intermediate-event-first retirement;
- oldest-completed-window retirement under global pressure;
- bounded retirement with operator-visible configuration and checked evidence;
- contiguous sequence rebasing at snapshot time;
- replay compatibility for schemas 1 and 2.

The internal workload key is a domain-separated digest of authoritative task plus context. Bounded
signal-hash aliases map hash-only lifecycle events to that same key and are pruned with retained history.
Completed windows retire atomically so admission and terminal anchors are never split.

Runtime task/context identity is attached only to `SignalEmitted`; later runtime events remain linked by
their signal hash. Active identity retires at terminal publication. This prevents a delayed event after
hash reuse from inheriting or retiring a newer workload while keeping the active map bounded. Retained
aliases forbid cross-workload rebinding. Reuse after window retirement is marked generation-ambiguous;
its intermediate events retire conservatively. A fixed seen-hash history bounds this decision state.

OTLP dispatch correlations are bounded and keyed by `(tenant_scope, dispatch_id, lease_generation)`.
Each claimed attempt owns an RAII guard, so every retry, completion, dead-letter, cancellation, shutdown,
or error exit retires only its exact generation. Telemetry saturation remains optional and cannot block
durable work.

## Consequences

The trace is an explicit recent-window observability RPO, not a durable full-history ledger. Admission and
terminal anchors have RPO zero while their workload window is retained; older completed windows can be
retired. Durable task, outbox, audit, and artifact authorities remain the recovery authority.

Operators can configure the process, optional, and per-workload windows only within validated startup
bounds. Invalid values fail before serving. Collector or correlation saturation can produce telemetry
gaps but cannot change durable outcomes.