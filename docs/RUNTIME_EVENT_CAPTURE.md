# Runtime event capture

Runtime mode adapts genuine `smesh_runtime::RuntimeEvent` values into a closed, payload-free trace at
the gateway boundary.

## Required lifecycle events

These are never sampled:

- signal emitted;
- signal received;
- signal reinforced;
- signal expired;
- peer connected;
- peer disconnected.
- review/test/attestation/ratification claims;
- contradiction findings;
- public terminal output and artifact digests.

Required history uses a bounded recent-window RPO rather than a process-lifetime append buffer. The
default standalone window retains at most 768 required events, 256 optional events, and at most 256
required events for one task/signal workload. A saturated workload retires its own oldest intermediate
evidence before consuming more of the process window; global retirement is oldest-completed-first when
many distinct workloads collectively fill the window. Retirement does not cancel the gateway.

Capacity accounting uses a private domain-separated digest of authoritative task plus context. A
signal-hash alias maps hash-only lifecycle events into that same opaque workload key, so one workload
gets one share and identical task IDs in different contexts cannot retire one another.

This is an explicit observability RPO: accepted work remains represented by its most recent bounded
lifecycle window, but events older than the per-workload or process limit may be retired. Durable task,
outbox, audit, and artifact authorities remain the recovery authority. Invalid trusted runtime events,
sequence overflow, and persistence failures still fail closed.

Within a retained workload window, `SignalEmitted` admission and `TerminalOutput` are protected anchors;
intermediate lifecycle events retire first. Completed workload windows retire oldest-first when the
global limit turns over. Thus accepted/terminal RPO is zero for retained windows and explicitly bounded
by window retirement for older completed work.

Operators may lower or raise the bounded windows before startup with
`SMESH_A2A_RUNTIME_TRACE_REQUIRED_CAPACITY` (2..=1023),
`SMESH_A2A_RUNTIME_TRACE_OPTIONAL_CAPACITY` (1..=1022), and
`SMESH_A2A_RUNTIME_TRACE_PER_WORKLOAD_CAPACITY` (2..=the required capacity). Required plus optional
capacity must not exceed 1024, keeping every maximum-shape canonical artifact within replay's 16 MiB
limit. Invalid values fail before the runtime gateway starts serving.

## Optional telemetry

`TickCompleted` is optional telemetry. It records only tick and aggregate signal counts. Once its
separate bounded capacity is full, later tick metrics are dropped and `droppedOptional` increments.
Required lifecycle capacity is unaffected.

## Correlation and ordering

`CorrelatingRuntimeProcessor` binds the emitted signal hash to A2A task/context after genuine runtime
ingress. Registration backfills an already-recorded emission event, closing the runtime-event versus
processor-start race. Only `SignalEmitted` receives direct task/context correlation; later signal
events remain hash-linked and payload-free. Active identity retires at public terminal publication.
A hash cannot bind a different workload while its retained alias/window exists. After that window
retires, a repeated hash may admit new work, but generation-ambiguous intermediate events are
conservatively retired rather than charged to either workload. The fixed 1,024-entry seen-hash history
is bounded; after it saturates, new hashes receive the same conservative intermediate policy. Capacity
rejection never invalidates the process capture.

Every trace event receives:

- producer-local monotonic sequence;
- monotonic microsecond offset;
- allowlisted event kind;
- signal hash where applicable;
- correlated task/context where known;
- closed, typed aggregate/claim/terminal details only.

Runtime payloads, request text, evidence bytes, peer identity material, and raw errors are never
copied into the trace. Gateway claims retain only bounded IDs, subject digests, claim class, and
an asserted outcome where the claim schema contains one. Unvalidated attestations are never labeled
accepted. Public artifacts retain only their policy-bound digests.

## Replay

`RuntimeEventCapture::replay` consumes serialized trace bytes only. It validates schema version,
input/event bounds, contiguous sequence, non-regressing monotonic time, bounded identifiers, and
event/detail shape. It never reads live runtime state.

`runtime-trace/3` rebases the bounded retained artifact to a contiguous local sequence. The configured
RPO is recorded by operator configuration/evidence rather than changing the source-compatible public
`RuntimeTrace` fields. `runtime-trace/2` added
a typed `cancellationOutcome` to cancellation terminal events. `Canceled`
requires `cooperativeStop`; `Failed` may record `forcedAbort` or `failed`. Ordinary terminal events
omit the field. Replay remains compatible with legacy `runtime-trace/1` captures that lack the field,
and with `runtime-trace/2`, and rejects contradictory cancellation state/outcome pairs.

## Persistence and shutdown

Set `SMESH_RUNTIME_TRACE_PATH` to persist the final trace. Persistence uses create-new semantics,
mode `0600` on Unix, a complete JSON document, and `sync_all`; an existing destination or write/sync
failure fails the runtime command. Shutdown stops runtime producers, drains queued runtime events,
then snapshots and persists the trace. A bounded emergency abort remains only for a drain task that
does not honor its five-second stop deadline.

```bash
cargo test --test runtime_event_capture
```

The real-runtime fixture emits a genuine Query through `RuntimeWorker`, consumes the corresponding
`RuntimeEvent::SignalEmitted`, and verifies the captured task/context correlation.
