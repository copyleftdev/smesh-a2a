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

Required-capacity exhaustion is an error. The standalone runtime gateway stops serving rather than
continue with an incomplete lifecycle trace.
The snapshot is marked `captureValid: false`; invalid snapshots cannot be replayed or persisted as
canonical traces.

## Optional telemetry

`TickCompleted` is optional telemetry. It records only tick and aggregate signal counts. Once its
separate bounded capacity is full, later tick metrics are dropped and `droppedOptional` increments.
Required lifecycle capacity is unaffected.

## Correlation and ordering

`CorrelatingRuntimeProcessor` binds the emitted signal hash to A2A task/context after genuine runtime
ingress. Registration backfills an already-recorded emission event, closing the runtime-event versus
processor-start race.

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

`runtime-trace/2` adds a typed `cancellationOutcome` to cancellation terminal events. `Canceled`
requires `cooperativeStop`; `Failed` may record `forcedAbort` or `failed`. Ordinary terminal events
omit the field. Replay remains compatible with legacy `runtime-trace/1` captures that lack the field,
but rejects v1 traces that try to carry v2 cancellation claims and rejects contradictory v2
state/outcome pairs.

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
