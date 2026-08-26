# ADR-0001: Runtime and process ownership

- Status: Accepted
- Date: 2026-08-26
- Milestone: M1 — Live SMESH Runtime

## Context

The gateway exposes one A2A agent while SMESH remains the internal coordination and peer-network
layer. A runtime Query admission, a worker completion proposal, and a public A2A terminal task have
different authority and lifecycle semantics. Conflating them would allow ingress or an untrusted
worker to publish artifacts or completion.

## Decision

### A2A request ownership

`DefaultRequestHandler` and the injected `TaskStore` own the externally visible task ledger.
`SmeshExecutor` owns translation between that ledger and one bounded internal execution. Durable A2A
state is authoritative; transient runtime signals are not task records.

### Runtime ownership

The standalone runtime-mode process owns one `SmeshRuntime`, its runtime loop, mesh handle, event
receiver, `RuntimeWorker`, and canonical `RuntimeEventCapture`. Startup validates the configured
runtime node before accepting work.

`RuntimeWorker` owns the command channel and every active processor task. Execute is reserved before
Cancel can overtake it. Cancellation acknowledgement is sent only after cooperative exit or bounded
abort-and-join. Shutdown stops admission and joins all tracked work.

### Completion authority

`SmeshRuntime::emit` proves only local Query admission. It cannot produce semantic evidence,
artifacts, or A2A completion.

Processor artifacts and `MeshEvent::Completed` are untrusted proposals. `SmeshExecutor` buffers
candidates until the worker stream seals. Only `VersionedCompletionPolicy` may publish artifacts and
a public `Completed` task. Required review, test, and explicit contradiction-clearance evidence is
bound to task, context, request, and artifact digests.

### Terminal arbitration

Each execution has one atomic `OPEN`/`CANCEL`/`EXECUTION` winner. Working/progress publication is
serialized against cancellation. Completion-first rejects late cancellation; cancel-first suppresses
completion and waits for runtime termination acknowledgement. Dropping the caller's cancel stream
does not abandon executor-owned cancellation or terminal publication.

### Runtime trace ownership

Runtime mode drains genuine `RuntimeEvent` values into a closed canonical trace. Required lifecycle,
claim, contradiction, and terminal records are never sampled. Optional tick aggregates are shed
first. Any required capture gap invalidates the capture and stops serving; invalid captures cannot be
replayed or persisted as canonical evidence.

The trace excludes payloads, request text, raw evidence, artifact content, peer IDs, keys,
signatures, and raw errors. It contains bounded correlations, canonical digests, producer-local
sequence, and monotonic offsets. Replay consumes trace bytes only and never rereads runtime state.

### Process and subprocess ownership

The M1 semantic harness launches review, test, and contradiction specialists as separate bounded
child processes without a shell or inherited environment. The harness owns their stdin/stdout/stderr,
deadline, cancellation, kill, and reap lifecycle. No hidden retries or orphaned children are allowed.

## Shutdown order

1. Stop accepting or finish serving.
2. Shut down `RuntimeWorker` and join active processors.
3. Shut down runtime and mesh producers.
4. Join the runtime loop within its deadline.
5. Drain queued runtime events; invalidate capture on close, panic, or timeout.
6. Refuse persistence if capture is invalid.
7. Persist with create-new semantics, mode `0600` on Unix, complete write, and `sync_all`.

## Consequences

- Runtime admission cannot be mistaken for task completion.
- Candidate artifacts remain private until policy acceptance.
- Cancellation and shutdown have explicit bounded ownership.
- Canonical evidence fails closed instead of silently containing gaps.
- The in-memory task ledger and process-local receipt keys remain non-durable; M2 owns persistence,
  restart recovery, durable keys, authenticated principals, and tenant isolation.
