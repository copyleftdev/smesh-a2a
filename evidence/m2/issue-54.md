# Issue #54 durable receiver and driver evidence

## Scope

This change integrates the repository-owned durable request handler, sender outbox driver, receiver inbox, exact public transcript replay, cancellation, continuation, and production loopback+SQLite startup.

The durable guarantee is deliberately limited to the owned loopback adapter's transactionally committed local effect marker and transcript. Arbitrary remote effects and SMESH runtime execution do not yet expose an enforceable stable-effect idempotency boundary. Runtime+SQLite therefore fails before resource acquisition rather than making an exactly-once claim.

## Delivered invariants

- Canonical message identity is scoped by the trusted single-tenant sentinel and sender messageId.
- Omitted/default response controls normalize to the same execution identity.
- Unary and streaming invocation kinds remain distinct.
- Admission atomically commits task, event, idempotency result, and message-bound outbox intent.
- Receiver capacity is acquired before acceptance.
- Receiver processing is leased and fenced by epoch, owner, token, payload digest, and expiry.
- Receiver completion, ordered frames, transcript digest, and loopback effect marker commit in one transaction.
- Completed delivery replays exact immutable receiver and public transcripts without rerunning the effect.
- Sender delivery atomically commits task transition, event, public transcript, message-scoped idempotency result, outbox acknowledgement, and attempt completion.
- Completion, cancellation, and dead-lettering produce one terminal winner.
- Pending, active, interrupted, recovered, and continuation cancellation are SQLite-authoritative.
- Earlier completed message results remain unchanged after continuation.
- Streaming and subscriptions reconcile persisted cursors; transient watches are wake optimizations only.
- REST errors use pre-stream HTTP/google.rpc.Status responses; established SSE contains only StreamResponse values.
- Explicit shutdown joins admission, ticker, driver, and SQLite ownership. Drop aborts owned work and releases shared ownership without claiming an async join.

## Deterministic evidence

- Official JSON-RPC and HTTP+JSON unary, streaming, subscription, cancellation, and continuation tests.
- Cross-binding replay in both directions.
- Immediate Task, persisted Working progress, artifact, and one terminal status event.
- Duplicate attachment, disconnect/reconnect, history projection, output-mode negotiation, and one-shot errors.
- InputRequired and AuthRequired interruption plus same-task continuation and exact per-message replay.
- Named subprocess checkpoints around admission, receiver acceptance, receiver completion, and sender commit.
- Final-attempt reconciliation with frozen clocks and no attempt inflation.
- Cancel-first, completion-first, and dead-letter-first arbitration.
- Stale sender/receiver fencing and bounded shutdown.
- Schema v1-v4 migration, rollback, exact object/trigger/index validation, FK checks, UTF-8 bounds, corruption probes, and restart recovery.
- Production process startup, SIGINT shutdown, restart replay, automatic system-clock retry, SQLite lock reacquisition, and runtime+SQLite resource-free rejection.

## Exact-tree local gates

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
cargo audit
git diff --check
```

All gates passed on the final local tree. cargo audit reported only the pre-existing allowed unmaintained bincode 1.3.3 warning inherited through pinned smesh-core/smesh-runtime; no vulnerability failure.

## Explicit exclusions

- Durable SMESH runtime effect execution and replay.
- Arbitrary third-party durable dispatcher implementations.
- Cross-tenant authority, which remains issue #13.
- Push notifications, which remain unsupported pending issue #17.
