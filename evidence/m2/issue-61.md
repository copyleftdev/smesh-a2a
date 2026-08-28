# Issue 61 — enforced backend-neutral durable authority

## Outcome

Production durable code now consumes an object-safe `Arc<dyn DurableAuthority>`
umbrella composed from narrow required traits: identity, scoped reads, admission,
lifecycle, outbox, receiver, transcript, cancellation, audit, change observation,
diagnostics, and shutdown. Required methods have no defaults, and a rustdoc
compile-fail probe proves a blank implementation cannot conform.

Backend-neutral scope/audit/effect, identity canonicalization, and durable
command/result types live in `durable_authority`, not `sqlite_store`. The
production durable handler has no `sqlite_store` reference. SQLite delegates each
narrow trait to its existing schema-v6 transaction methods.

## Scope and compatibility

Global get/list/replay/cancel/final-result/transcript methods are absent from the
public production authority. Local development uses a crate-private
`LocalDevelopmentCompatibility` dependency supplied only by SQLite's opaque
conversion parts. The authorized builder deliberately discards that adapter.

`AuthorizationMiddlewareState::with_sqlite(policy, store, clock)` is restored as
a forwarding compatibility constructor. An external integration compile probe
checks its exact function type. Existing SQLite durable gateway calls remain
source-compatible.

Issue #61 exposes no lease-renewal methods. Issue #63 owns a future negotiated
renewal capability together with runtime renewal calls and atomic fencing.

## Polling and failure semantics

`PollInterval` validates `10ms..=5s`; `ChangeObservation` can no longer publish a
raw `Duration`. The driver, unary waiter, transcript stream, and task-event stream
accept only the validated value. Boundary tests reject zero, 9ms, and 5001ms and
accept 10ms and 5s. SQLite defaults to 100ms, preserving periodic correctness
polling plus process-local wake acceleration.

The spawned driver installs one process-wide panic hook while preserving the
hook present before first spawn. A custom future wrapper sets a thread-local
redaction flag only for each synchronous driver poll and restores it on normal
return or unwind. The hook emits only a fixed generic line for a driver panic,
so payload and location are absent from process stderr, protocol, watch, and
shutdown errors; unrelated panics delegate to the preserved hook. Subprocess
regressions capture stderr and prove the driver canary is absent, the generic
error is present, and a separate unrelated panic canary remains visible. Fatal
publication still wakes all observers and shutdown joins the worker.

## Conformance and evidence

`tests/support/durable_authority_conformance.rs` provides reusable command-level
conformance for future adapters. A watchdog-bounded fixture factory supplies an
`Arc<dyn DurableAuthority>` and RAII cleanup. The harness directly covers
identity/key access, admission/replay/conflict, scoped get/list and cursor,
outbox and receiver fences, progress/delivery, transcript/events, continuation,
cancellation, audit denial/failure, diagnostics/change observation, and shutdown.
A deterministic recording fake asserts tenant/owner/audit/clock/lease arguments;
the same core harness runs against real SQLite state. The full SQLite JSON-RPC
admission/outbox/receiver/get/list lifecycle remains separate local gateway
compatibility evidence and is deliberately not called backend-neutral.

Static checks:

- no `sqlite_store` coupling in `src/durable_handler.rs`;
- no `compatibility_*`, `renew_outbox`, `renew_receiver`, or `LeaseRenewal` symbols;
- no default method bodies in required authority capability traits;
- no `Notify`/`watch` types in the authority API.

## Remaining concrete dependencies

SQLite remains only at construction/open/migration/admin/fault-injection/test
seams and the sealed local-development adapter. No PostgreSQL backend is included.
SQLite remains exclusive-open and keeps shared-clone invalidation on shutdown.

## Final verification (2026-08-27)

- `cargo test --all-targets --all-features -- --test-threads=1` — pass, including
  lifecycle/restart/stress/TLS and the panic regression.
- `cargo clippy --all-targets --all-features -- -D warnings` — pass.
- `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` — pass.
- `RUSTDOCFLAGS='-D warnings' cargo test --doc --all-features` — compile-fail
  authority probe passes.
- `cargo +1.88.0 check --all-targets --all-features` — pass.
- `cargo fmt --all -- --check` and `git diff --check` — pass.
- `cargo audit` — no vulnerabilities; existing allowed warnings remain for
  unmaintained `bincode 1.3.3` and yanked transitive `chacha20 0.10.1`.
