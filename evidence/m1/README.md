# M1 replayable evidence bundle

This directory closes the evidence gate for **M1 — Live SMESH Runtime**.

## Contents

- `manifest.json` binds every checked-in artifact by SHA-256 and records the six merged child gates.
- `runtime-trace.json` is a genuine `RuntimeEvent::SignalEmitted` capture produced by the real
  `SmeshRuntime`/`RuntimeWorker` fixture, correlated to A2A task and context IDs.
- [`../../docs/ADR-0001-RUNTIME-PROCESS-OWNERSHIP.md`](../../docs/ADR-0001-RUNTIME-PROCESS-OWNERSHIP.md)
  records process, runtime, cancellation, completion, trace, and shutdown ownership.

The substantial official-client → runtime → separate specialist processes → policy-accepted artifact
proof remains executable in `tests/runtime_e2e_harness.rs`. The checked-in runtime fixture is a small,
inspectable replay artifact; it is not substituted for that multi-process acceptance test.

## Verify

```bash
cargo test --test m1_evidence_bundle
cargo test --test runtime_e2e_harness
cargo test --test runtime_worker --test runtime_terminal_races --test runtime_event_capture
cargo test --all-features --no-fail-fast
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
```

`m1_evidence_bundle` verifies all artifact hashes, validates the six issue/PR/merge gates, and replays
the runtime trace without reading current runtime state.

## Scope

This bundle proves the M1 runtime boundary and its executable tests. It does not claim production
readiness. Durable task storage, restart recovery, durable policy keys, authenticated principals,
tenant authorization, distributed quotas, and deployment hardening remain M2 work.
