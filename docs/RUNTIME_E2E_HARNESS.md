# Runtime end-to-end harness

Issue #5's deterministic harness exercises the complete accepted path without changing production
completion policy:

```text
official A2A client
  -> real Axum socket
  -> SmeshExecutor
  -> ChannelDispatcher
  -> RuntimeWorker
  -> genuine SmeshRuntime Query
  -> private candidate artifact
  -> review specialist process
  -> test specialist process
  -> contradiction specialist process
  -> VersionedCompletionPolicy
  -> accepted terminal Task + artifact
```

Run it locally:

```bash
cargo test --test specialist_process --test runtime_e2e_harness
```

## Process protocol

The harness executes the exact Cargo-built `smesh-e2e-specialist` binary directly, never through a
shell or `PATH`. Each invocation receives one closed-schema JSON document on stdin and emits one
bounded closed-schema decision on stdout. The child environment is cleared, execution has a
2-second deadline, and output is capped at 4 KiB before it becomes policy evidence.
Both stdout and stderr are read through bounded pipes. Timeout or cancellation kills and reaps the
child before the harness proceeds.

Roles are fixed and unique:

- `review` -> `review-authority`;
- `test` -> `test-authority`;
- `contradiction` -> `contradiction-monitor`.

Each role runs exactly once. Role/issuer mismatches, rejection, malformed JSON, timeout, nonzero
exit, excessive output, duplicate candidate/completion events, or incomplete worker streams fail the
A2A task without publishing the candidate artifact.

Every specialist independently recomputes the artifact-set digest from the exact artifact name,
media type, and bytes, then echoes task ID, context ID, and subject digest. The parent rejects any
binding mismatch before constructing `CompletionEvidence`.

## Correlation and replay evidence

The harness records task ID, context ID, runtime signal hash, candidate creation, specialist role and
process ID, evidence emission, and terminal publication. Every event must bind to the originating
task/context. The test rejects hidden specialist retries and requires at least two distinct child
process IDs. Every attempt must have a matching reaped event; cancellation waits for the active
specialist wrapper to stop.

A private `target/harness-artifacts/run-<pid>-<sequence>.json` trace is written atomically with mode
`0600` on Unix. Successful tests verify and remove it. If the harness unwinds before completion, the
drop guard leaves the trace behind with attempted role, PID, bounded failure detail, and reap state.

## Scope

This is deterministic integration evidence, not a production identity system. Specialist issuer
labels are locally configured structural authorities. Authentication, revocation, durable replay,
and production multi-organization evidence remain later milestones.
