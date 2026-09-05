# LIFELINE failure, cancellation, and fallback scenario

This is a closed fictional loopback scenario. It is not a production-readiness claim, medical advice, or clinical validation.

## Run

From the repository root, use one command with a destination that does not exist:

```bash
out="/tmp/lifeline-failure-$PPID-$$"; test ! -e "$out" && timeout 120s cargo run --locked --quiet --bin lifeline-failure-scenario -- deploy/lifeline-teams.json "$out"
```

The command starts the production-like organization-team topology, faults only the `atlas-primary` route, requires the official client to observe an injected SSE response-body error, drives all network operations through official A2A clients, verifies both artifacts after readback, shuts down every listener and worker, and prints the created `run.json` path.

Outputs are private and create-new:

- `run.json`: measured scenario receipt, including task identities, attempt counts, sibling dispatch count, and final primary state.
- `restricted-scenario.jsonl`: restricted causal evidence using `lifeline-failure-scenario/1`. The causal artifact is JSONL and remains private.
- `journals/`: organization-local semantic and runtime journals.

The trace has an explicit final `scenario-completed` record. The verifier rejects unterminated or blank-line JSONL, sequence gaps, invalid parents, extra or unknown fields, missing or downgraded stream/cancellation evidence, more than one fallback attempt, missing sibling submissions or completions, inconsistent replacement identities, and a final primary state other than `Canceled`. The scenario builds the complete artifact set in a private, lease-owned staging directory, synchronizes nested journal and artifact directories, and atomically publishes the set without replacing an existing destination. A later invocation removes only stale, owner-validated staging directories while preserving actively leased runs.

Replay and cross-check a retained receipt and trace independently:

```bash
timeout 20s cargo run --locked --quiet --bin lifeline-failure-scenario -- verify "$out/run.json" "$out/restricted-scenario.jsonl"
```

Normal organization-team behavior remains available through:

```bash
out="/tmp/lifeline-teams-$PPID-$$"; test ! -e "$out" && timeout 20s cargo run --locked --quiet --bin lifeline-organization-teams -- deploy/lifeline-teams.json "$out"
```
