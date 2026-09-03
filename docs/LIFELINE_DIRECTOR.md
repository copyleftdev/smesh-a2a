# LIFELINE Response Director

The Response Director is a thin external A2A client for the fictional, loopback-only LIFELINE scenario. It resolves the six reviewed public Agent Cards, creates one root incident context, commissions four child tasks concurrently, uses JSON-RPC, HTTP+JSON, and streaming paths, reconnects through GetTask and SubscribeToTask, cancels a stalled logistics primary, redelegates only that task to the reviewed fallback, and requests an independent review.

## Run

From a clean checkout:

```bash
cargo run --bin lifeline-response-director -- \
  deploy/lifeline-topology.json \
  deploy/lifeline-director.json \
  /tmp/lifeline-director-run.json
```

The command starts the checked local topology, runs the official A2A Rust clients, shuts down every listener, and creates the output file with mode `0600`. It refuses to overwrite an existing output file.

The checked director manifest is a closed run plan. Only loopback ports may vary in test fixtures. Card discovery and task transports disable redirects and ambient proxies. Resolved interfaces must remain on the exact discovery origin and expose only the reviewed JSON-RPC and HTTP+JSON paths.

Fallback is fail-closed. The Director may use Atlas fallback when the primary is unavailable during discovery, before any commission can be accepted, or when an acknowledged primary task is confirmed `Canceled`. Failed, rejected, mismatched, or ambiguously reachable tasks do not authorize redelegation. Once a task ID is observed, later reconciliation errors trigger a bounded best-effort cancellation before the run fails.

## Run record

The run record contains:

- validated Agent Card discovery receipts for every available gateway, plus an explicit failure receipt when Atlas primary is unavailable before commission;
- the fictional run and root context IDs;
- four initial operation receipts in the normal run, or three receipts plus an explicit primary discovery failure in the pre-commission fallback run;
- an optional logistics fallback receipt linked by `replacesTaskId`;
- the independent review receipt with explicit A2A `referenceTaskIds` for every acknowledged child and fallback task;
- every director-generated or observed message, task, and artifact ID;
- the selected public gateway and protocol binding;
- GetTask, SubscribeToTask, and cancellation observations.

The record stores identifiers and public routing evidence, not request bodies, artifact bytes, headers, credentials, environment values, or private SMESH topology.

Before evidence is retained or forwarded to the independent review, each decoded Agent Card, task, and stream event must fit the 64 KiB local evidence bound. Protocol identifiers are limited to 128 safe ASCII identifier characters. The upstream official client performs decoding before these checks; this fixture therefore treats the limits as retention and cross-agent boundaries, not as transport-level byte quotas.

## Scope and safety

This is a deterministic local interoperability fixture. `local-none` is not production authentication or authorization. Agent Cards are capability metadata only; they are not evidence of trust, clinical validation, medical advice, or authority to act. The standalone Director run record is director-observed public A2A evidence only. Issue #22 can compose that same external boundary with five real organization-local SMESH runtimes, but neither fixture claims the full A2A x SMESH x tool x artifact x human capture owned by later LIFELINE milestones.
