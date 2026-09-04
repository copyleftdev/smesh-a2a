# Full-matrix trace capture

## Purpose

The LIFELINE film must be a replay of observed protocol activity, not animation invented after the fact. The operational demo therefore needs one append-only event ledger that can reconstruct:

- every public A2A discovery, message, task transition, stream update, cancellation, and artifact;
- every internal SMESH emission, send, receive, sense, claim, backoff, reinforcement, attestation, decay, and expiry;
- every bounded tool call and policy decision;
- every human review, amendment, rejection, and ratification;
- the narration and camera cues attached later during editorial work.

The checked-in `demo/lifeline.trace.jsonl` is a deterministic cinematic fixture using schema `1.0.0`. It proves replay, hash chaining, rendering, and export. The operational capture plane described here is the next implementation boundary.

## Issue #23 implemented capture boundary

Issue #23 provides the bounded `full-matrix-capture/1` observation schema and adapters in
`src/full_matrix_capture.rs`. It is deliberately smaller than the complete pipeline below:

- `CanonicalCapture::create_spool` creates a new owner-private JSONL spool (`0600` on Unix). Its closed
  tagged record protocol contains `event`, `failure`, and terminal `complete` records. Each accepted
  event is encoded as one bounded line, written, and `sync_all`ed before the adapter returns;
  the source-local producer sequence advances only after that durable acknowledgement. Existing paths
  are never truncated or appended to. The spool is limited to 16 MiB, each line to 64 KiB, and its
  configured event capacity is mandatory rather than sampled. Bounded lifecycle headroom cannot be
  consumed by events. Call `complete` after the final event; replay and ingestion reject an absent
  completion and reject a failure record, so a crash or failed write cannot revive a valid prefix.
- `CanonicalCapture::new` is an in-memory schema/test collector. A later `persist_new` export is useful
  for fixtures but is **not** durable live capture and must not be described as the canonical production
  path.
- A2A send and receive observations, pinned `smesh_runtime::RuntimeEvent`/`JournalEvent` values, real
  tool closures, artifact bytes, and console `Read`/`Write` are normalized before raw detail is lost.
  Captured content stores only a SHA-256 digest and byte length; this is data minimization, not the full
  publishable redaction policy owned by issue #25.
- Tool call/result, A2A receive/send, and human prompt/decision slots are reserved as a pair before
  invoking the wrapped operation or performing console I/O. Capacity failure therefore occurs before the
  external effect. Tool errors and console write/read/EOF/oversize outcomes consume the terminal slot as
  `toolFailed` or `humanFailed`. A panic, cancellation, or otherwise abandoned reservation marks the
  capture invalid as `unclosedInteraction`; persistence and sequence-gap failures are also explicit and
  fail closed.
- Interaction IDs bind task/context globally, bind paired tool/human subjects, and bind artifact
  production/consumption to one subject and content contract without coupling valid multi-signal SMESH
  observations. Conflicting reuse is rejected. Event parents must already exist; a boundary that cannot
  supply one uses typed `missing` parent data with a reason and a canonical lowercase SHA-256 expected
  event ID. A `missing` claim conflicts if that expected event is already present.
- `ingest_jsonl` accepts completed, validated source-local spools into a durable canonical spool in the
  caller-declared causal order. It preserves producer identity, process instance, source sequence, and
  event ID while assigning only the canonical append sequence. Identical event IDs are idempotent;
  conflicts, regressions, and gaps fail. The complete accepted batch's event count and serialized bytes
  are admitted before its first append; a write failure leaves the destination invalid and incomplete.
  The integration-test executable self-spawns as two bounded,
  simultaneously distinct OS processes, covers all five adapter families, and joins one cross-process
  A2A send/receive causally without adding a shipped fixture binary.
- Replay is parse/validation only. It has no URL, tool, model, clock, or randomness callback and rejects
  unsupported schemas, unknown fields/kinds, invalid IDs, event-ID mismatch, noncontiguous canonical or
  producer sequences, conflicting interactions, and unresolved parents.

The `A2aCaptureAdapter` implements the real `a2a_server::CallInterceptor` contract, and its `before` and
`after` hooks are exercised directly for schema coverage. `capture_unary` owns the paired unary lifecycle
and invalidates an open reservation if dispatch is cancelled or panics. The pinned `a2a-server-lf`
`InterceptedHandler` does not implement `RequestHandler`, and `CallInterceptor::after` receives one unary
`Value` rather than streaming frames. Consequently issue #23 does not install this interceptor into every
existing topology/director router and does not claim live streaming-frame coverage. A production router
wrapper must capture each unary result and every stream frame at the `RequestHandler` seam before making
that broader claim. Raw `before`/`after` use remains schema-hook scope: while a raw pair is outstanding it
blocks finalization and unrelated capture/effects, and abandonment leaves the spool failed rather than
replayable. Callers needing cancellation/panic ownership must use `capture_unary`.

Issue #23 also does not provide deterministic distributed merge, HLC/Lamport ordering, per-producer hash
chains, Merkle roots, or run sealing; those belong to issue #24. Ingestion order here is explicit caller
order and is not permutation-independent.

## Source-of-truth rules

1. One immutable JSON object per line.
2. Producers emit observed facts, not reconstructed conclusions.
3. Corrections, supersession, and redaction are new events.
4. Delivery is at least once; ingestion deduplicates by stable `eventId`.
5. Source-local sequence is authoritative. Cross-source order follows explicit causality, then a deterministic merge key.
6. Capture happens before A2A/SMESH translation discards detail.
7. Presentation time never rewrites protocol time.
8. Terminal lifecycle events, policy decisions, trust changes, artifact manifests, and human approvals are never sampled.
9. A2A task state remains durable after related SMESH signals decay.
10. External A2A metadata can never set internal identity, trust, confidence, or reinforcement.

## Operational envelope

The production envelope extends the cinematic schema with these groups.

### Producer

- producer ID and component (`a2a-gateway`, `smesh-runtime`, `tool-wrapper`, `human-console`);
- process-instance ID and restart epoch;
- strictly increasing source sequence;
- build version, Git commit, and protocol checksum.

### Time and order

- wall timestamp for operator inspection;
- monotonic timestamp and duration for local performance;
- run-relative nanoseconds for film alignment;
- hybrid logical clock for distributed merge;
- Lamport counter;
- deterministic merge key: HLC physical, HLC logical, producer ID, epoch, source sequence, event ID.

64-bit counters and nanosecond values are decimal strings in JSON. Probabilities use integer parts per million. Geographic coordinates use fixed-point `latE7` and `lonE7` values. Replay must not depend on binary floating-point ordering.

### Causality and correlation

- trace ID, span ID, and parent span ID;
- one or more causal parent event IDs;
- typed links such as `caused-by`, `reinforces`, `contradicts`, `supersedes`, `acknowledges`, and `derived-from`;
- A2A context, task, message, and interaction IDs;
- SMESH signal ID and signal hash;
- tool-call and artifact IDs;
- narration line and audio-alignment IDs.

A send and receive are separate observations joined by one interaction ID. This preserves retries, fan-out, missing delivery, and different observations at each endpoint.

### Channel and lifecycle

Every event declares a channel family:

| Family | Representative events |
|---|---|
| `a2a` | agent discovered, message accepted, task submitted, status changed, cancellation requested/acknowledged |
| `smesh` | signal emitted/sent/received/sensed, task claimed/backed off, signal reinforced/attested/decayed/expired |
| `tool` | call requested/authorized/started/progress/completed/failed/timed out |
| `artifact` | artifact declared/stored/linked/verified/superseded/redacted |
| `human` | review opened, amendment requested, recommendation rejected, decision ratified |
| `system` | run started, node restarted, peer connected, capture gap detected, run sealed |

Lifecycle fields include machine, transition, from/to state, attempt, terminal flag, and reason code. Terminal A2A states are absorbing. A cancellation request and dispatcher acknowledgement are distinct events.

### Assessment semantics

The trace keeps these concepts separate:

- authentication: whether identity was verified;
- trust: relationship-scoped belief, with model and before/after values;
- confidence: claim-local certainty from the producing component;
- reinforcement: independent corroboration count;
- attestation: a verified statement over a signal hash;
- reputation: a longer-lived projection derived from trust observations.

Every trust update records model version, prior, observation, weight, posterior, and evidence event IDs. Replay consumes the recorded result; it never recalculates trust with a newer model.

### Payload and redaction

Large content lives in a content-addressed artifact store. Events carry summaries, media types, digests, sizes, and portable artifact references rather than local paths.

Redaction happens before public persistence:

1. classify fields as public, internal, confidential, PII, PHI, or secret;
2. drop secrets completely;
3. replace stable sensitive identifiers with run-scoped HMAC handles;
4. replace sensitive content with typed placeholders;
5. record JSON Pointer-level redaction actions.

The public trace hashes the sanitized event. A restricted original digest, if policy permits one, belongs only in an encrypted audit manifest.

### Integrity

- canonicalize JSON with one documented canonicalization algorithm;
- hash every artifact and payload;
- maintain one hash chain per producer;
- compute a run-level Merkle root after deterministic merge;
- seal the replay bundle with event count, JSONL digest, artifact-manifest digest, projector versions, and final projection digests.

The current fixture uses SHA-256 over Rust/Serde's stable struct-field serialization and a single global previous-event hash. This proves repeatability inside this implementation; it is not a cross-language canonicalization standard, authenticity signature, or production tamper seal. The multi-producer implementation will adopt a documented canonical JSON algorithm, per-producer chains, signatures where policy requires them, and a run seal.

## Capture pipeline

```text
A2A interceptor ─┐
SMESH journal ───┤
Tool wrapper ────┤
Artifact store ──┼─> source adapter
Human console ───┤       |
OTel bridge ─────┘       v
                     normalize
                        |
               schema + authority checks
                        |
                 classify + redact
                        |
              source sequence + HLC
                        |
             canonicalize + hash
                        |
          local append-only spool + ACK
                        |
           collector dedupe by event ID
                        |
       deterministic causal merge + index
                        |
          task/signal/trust projections
                        |
        JSONL / live inspector / film replay
```

Each producer owns a local spool, so no global lock sits on the hot path. The collector acknowledges only after durable append. Sequence discontinuities emit `system.capture-gap`; missing causal parents emit `system.missing-parent`. Backpressure drops optional metrics before lifecycle events.

## Deterministic replay

Merge events by:

1. explicit causal parents;
2. HLC physical time;
3. HLC logical counter;
4. producer ID;
5. producer epoch;
6. source sequence;
7. event ID.

A child arriving before its parent remains pending. Finalization either resolves it or emits a missing-parent event.

Replay never rereads URLs, reruns a model or tool, recalculates trust, regenerates random choices, or infers decay from current wall time. Probabilistic decisions record algorithm, seed, draw, threshold, and result. Signal decay records field ticks and checkpoints.

## Conformance gates

- Every nonblank line parses as one JSON object and validates against its schema version.
- Event IDs reproduce from their documented preimage.
- Duplicate IDs are idempotent; conflicting content under one ID is fatal.
- Source sequence increases strictly within producer instance and epoch.
- The causal graph is acyclic; every parent precedes its child after merge.
- Randomized ingestion order produces byte-identical merged JSONL.
- Every accepted task has exactly one terminal transition.
- Terminal states never regress.
- Artifacts bind to exactly one task and context.
- Cancellation request, dispatcher acknowledgement, internal stop, and durable terminal state are all present.
- Human ratification references the exact hashes of reviewed artifacts.
- The public bundle contains no secrets, PII, or PHI.
- A normalized replay of the same run produces the same run seal.

## Film contract

Narration and actor dialogue are distinct projections. Both reference source event IDs. Audio alignment controls playback time but cannot alter event time. Every packet, filament, status label, artifact, contradiction, failure, and human ring in the film must point back to a committed event.
