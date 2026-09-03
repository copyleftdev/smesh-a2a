# LIFELINE organization-local teams

Issue #22 adds five fictional organization-local SMESH teams behind the six checked LIFELINE gateways. Atlas primary and fallback are separate A2A routes into one Atlas organization runtime. Northstar remains an external Response Director and never calls a team runtime directly.

## Boundary

Each organization owns a separate `SmeshRuntime`, `RuntimeWorker`, node set, local dataset, candidate projection, outcome registry, semantic journal, and runtime event trace. No runtime, mutable field, local record, journal handle, or reinforcement authority is shared between organizations.

The checked catalog is `deploy/lifeline-teams.json`. It is closed to the reviewed bytes after structural validation. Any changed organization, gateway, role, tool, record, projection, candidate, seed, or disclaimer fails startup.

All data is deterministic and fictional. The output is not medical advice, clinical validation, authorization, or evidence of trust.

## Real runtime behavior

A task enters the existing `ChannelDispatcher -> RuntimeWorker -> SmeshRuntime` path. The organization processor then:

1. retains the A2A-derived query in its real runtime;
2. deterministically scores two non-overlapping claim roles;
3. records both claims and the lower-affinity backoff;
4. emits one content-addressed claim from two named runtime nodes;
5. verifies distinct runtime attesters and reinforcement;
6. emits an unsupported short-lived hypothesis, then emits a separately signed runtime claim that names and rejects that hypothesis;
7. advances the runtime for at most 128 ticks and verifies field removal plus history retention;
8. runs one checked local projection and emits one bounded candidate artifact;
9. has three distinct authority-role nodes sign subject-bound review, test, and contradiction-clearance claims in the runtime;
10. exposes completion evidence only after verifying those signatures and matching the exact runtime outcome to the candidate artifact digest.

Pinned SMESH does not define a native contradiction operator. The demonstration therefore does not claim that contradiction causes decay: it proves that the signed contradiction claim names the unsupported hypothesis, and separately proves through real runtime tick events that the hypothesis expires into field history.

Task and context identifiers are included in claims, hypotheses, journals, candidates, and completion subjects. Gateway-scoped internal task identifiers keep Atlas primary and fallback admission and cancellation namespaces separate while the artifact retains the external A2A task and context IDs.

## Journals and bounds

The runner creates a new owner-private output directory. Each organization gets a semantic `<team>.jsonl` journal and a pinned-runtime `<team>.runtime.jsonl` event trace. Both use create-new mode, Unix mode `0600`, a closed event vocabulary, monotonic sequence numbers, and no wall clock, request text, raw local records, credentials, or environment values. Runtime traces are captured from `SmeshRuntime::take_events`; they record emitted hashes and tick outcomes rather than self-authored lookalike events. A monitor barrier drains pending runtime events before an outcome can authorize completion, and a sticky health gate linearizes the final public completion against concurrent capture failure. A monitor, limit, write, or sync failure therefore fails affected active tasks and all subsequent tasks instead of silently dropping trace evidence.

Each semantic journal and runtime trace is independently limited to:

- 512 events;
- 4 KiB per event;
- 256 KiB total.

The candidate is limited to 8 KiB. The manifest is limited to 64 KiB; local records are limited to 32 entries and 8 KiB, and the public projection is limited to 4 KiB. Existing journal files, insecure roots, symlinks, unknown fields, and unreviewed catalog changes fail closed.

## Run

From a clean checkout:

```bash
cargo run --bin lifeline-organization-teams -- \
  deploy/lifeline-teams.json \
  /tmp/lifeline-team-run
```

The command starts ephemeral loopback gateways, invokes the checked Response Director through official A2A clients, waits for four initial completions and the Sentinel review, shuts down listeners before workers, drains runtime event monitors, syncs five semantic journals and five runtime traces, and writes `/tmp/lifeline-team-run/run.json` with mode `0600`. It refuses to overwrite an existing output directory or journal. Dropping a worker owner starts cooperative cancellation even when dispatcher clones remain; explicit shutdown additionally joins workers and syncs files.

The summary is bounded routing and completion metadata. It does not contain request bodies, artifact bytes, local records, runtime topology, headers, credentials, or environment values.

## Verification

```bash
cargo test --test lifeline_teams -- --test-threads=1
```

The integration and unit suites cover the checked five-team/six-gateway mapping, launch-time revalidation, real claim reinforcement, distinct attesters, deterministic backoff, signed contradiction linkage and decay, candidate derivation and bounds, runtime-signed subject evidence, exact task/context binding, duplicate-admission integrity, atomic dropped-consumer cleanup, runtime-trace failure propagation, organization data isolation, Atlas gateway task namespacing, byte-identical semantic journals and canonically identical captured runtime semantics, private create-new journals, official A2A Director traversal, drop-safe cancellation, explicit shutdown, and the one-command runner.
