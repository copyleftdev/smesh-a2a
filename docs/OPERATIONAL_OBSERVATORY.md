# Operational observatory projection (Wave 1)

Issue #28 Wave 1 adds a backend-neutral projector from a **verified** `full-matrix-replay/1` bundle and canonical `full-matrix-replay-receipt/1` receipt to `operational-observatory/1` JSONL. It does not implement the WebGL/browser observatory, scorecard, film, or publication.

## Trust and input boundary

`project_operational_observatory` requires the replay bundle, receipt, and caller-pinned run seal. It calls `verify_replay_receipt` before parsing projection records. It has no URL, network, filesystem, clock, random, model, tool, policy, or remote-code callback. The library therefore cannot fetch data or manufacture time, IDs, geography, confidence, trust, summaries, or causality.

Two canonical, closed local inputs are separate from captured facts:

- `operational-observatory-actors/1` maps every exact `(producer kind, id, instanceId)` to one local actor and site. Entries are strictly sorted and unique. `visibility: restricted` emits a restricted record instead of event detail.
- `operational-observatory-editorial/1` is strictly sorted by source `eventId`. It permits only the closed cues `clear`, `focus`, `follow`, and `hold`, plus bounded narration. Missing or restricted event references reject the whole projection.

These inputs label presentation only. They cannot alter source event IDs, merge order, HLC-derived time, source fields, parent state, content digest, or content length.

## Output contract

The package starts with one `package` record and then emits replay records in verified order:

- `event`: exact source `eventId`; merge index; run-relative nanoseconds derived only by subtracting the first recorded HLC physical value; channel/kind; producer identity and source sequence; interaction/peer/task/context/subject IDs; parent state; content digest/length; actor/site labels; optional event-ID-keyed editorial data.
- `restricted`: retains event identity, order, recorded time, channel/kind, producer, parent, actor/site, and the explicit `actorManifest` restriction reason; event detail and editorial data are absent.
- `gap`: preserves the verified missing-parent record and adds only the closed `unresolvedAtSeal` rendering reason. A source event's declared `missing` parent preserves exactly one of `externalBoundary`, `captureStartedLate`, or `producerRestart`.

`ProjectionReceipt` binds projector ID/version, the verified replay merged-input digest, a domain-separated digest of every output byte, and output byte length. `verify_operational_projection` validates canonical JSONL, the closed record shapes and enums, order, bounds, duplicate event IDs, parent reasons, references, and receipt binding. `OperationalProjection::record_json` provides immutable event-ID random access; access order cannot affect bytes.

## Bounds

Hard maxima (callers may lower, never raise):

- package, actor manifest, or editorial overlay: 16 MiB each;
- JSONL line: 64 KiB;
- projected events/editorial entries: 100,000;
- actors and sites: 1,024 each;
- display/narration text: 4,096 UTF-8 bytes.

All identifiers use the existing bounded public-safe identifier grammar. Counters and nanoseconds are canonical unsigned decimal strings. Unknown fields, schemas, kinds, cues, visibility values, shapes, duplicate keys, duplicate identities, noncanonical ordering/encoding, malformed values, and over-limit input fail closed.

## Local executable and fixture

```bash
cargo run --bin operational-observatory-project -- \
  REPLAY_JSONL REPLAY_RECEIPT PINNED_RUN_SEAL ACTORS_JSON EDITORIAL_JSON \
  SOURCE_FACTS_JSON OUTPUT_JSONL OUTPUT_RECEIPT
```

The executable reads only the named local files and creates new output files. The checked fixture is in `demo/fixtures/operational-observatory-v1/` and is reproduced from `demo/fixtures/full-matrix-replay-v1/expected.bundle.jsonl` and its verified receipt. That source contains two captured-schema A2A events named `alpha` and `beta`; it is an operational projection contract vector, **not** evidence that the full six-organization LIFELINE run was composed. `demo/lifeline.trace.jsonl` remains a separate synthetic cinematic fixture.

## Wave 2 browser boundary

Start the loopback-only allowlisted server and open the explicit operational route:

```bash
cd demo
npm run serve
# http://127.0.0.1:43130/operational.html
```

The operational page fetches exactly `package.jsonl`, `receipt.json`, `actors.json`, `editorial.json`, and `browser-bootstrap.json` from the checked same-origin fixture and imports the pinned same-origin `vendor/three.module.min.js`. It never requests `lifeline.trace.jsonl`, the bundled synthetic audio, `src/lifeline.rs`, or remote code/data. The legacy `/` route remains clearly labeled as a fictional simulation.

Before controls are enabled, `operational-observatory.mjs` verifies canonical closed JSON/JSONL, terminal LF and hard bounds, receipt byte length/domain-separated SHA-256/projector identity/input commitment, the pinned input digest, run seal, duration, package output, run ID, event count and site set, manifest and overlay commitments, actor/site/producer conflicts, editorial references, contiguous merge order, unique IDs, bidirectional parent/gap semantics, source-fact references/content digests/closed enums/restrictions, and final duration. Failure keeps every control disabled, clears all event visuals, and exposes one bounded error. The browser does **not** claim to cryptographically replay the upstream Rust run-seal verification; its authority label says that the projection receipt and expected input commitment were verified while the upstream seal is displayed but not re-verified.

All live playback, normalized manual scrubbing, debug inspection, direct frame rendering, and export call the same immutable projector. `OPERATIONAL_RENDER_FRAME(frame, fps)` returns contributing source event IDs plus the domain-separated renderer-independent state digest. `export-film.mjs --mode=operational` writes those values for every frame to an `observatory-export-evidence/1` JSON sidecar. The legacy synthetic exporter now emits the same evidence shape but remains labeled `legacy-synthetic`.

Every operational event row and rendered event object carries immutable `sourceEventIds` plus an exact `eventId` in Three.js `userData`; keyboard or raycast pointer inspection displays that package record. Source failures are red octahedra, cancellation/fence controls are blue octahedra, transitions are purple tetrahedra, completions are green icosahedra, unavailable source identifiers are orange squares with explicit non-color text, and gaps are yellow triangles. The operational renderer uses a non-geographic event grid because the manifest supplies no coordinates. Missing local display labels are stable anonymous labels derived from recorded actor/site IDs, never invented places. Replaced geometries and materials are disposed on every projection.

Narration is selected only from event-ID-linked editorial entries and explicit half-open intervals ending at the next cue or the committed final duration. Seeking and restart recompute the cue from pure state. Under `prefers-reduced-motion: reduce`, automatic playback is disabled and no timeline, packet, pulse, easing, or camera interpolation runs; manual scrub, event rows, source inspection, and narration remain available.

The operational document uses external scripts/styles under a CSP without `unsafe-inline`; every loopback server response, including 400/404/405/416/500, receives no-store, CSP, nosniff, frame denial, referrer, resource/opener, and permissions headers. Canvas fallback/name, log/live semantics, button/range state, keyboard focus, textual/shape distinctions, and contrast are browser-tested. Both routes use vendored Three.js r169 (`three@0.169.0`); its reviewed SHA-256 `f7cee3c7533449a1505cc12cb5128b89e3d4fd3d7ea62b05f9f5464a217472ee` is pinned by a checked test.

## Wave 3 operational capture

The production default is `demo/fixtures/operational-lifeline-v1/`. Reproduce it with one bounded command:

```bash
scripts/generate-operational-lifeline.sh /tmp/operational-lifeline-v1
```

The harness starts the existing loopback LIFELINE failure scenario, resolves and uses all six Agent Card endpoints through the official A2A director/client, executes the organization-local SMESH teams, and captures the observed failure trace, team journals, and runtime traces through versioned canonical adapters. It freezes a canonical **pre-decision** capture prefix and candidate manifest, then records a deterministic named test-human fixture decision over exactly that packet. This fixture is not live-human evidence, is not authenticated, and does not claim mTLS. The returned review and decision receipt identities are captured before deterministic causal merge and final sealing; the final replay seal authenticates inclusion of the decision receipt. The decision authorizes only the frozen pre-decision packet/candidate and cannot authorize a replay containing itself. Every public line then passes through the privacy authority with read-back verification. The sources have sequence but no authoritative wall clock, so the manifest explicitly identifies the displayed nanoseconds as an adapter-ordinal presentation schedule. Scheduler-dependent runtime tick ordinals/counts are normalized to kind-only evidence. The closed source-facts manifest binds each operational failure classification/outcome and five unavailable `subjectId` restrictions to its exact projected event and source content digest. Ephemeral signal hashes remain absent (`null`) and are never replaced by manufactured identities. Temporary raw scenario state is deleted by a trap and the mutable ratification ledger is not retained.

The deployment has six independently addressed gateway cards but five provider names: Atlas Cold Chain owns both `atlas-primary` and `atlas-fallback`. The evidence keeps that authoritative topology rather than inventing or relabeling a sixth provider.

`/operational.html` accepts only the exact checked 46-event, six-gateway production commitment. Input digest, run seal, final duration, package digest/length/count/run ID/site set, and source-facts digest are pinned in non-fetched code; coherent receipt/bootstrap substitutions fail closed. Browser requests remain limited to the five public package assets and the pinned same-origin Three.js module. Restricted capture, replay, source facts, privacy, and scripted test-human ratification evidence is checked under the fixture's `restricted/` directory and is not server-addressable. Editorial narration/focus is keyed only by captured event IDs and cannot overwrite operational facts, ordering, or timestamps.

Checked production visual evidence is `demo/evidence/operational-lifeline-chrome152-linux.{json,png}`. It captures deterministic end-state frame 1380 at 30 fps (46 seconds), where all 46 source events contribute. Its PNG SHA-256 is environment-bound to Chrome 152.0.7977.64 headless Linux and the project's pinned SwiftShader arguments; the checked renderer-independent state digest is the portable authority.

Issue #29 scorecard/CI acceptance receipts and issue #30 film/publication/postmortem remain out of scope.
