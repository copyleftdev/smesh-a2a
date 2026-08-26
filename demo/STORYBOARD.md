# LIFELINE cinematic storyboard

Format: 1920×1080, 16:9, 30 fps, approximately 3:00. Primary surface: Monitor. The checked-in film replays the deterministic synthetic fixture. The operational target will use the same surface for captured protocol events; there is no marketing hero or feature-card interlude.

## Visual language

- Background: warm near-black, closer to graphite than outer-space blue.
- Geography: a restrained charcoal globe with faint political boundaries and no satellite texture.
- A2A: precise ivory arcs with small amber packets. These arcs exist only between organizations.
- SMESH: organic mineral-green filaments contained inside each organization node.
- Evidence: pale cyan geometric shards traveling with artifacts.
- Contradiction: vermilion fracture lines, never a generic red glow.
- Human authority: one solid gold ring. It appears once, at ratification.
- Type: condensed grotesk for labels, mono for IDs and protocol state. Avoid default Inter.
- Motion: A2A moves ballistically between endpoints. SMESH moves diffusively and loses energy over time. Their motion grammars must never be confused.

## Data mapping

| Trace field | Visual behavior |
|---|---|
| `layer=a2a` | globe arc and packet |
| `layer=smesh` | local filament pulse inside one organization |
| `kind=*.discovered` | endpoint resolves from outline to solid |
| `state=working` | slow orbital tick around task |
| `state=reinforced` | filament thickens once per reinforcement |
| `state=decayed` | hypothesis line physically shortens and disappears |
| `state=contested` | line splits with a vermilion seam |
| `state=canceled` | packet arrests, arc retracts cleanly |
| `state=ratified` | gold ring closes; no explosion |
| `metrics.confidence` | opacity, not size |
| `metrics.trust` | edge continuity: low trust becomes broken/dashed |
| `visual.importance` | camera priority and label persistence |

## Timeline

### 00:00–00:14 — Three points of noise

Black. A single low pulse. Boston appears, then Rotterdam, then Singapore. Each hospital is one small point with a short clinical event code. No arcs yet.

Camera: slow orbital drift over the Atlantic, then widen to include all three points.

Sound: three dry telemetry clicks, separated by silence.

On-screen copy: `3 EVENTS / 3 SYSTEMS / NO SHARED CONTEXT`

### 00:14–00:34 — Discovery

Northstar’s endpoint emits an A2A discovery request. Five Agent Cards resolve around the globe: manufacturer, regulator, logistics, payer, independent auditor. Each card appears as one line: name, capability, supported modality.

Camera: hold globe-wide. Avoid rapid cuts.

Sound: short mechanical registration tones, one per endpoint.

On-screen copy: `A2A — DISCOVER CAPABILITY WITHOUT EXPOSING INTERNALS`

### 00:34–00:57 — Delegation across organizations

A root incident context forms. Four tasks depart in parallel: lot genealogy, exposure cohort, shipment graph, recall threshold. Packets carry visible task IDs. Status updates return along the same paths.

Camera: track one packet, then widen to show concurrency.

Sound: restrained rhythmic sequence at 92 BPM begins.

### 00:57–01:22 — Inside one endpoint

The camera dives through Meridian Bio’s A2A boundary. The globe falls away. Inside is a local SMESH field: manufacturing, quality, toxicology, and legal agents. A task-available signal diffuses. Two agents claim. The weaker claimant backs off. Evidence from manufacturing and quality reinforces the same lot hypothesis.

Camera: macro dolly through layered filaments; shallow depth, no cyberspace tunnel.

On-screen copy: `SMESH — LOCAL COORDINATION WITHOUT A CENTRAL DISPATCHER`

### 01:22–01:43 — The contradiction

Return to the globe. Meridian’s first artifact points to ZX-472. Atlas returns a shipment graph that connects two adjacent lots to the same thermal excursion. Sentinel marks the original boundary contested. Confidence visibly falls. Unsupported green filaments decay. A revised task travels back through A2A.

Sound: rhythm drops out; one bowed-metal scrape, then silence.

### 01:43–02:02 — Failure without collapse

Atlas’s primary endpoint stops streaming. Its arc freezes. The task state changes to failed, then canceled. A fallback Agent Card resolves in Frankfurt. The task is delegated again. Other tasks continue moving.

Camera: do not shake. The power of the moment is that almost nothing else changes.

On-screen copy: `ONE AGENT FAILS. THE INCIDENT DOES NOT.`

### 02:02–02:31 — Convergence

Artifacts arrive: expanded lot boundary, de-identified exposure count, quarantine GeoJSON, recall threshold, contradiction report. The globe overlays the real shipment graph. Inside each organization, local SMESH activity settles. Between organizations, A2A tasks reach completed.

Camera: alternate globe-wide with two brief interior cuts. End above the North Atlantic.

Sound: rhythm returns with warmer low strings.

### 02:31–02:48 — Consensus is not authority

All evidence converges on one recall packet. The system pauses. The human incident commander reviews the packet. A single gold ring closes around the decision node. `human.ratified` enters the trace.

No confetti, flare, or triumphant swell.

On-screen copy: `HUMAN AUTHORITY / MACHINE-SPEED EVIDENCE`

### 02:48–03:00 — The two layers

Split the frame vertically. Left: clean A2A arcs between six organizations. Right: a cutaway of one organization’s SMESH field. The layers align, then merge into the protocol diagram.

Final copy:

`A2A BETWEEN AGENTS.`

`SMESH WITHIN THE SWARM.`

`INTEROPERABILITY OUTSIDE. RESILIENCE INSIDE.`

End on repository names, not logos or slogans.

## Capture requirements

- Every packet, filament, label, state transition, and narration cue comes from the JSONL trace.
- Render deterministically at 30 fps from simulation time, never wall-clock animation.
- Provide live, scrub, and frame-export modes.
- Expose a debug overlay that shows `sequence`, `eventId`, `taskId`, `signalId`, confidence, trust, and causal parent.
- Respect reduced motion in interactive mode; deterministic film export retains the directed camera timeline.
