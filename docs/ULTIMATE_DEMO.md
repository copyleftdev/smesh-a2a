# Ultimate demo: LIFELINE // 47 MINUTES

The title names the fictional operational response time. The browser and film compress those 47 incident minutes into a three-minute replay.

## Current status

The checked-in JSONL and film are synthetic cinematic fixtures. They exercise the replay contract, event vocabulary, deterministic hashing, rendering, failure story, and human gate. They do not report observed Agent Card negotiation, live task streaming, signed evidence, or six running SMESH deployments. The operational demo described below is complete only when capture adapters replace fixture emission with those observed events.

## The use case

A fictional oncology medication lot begins producing the same rare adverse-event pattern in Boston, Rotterdam, and Singapore. No organization has enough evidence to act alone. The hospitals can see patient outcomes, the manufacturer can see production telemetry, the logistics network can see where each lot traveled, the payer can identify exposed members, and the regulator can define the legal threshold for a recall.

Their agents were built by different teams, run in different clouds, and cannot share private memory or internal tools. A2A lets those opaque systems discover one another, delegate work, stream status, and exchange artifacts. Inside each organization, SMESH coordinates specialist agents through signals, local claims, reinforcement, decay, trust, and bounded consensus.

The demo asks one question:

> Can independent organizations turn weak, scattered evidence into a fast, governed recall decision without giving any central orchestrator access to everyone’s internals?

Everything in the scenario is fictional. The demo makes no medical claim and performs no real clinical action.

## Cast

| Organization | Public A2A agent | Internal SMESH team | Owns |
|---|---|---|---|
| Northstar Hospital Network | Clinical Safety Agent | epidemiology, pharmacy, records, privacy, evidence audit | adverse-event cluster and de-identified exposure cohort |
| Meridian Bio | Pharmacovigilance Agent | manufacturing, lot genealogy, quality, toxicology, legal | production anomaly and affected-lot boundaries |
| Atlas Cold Chain | Logistics Agent | routing, inventory, telemetry, customs, contingency | shipment graph and quarantine/reroute plan |
| Helix Medicines Authority | Recall Authority Agent | regulation, threshold analysis, jurisdiction, public notice | recall criteria and approval workflow |
| Harbor Health | Member Safety Agent | eligibility, claims, outreach, privacy | exposure counts and patient-contact artifact |
| Sentinel Labs | Independent Evidence Agent | contradiction, provenance, statistics, red-team | corroboration and contradiction report |
| Incident Commander | Human authority | none | approves the final recall and public action |

## Why this is the ultimate A2A × SMESH demo

A simpler demo can be solved by one orchestrator. This one cannot.

- No party owns the whole truth.
- Data cannot be pooled into one prompt.
- Work is long-running and produces several artifact types.
- The participants use different agent stacks.
- One remote agent becomes unavailable mid-task.
- Evidence conflicts before it converges.
- A human must authorize the irreversible action.
- The entire run can be replayed from a deterministic event ledger.

## Protocol exercise

### A2A surface

1. Discover six remote agents through Agent Cards.
2. Negotiate text and structured JSON artifacts.
3. Create one root incident context and parallel child tasks.
4. Stream task status and artifact updates.
5. Continue a task with newly discovered lot information.
6. Cancel a stalled logistics task and delegate to a fallback endpoint.
7. Retrieve and list durable tasks after internal SMESH signals have decayed.
8. Return a final recall packet as a set of linked artifacts.

### SMESH interior

1. Emit task-available signals inside each organization.
2. Let specialists claim work by local affinity.
3. Show weaker claims backing off rather than being centrally reassigned.
4. Reinforce matching evidence from independent specialists.
5. Let stale or unsupported hypotheses decay.
6. Reduce trust when a claim is contradicted by signed evidence.
7. Promote only bounded, provenance-bearing outputs to A2A artifacts.
8. Escalate the final irreversible decision to a human.

## Dramatic spine

### 1. Three weak signals

Three hospitals report an unusual reaction. Each event alone looks like noise.

### 2. The network discovers itself

Northstar’s agent discovers Meridian Bio, Atlas, Harbor, Helix, and Sentinel through A2A Agent Cards. No shared framework is assumed.

### 3. Dive beneath the endpoint

The camera enters Northstar’s A2A node. A single external task becomes a field of internal SMESH signals. Specialists claim, reinforce, and challenge pieces of the investigation.

### 4. Evidence crosses borders, not private memory

Each organization returns a narrow artifact: a lot boundary, an exposure count, a shipment graph, a legal threshold, or a contradiction report. Internal prompts and tools remain hidden.

### 5. The contradiction

Manufacturing telemetry initially points to lot ZX-472. Logistics records show two supposedly unaffected pallets traveled through the same thermal excursion. The scope widens. Confidence drops before it rises.

### 6. Failure without collapse

Atlas’s primary endpoint stops streaming. The A2A task is canceled. A fallback logistics agent is discovered and receives the same bounded task context. The wider incident continues.

### 7. Consensus is not authority

The SMESH swarms converge on a recall recommendation, but the system does not publish it. The incident commander receives the evidence packet, sees the remaining uncertainty, and approves the recall.

### 8. The map changes

Affected routes turn from amber to red, then fade. Replacement shipments appear in cool white. Patient outreach tasks turn green. The final frame separates the two layers: A2A between organizations, SMESH within them.

## Final artifact set

- `incident-summary.json`
- `affected-lots.json`
- `deidentified-exposure-cohort.json`
- `shipment-quarantine.geojson`
- `regulatory-threshold.md`
- `contradiction-report.json`
- `human-ratification.json`
- `public-recall-draft.md`

## The matrix capture

Every visible event comes from one append-only JSONL trace. In the checked-in film those events are explicit synthetic fixtures; the visual does not invent additional activity beyond them. In the operational film the same trace must be populated by capture adapters. Events are grouped into six layers:

- `a2a`: discovery, messages, task transitions, streaming, cancellation
- `smesh`: emission, sensing, claiming, reinforcement, decay, backoff
- `tool`: bounded tool and data-source interactions
- `artifact`: artifact creation, revision, and acceptance
- `human`: review and ratification
- `system`: clocks, failures, retries, and integrity checkpoints

The trace carries causal IDs, geo coordinates, organization and agent identities, task and signal IDs, trust/confidence values, artifact references, narration cues, and cryptographic hashes for deterministic replay.

## Checked-in fixture acceptance

- The fixture represents six heterogeneous A2A endpoints and four parallel task submissions under one incident context.
- Every organization has synthetic claim and reinforcement events; Meridian also demonstrates competing claims and backoff.
- At least one hypothesis visibly decays after losing evidentiary support.
- One remote endpoint fails; cancellation and fallback complete without restarting the incident.
- The trace contains no orphan task, signal, artifact, or narration reference.
- Replaying the same seed produces byte-identical normalized JSONL.
- The final decision is impossible without the human-ratification event.
- The visualization can render live, scrub by time, or export deterministic frames for a 1920×1080 film.

## Operational acceptance

- Six real Agent Cards are retrieved and their advertised contracts are recorded.
- Real JSON-RPC, REST, and SSE traffic produces durable A2A task transitions.
- Each gateway emits a real `smesh_core::SignalType::Query` into its organization-local runtime.
- Captured internal activity includes claims, reinforcement, contradiction, decay, and at least one backoff sequence.
- Cancellation records request, dispatcher acknowledgement, internal stop, and durable terminal state.
- Every returned artifact has observed task/context correlation and provenance.
- The human decision records the exact hashes of reviewed artifacts.
- The merged replay has no unexplained capture gap or missing causal parent.
