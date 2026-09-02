# LIFELINE local topology

Issue #20 provides a deterministic, local-only discovery topology for the fictional LIFELINE exercise. It does not run the operational response, organization-local SMESH dream teams, or human ratification workflow. Those remain later M3 tracks.

## Boundary

Northstar is the Director client. The manifest defines the six independently addressed remote gateways it discovers: five primary organization gateways plus the independently deployed Atlas fallback. There are exactly six loopback listeners.

| Gateway | Fictional organization | Public agent | Listener |
|---|---|---|---|
| `meridian` | Meridian Bio | Pharmacovigilance Agent | `127.0.0.1:43141` |
| `atlas-primary` | Atlas Cold Chain | Logistics Agent | `127.0.0.1:43142` |
| `helix` | Helix Medicines Authority | Recall Criteria Agent | `127.0.0.1:43143` |
| `harbor` | Harbor Health | Member Safety Agent | `127.0.0.1:43144` |
| `sentinel` | Sentinel Labs | Independent Evidence Agent | `127.0.0.1:43145` |
| `atlas-fallback` | Atlas Cold Chain | Fallback Logistics Agent | `127.0.0.1:43146` |

Every listener is plain HTTP on a literal loopback address with `local-none` authentication. The corresponding cards advertise no security scheme. This is truthful for the local fixture and is not a production deployment profile. Public profile fields must match the reviewed built-in catalog exactly; only loopback port selection may vary for isolated tests. Non-loopback binds, unknown manifest fields, duplicate gateway or listener identities, malformed geography, missing routes, internal-role disclosures, and prohibited clinical-authority claims fail validation.

Agent Cards expose only the public organization capability. They omit internal SMESH roles and include this discovery boundary:

```text
Fictional simulation capability metadata only; not authorization, medical advice, clinical validation, or evidence of trust.
```

A card is discovery metadata. It does not authenticate a principal, authorize an operation, establish tenant identity, validate evidence, or permit clinical, regulatory, logistics, outreach, or public action.

## Manifest

The checked manifest is `deploy/lifeline-topology.json`. It records:

- a closed schema version and explicit fictional marker;
- organization, public agent, bounded public skill, input/output modes, and geography;
- explicit local authentication mode;
- deterministic listener IDs and addresses;
- the Atlas primary/fallback route.

The two Atlas gateways advertise the same provider and bounded logistics skill but distinct agent identities and interface URLs. Route priority comes from the manifest, not from A2A Agent Card interface ordering.

## Launch

Validate without binding ports:

```bash
cargo run --bin lifeline-topology -- --check deploy/lifeline-topology.json
```

Launch the complete topology with one command:

```bash
cargo run --bin lifeline-topology -- deploy/lifeline-topology.json
```

The process binds all six sockets before it publishes readiness lines. If any bind fails, no server task is started. Press Ctrl-C to request bounded graceful shutdown of every listener.

Inspect a card:

```bash
curl http://127.0.0.1:43141/.well-known/agent-card.json
curl http://127.0.0.1:43146/.well-known/agent-card.json
```

## Verification

```bash
cargo test --test lifeline_topology
```

The integration suite:

- parses the checked deterministic manifest;
- round-trips all six cards through the A2A v1 Rust types;
- verifies public/internal and authority boundaries;
- binds six ephemeral real sockets, including the Atlas fallback;
- resolves every listener with the official `AgentCardResolver`;
- proves the primary and fallback Atlas cards retain the same provider and bounded skill;
- launches the real topology binary and observes all six readiness records;
- explicitly shuts down and joins the in-process discovery topology.

This establishes the M3 discovery and deployment-topology prerequisite only. It does not claim the later Response Director, real SMESH teams, full capture matrix, failure redelegation workflow, or operational acceptance run.
