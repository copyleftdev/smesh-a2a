---
title: My agent mesh could coordinate. It couldn't introduce itself. So I added A2A.
published: false
description: I added A2A to SMESH, my decentralized Rust agent framework. Here is the boundary, the tested gateway, the fictional demo, and what is still missing.
tags: ai, agents, architecture, distributedsystems
cover_image: https://raw.githubusercontent.com/copyleftdev/smesh-a2a/main/docs/devto-a2a-cover.jpg
---

{% embed https://www.youtube.com/watch?v=EFPKaIuF8iA %}

*The 2:56 video above is a fictional medication-safety exercise. The gateway interoperability is tested; the six-organization incident is a deterministic simulation.*

[Read the corrected narration transcript](https://github.com/copyleftdev/smesh-a2a/blob/main/demo/NARRATION.txt).

Last time, I discovered that the QUIC transport in my agent framework had never actually transported anything.[1]

This time the transport was real. Five processes could find each other, exchange encrypted messages, reinforce independent conclusions, and let unsupported signals decay.

The mesh worked.

It still could not introduce itself to another agent.

There was no standard way to ask what the swarm could do. No retained task to retrieve after an internal signal expired. No interoperable progress stream. No cancellation contract. No artifact another framework would understand.

I had built a society with no border crossing.

{% link https://dev.to/copyleftdev/my-quic-transport-had-never-once-been-executed-heres-what-happened-when-i-ran-it-24ge %}

Google's Agent2Agent protocol gave that missing boundary a name. A2A was announced in April 2025 as an open protocol for agents built by different vendors and frameworks to discover one another, exchange messages, and collaborate without sharing their private memory, tools, or internal plans.[2] The project moved under Linux Foundation governance in June 2025, so "Google's A2A" is historically accurate, but no longer the whole story.[5]

What I needed was not a new brain for SMESH.

I needed a public contract in front of it.

## A working mesh is not an interoperable agent

SMESH is the framework I designed for decentralized coordination between LLM agents. It borrows its mechanics from mycorrhizal networks rather than job queues.[6]

- agents emit signals into a field;
- signals lose intensity over time;
- agents claim work according to local affinity;
- independent agreement reinforces a claim;
- unsupported claims disappear without a central process rejecting them;
- trust changes what a node is willing to relay.

That solves an internal coordination problem. It answers questions such as:

- Which specialist should take this work?
- Has another independent agent seen the same thing?
- Is this claim gaining support or merely being repeated?
- Can a stale task disappear without a scheduler cleaning it up?

A2A solves a different problem.

It asks:

- How does an outside agent discover this system?
- How does it delegate a unit of work?
- How does it watch a long-running task?
- How does it cancel that task?
- What retrievable result comes back?

The official A2A specification describes an interoperability layer for independent, potentially opaque agent systems. Its current v1 model separates canonical data objects, abstract operations, and concrete bindings such as JSON-RPC, gRPC, and HTTP+JSON/REST.[3][4]

The core vocabulary is small:

| A2A concept | job |
|---|---|
| `AgentCard` | advertise identity, skills, interfaces, media modes, and security declarations |
| `Message` | carry one interaction turn as typed parts |
| `Task` | track stateful work through a lifecycle |
| `Artifact` | return result data associated with a task |
| `contextId` | group related messages and tasks |

A2A v1 defines operations such as `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, and `SubscribeToTask`. A binding decides how those operations appear on the wire; the canonical task semantics stay the same.[4]

That distinction matters. If I tried to make A2A the swarm's internal coordination algorithm, I would flatten SMESH into a remote procedure call graph. If I tried to expose raw SMESH signals as the public protocol, every client would need to understand decay, relay probability, local trust, topology, and attestation sets.

Neither would be interoperability. It would be leakage.

## The three layers are not competitors

The cleanest architecture I have found is this:

| layer | relationship | owns |
|---|---|---|
| **A2A** | agent ↔ agent | discovery, tasks, streaming, cancellation, artifacts |
| **SMESH** | agent ↔ local swarm | claiming, diffusion, reinforcement, decay, trust |
| **MCP** | agent ↔ tool or data source | tool invocation and resource access |

The official A2A documentation makes the same separation from MCP: MCP equips an agent with tools and resources; A2A lets independent agents collaborate as agents.[3]

For SMESH, that produced a hard architectural rule:

> **A2A is the external task contract. SMESH is the ephemeral internal coordination field.**

The design requires the A2A ledger to outlive internal signal decay. When `SMESH_A2A_SQLITE_PATH` is set, the production loopback path uses SQLite-backed durable admission, replay, subscriptions, cancellation, and restart recovery; otherwise loopback uses the ephemeral compatibility receiver.

The boundary is split between a path that runs now and a path that is only an integration seam:

```text
External A2A client
        |
        | Agent Card / Send / Stream / Get / List / Cancel
        v
+-------------------- smesh-a2a ---------------------+
| A2A SDK routers + guarded/durable request handler  |
| bounded task ledger + executor/outbox driver       |
| validation + MeshDispatcher                        |
+----------------------------------------------------+
        |
        +-- default binary mode: loopback
        |      `-> ephemeral compatibility or durable SQLite receiver
        |
        `-- explicit runtime mode: ChannelDispatcher
               `-> RuntimeWorker -> real SignalType::Query
                   `-> SmeshRuntime + loopback-bound QUIC mesh
                       `-> admission-only MeshEvent proposals
        |
        v
SQLite-backed A2A task history in durable loopback mode
```

The checked-in executable supports both loopback and explicit runtime modes. Setting `SMESH_A2A_SQLITE_PATH` in loopback mode selects the repository-owned durable receiver/outbox path; runtime mode remains fail-closed with SQLite until durable runtime effect replay exists.

I kept the adapter in a separate repository. `smesh-rust` remains the coordination substrate. `smesh-a2a` can follow A2A's release cycle, server dependencies, and security boundary without pushing HTTP and SDK churn into the core mesh.[6][7]

## The Agent Card is not the swarm

For a known endpoint, A2A capability discovery begins with an Agent Card: a public JSON description of an agent's interfaces, capabilities, skills, and security requirements.[4]

My first temptation was to list every internal role: security reviewer, tester, architect, performance analyst, contradiction sentinel.

That would have been wrong.

Those roles are implementation details. They may change per task. Some may not exist until the mesh senses the work. Publishing them would couple clients to an internal topology that SMESH is specifically designed to keep fluid.

The public card advertises one aggregate capability instead:

```rust
// Abridged from build_agent_card(). These are the public promises.
let supported_interfaces = vec![
    AgentInterface::new(
        format!("{base}/jsonrpc"),
        TRANSPORT_PROTOCOL_JSONRPC,
    ),
    AgentInterface::new(
        format!("{base}/rest"),
        TRANSPORT_PROTOCOL_HTTP_JSON,
    ),
];

let capabilities = AgentCapabilities {
    streaming: Some(true),
    push_notifications: Some(false),
    extensions: None,
    extended_agent_card: None,
};

let public_skill = AgentSkill {
    id: "smesh.collaborative-task".to_owned(),
    name: "Collaborative swarm task".to_owned(),
    description:
        "Coordinates specialist agents through SMESH and returns an accepted artifact."
            .to_owned(),
    tags: vec![
        "multi-agent".to_owned(),
        "coordination".to_owned(),
        "review".to_owned(),
        "testing".to_owned(),
    ],
    examples: Some(vec![
        "Review this Rust repository for correctness, security, and performance."
            .to_owned(),
    ]),
    input_modes: Some(vec!["text/plain".to_owned()]),
    output_modes: Some(vec![
        "text/plain".to_owned(),
        "application/json".to_owned(),
    ]),
    security_requirements: None,
};
```

The card says what an external client may rely on. It does not reveal how the swarm will organize itself, and it is not proof that the publisher should be trusted.

Discovery metadata is not authorization. A skill description is not a capability grant. A client saying `tenant=important-customer` does not make that identity real.

Those sound like obvious distinctions. They are also exactly the distinctions that disappear when a demo and a security model share the same JSON object.

## One A2A message becomes a typed SMESH query

At ingress, the gateway accepts bounded inline text, creates a stable A2A task envelope, and translates it into the actual core signal type used by SMESH:

```rust
pub fn to_signal(&self, gateway_node_id: &str) -> Signal {
    Signal::builder(SignalType::Query)
        .payload_json(self)
        .origin(gateway_node_id)
        .build()
}
```

The payload carries the A2A task ID, context ID, protocol marker, and validated text. `ChannelDispatcher` packages that typed signal with the request and hands both to a runtime-owned worker.

That boundary is implemented and tested. The standalone binary defaults to `LoopbackDispatcher`,
but `SMESH_A2A_MODE=runtime` now creates a genuine `SmeshRuntime`, joins a loopback-bound QUIC
mesh, and injects the Query through `SmeshRuntime::emit`. Its bundled admission processor supplies
no semantic evidence, so arbitrary work fails closed rather than claiming completion. A
multi-process semantic work/evidence harness remains the next integration step.

Setting `origin` on the gateway Query is deliberate. In my previous article, independently corroborated *claims* omitted their origin from the content hash so identical conclusions could converge on one address. This is a different signal. A gateway Query is an ingress envelope, not a claim waiting for independent corroboration. Its source belongs in the record.

The boundary also rejects what it does not understand. The MVP accepts inline text only. It does not fetch a client-provided URL, dereference an arbitrary file, or treat external metadata as instructions for the mesh.

Inline text is boring, but I know exactly what crosses the boundary.

## The task ledger and the signal field tell different kinds of truth

This was the most important design correction.

A SMESH signal is supposed to decay. If nobody reinforces a task, its intensity falls until it no longer matters. That is useful inside the coordination system because stale work cleans itself up.

An A2A task must not disappear because its internal coordination signal faded.

An external client may reconnect five minutes later and call `GetTask`. An auditor may list tasks by context. A user may need to see that a cancellation was accepted. An artifact must still belong to the task that produced it.

So the gateway cannot reconstruct its public state by looking at the mesh.

```text
A2A task ledger = retained external task state (SQLite-backed in durable mode)
SMESH signal     = temporary coordination pressure
```

The ledger is authoritative for the A2A lifecycle. The mesh is authoritative only for its local coordination observations.

That also means terminal states are absorbing. Once a task is completed, failed, canceled, or rejected, a repeated message cannot quietly restart work under the same ID.

## Streaming exposed a bug that all my tests had missed

A2A v1 supports both direct responses and stateful tasks. A task lifecycle stream begins with the Task itself, then emits ordered status or artifact updates, and closes when the task reaches a terminal state.[4]

My executor maps internal mesh events like this:

```text
mesh dispatch accepted  -> Working
mesh progress           -> Working + status message
mesh artifact           -> Artifact update
mesh completion         -> Completed
mesh failure            -> Failed
accepted cancellation   -> Canceled
```

The stream ordering test passed.

Then an independent review pointed out that my own worker budget allowed 256 events while the upstream server's broadcast subscription buffer held 32. A fast worker could stay inside my documented limit and still outrun the initiating subscriber. The task might finish in storage while the client received an internal "subscription fell behind" error.

That is a particularly unpleasant distributed-systems bug because both sides can truthfully report different outcomes.

The fix was not to hope the subscriber ran faster. I reduced the worker event budget to 16, clamp caller-provided limits to that ceiling, and added a burst test through the official client.

This is what protocols do to a design: they force every implicit assumption to become somebody else's observable failure.

## Cancellation has to stop work, not just change a status label

Forwarding `CancelTask` to a dispatcher was not enough.

If an internal worker ignored the request or kept its event stream open, the original client subscription could hang. Worse, late `Working` or `Completed` events could arrive after the public task had become `Canceled`.

The executor now owns a per-task cancellation token. The first accepted cancellation:

1. reaches the dispatcher;
2. wakes the active producer loop;
3. closes the original execution stream;
4. prevents post-cancel work from changing the terminal state.

Channel sends and cancellation acknowledgements have deadlines. Worker inactivity has a deadline. The total task has a deadline.

Cancellation is not a field update. It is a distributed state transition with work on both sides of the boundary.

## The boring limits are the real feature

The first version was interoperable. It was not bounded enough to deserve trust.

A fail-closed review found unbounded task retention, unbounded worker output, cancellation leaks, missing dispatcher deadlines, terminal task reuse, and invalid input that could leave a task stranded in `Submitted`.

The current localhost-first gateway now bounds:

| resource | default boundary |
|---|---:|
| HTTP request body | 128 KiB |
| accepted inline text | 64 KiB |
| retained tasks | 1,024 |
| active executions | 64 |
| worker events | 16 |
| artifacts per task | 16 |
| aggregate output per task | 1 MiB |
| worker inactivity | 30 seconds |
| total task execution | 5 minutes |
| channel/cancel acknowledgement | 5 seconds |

It refuses non-loopback binds unless the gateway terminates TLS directly, advertises an HTTPS URL
covered by its serving certificate, and enables OIDC and/or required mTLS. The old
`SMESH_A2A_UNSAFE_PUBLIC` override is ignored; it cannot bypass transport or authentication policy.
Loopback development may explicitly disable authentication, while internet-facing deployment still
requires tenant authorization and operational hardening beyond transport identity.[7]

I am spelling that out because "supports enterprise authentication" in a protocol specification does not mean every prototype using the protocol is enterprise-secure.

## The LIFELINE demo is a simulation, on purpose

The cover video follows a fictional medication-safety incident. Three hospitals see weak pieces of the same adverse-event pattern. Separate manufacturer, regulator, logistics, payer, and evidence agents contribute artifacts. Inside each public endpoint, a SMESH swarm claims work, reinforces evidence, contests an early hypothesis, and lets unsupported signals decay.

One logistics endpoint fails. Its task is canceled. A fallback is discovered. The incident continues. The agents converge on a recommendation, but a human incident commander owns the irreversible decision.

The visual separates the layers deliberately:

- ivory arcs are A2A traffic between organizations;
- green fields are SMESH activity inside an organization;
- cyan shards are artifacts;
- vermilion marks contradiction or failure;
- one gold ring marks human authority.

Every visible event comes from a 55-event, ordered, hash-chained JSONL fixture generated as one complete file. The browser can play it, scrub it, inspect it, or export deterministic frames. The narrated film and interactive replay are available from the gateway repository.[7][8]

{% card %}
**Honesty boundary:** the gateway's A2A interoperability is exercised against the official Rust client. The LIFELINE six-organization trace is synthetic. It proves the replay contract and the intended architecture; it does **not** prove that six live SMESH runtimes executed the scenario.
{% endcard %}

A captured run across live SMESH runtimes would be operational proof. This demo is not.

## What is implemented, and what is still a plan

| implemented now | still required for an internet-facing system |
|---|---|
| A2A v1 Agent Card advertising OIDC bearer requirements | tenant authorization from the authenticated principal |
| JSON-RPC and HTTP+JSON/REST bindings | tenant-aware authorization |
| official-client tests for discovery, JSON-RPC/REST send, streaming, and cancellation | PostgreSQL production adapter |
| SQLite durable task ledger, transactional outbox, receiver deduplication, and exact replay | multi-node SQL deployment and operations |
| SSE task streaming | distributed quotas |
| direct rustls TLS, optional/required mTLS, OIDC, and atomic SIGHUP material reload | tenant authorization and deployment policy |
| Get, List, and Subscribe routes through the SDK handler | managed certificate issuance and revocation operations |
| real `SignalType::Query` construction | live SMESH runtime adapter behind every organization |
| bounded execution with durable loopback recovery | push callback validation and SSRF controls |
| deterministic synthetic replay | captured multi-runtime causal trace |

There are two easy ways to lie with a demo like this.

The first is to animate what you wish the system did.

The second is to run one loopback worker and describe it as a decentralized enterprise.

I would rather keep the boundary visible.

## What A2A changed in the way I think about SMESH

Before this work, I thought of SMESH as the system.

Now I think of it as an interior.

The mesh can remain weird in useful ways. Signals can diffuse probabilistically. Specialists can appear and disappear. Trust can be local. Claims can decay. None of that has to leak into the contract presented to another agent.

MCP gives individual agents hands. SMESH gives a group local coordination. A2A gives that group a public identity, a task contract, and a cancel button.

The previous transport article ended with a lesson: code that has never been executed is a plan. This work left me with the same rule one layer higher:

> **A system nobody else can discover, hire, observe, or cancel is not interoperable. It is an island with excellent internal networking.**

If you are building multi-agent systems, where would you draw the boundary between cross-organization interoperability and internal swarm coordination—and which decisions would you refuse to delegate?

{% embed https://github.com/copyleftdev/smesh-a2a %}

Interactive replay: [copyleftdev.github.io/smesh-a2a](https://copyleftdev.github.io/smesh-a2a/)

SMESH core: [github.com/copyleftdev/smesh-rust](https://github.com/copyleftdev/smesh-rust)

## Sources

[1] https://dev.to/copyleftdev/my-quic-transport-had-never-once-been-executed-heres-what-happened-when-i-ran-it-24ge — My QUIC transport had never once been executed
[2] https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability — Announcing the Agent2Agent Protocol
[3] https://a2a-protocol.org/latest — What is A2A Protocol?
[4] https://a2a-protocol.org/latest/specification — A2A Protocol v1.0 specification
[5] https://linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents — Linux Foundation launches A2A project
[6] https://github.com/copyleftdev/smesh-rust — SMESH repository
[7] https://github.com/copyleftdev/smesh-a2a — SMESH A2A gateway repository
[8] https://youtu.be/EFPKaIuF8iA — SMESH A2A cinematic demo
