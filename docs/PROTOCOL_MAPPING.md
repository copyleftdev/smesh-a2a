# A2A to SMESH Protocol Mapping

| A2A v1 | SMESH gateway |
|---|---|
| Agent Card | Aggregate swarm capability and gateway interfaces |
| Agent skill | Supported task family; not internal role inventory |
| Message | Validated external request |
| Task ID | Stable gateway ID copied into the mesh task envelope |
| Context ID | Stable conversation/workflow grouping |
| `Submitted` | Durable task created by the A2A handler |
| `Working` | Mesh dispatch accepted or progress observed |
| Runtime Query ingress | Genuine `SmeshRuntime::emit`; progress only, never completion authority |
| Artifact data | Candidate output buffered and embedded only in the accepted terminal Task |
| `Completed` | Completion policy accepted the output |
| `Failed` | Dispatcher or worker produced a terminal error |
| `Canceled` | Cancellation reached the dispatcher |
| Task history | Durable A2A conversation record |
| SMESH signal decay | Internal coordination only; never deletes the A2A task |
| SMESH reinforcement | Internal confidence signal; not directly exposed as truth |
| SMESH attestation | Optional provenance extension after independent verification |

## Completion policy

`MeshEvent::Completed` is an untrusted completion proposal, not authority. The gateway
buffers candidate artifacts and evidence until the worker stream closes, then evaluates
one immutable snapshot under the locally configured `smesh-completion/v1` policy. Only an
`Accepted` policy decision publishes artifacts and produces A2A `Completed`.

The policy uses fixed-point assurance basis points, domain-separated SHA-256 hashes,
sorted closed-schema manifests, explicit review/test/attestation requirements, and an
absolute veto for blocking contradictions. Policy errors, missing evidence, malformed or
duplicate records, subject mismatches, duplicate completion proposals, and stream timeout
all fail without exposing candidate artifacts.

The `smesh-json-v1` hash profile serializes only closed typed structs with fixed field and
enum names, explicit option values, no floating-point values or maps, and sorted set-like
collections. Hash preimages are framed as the fixed SMESH completion-policy prefix, domain
length and domain, then payload length and JSON bytes. Review/test/contradiction payload
digests are recomputed from the submitted bytes. Issuer labels and attestation keys must be
present in the locally selected policy profile, and repeated logical issuers cannot inflate
required counts. At least one configured contradiction monitor must submit a non-blocking
clearance when no blocking contradiction exists; omission therefore blocks completion.

When human ratification is required, sufficient machine evidence produces A2A
`InputRequired`. A completion receipt is accepted only when an allowlisted public key signs
the exact policy hash, evidence-snapshot hash, artifact-set digest, and decision. The
evidence snapshot binds the request hash plus A2A task and context IDs, preventing cross-task,
cross-context receipt reuse.

Checkpoint and accepted-receipt claims are deterministic for a fixed snapshot, while both stored
records carry process-local HMAC seals. The guard verifies those seals, task/context binding, policy
identity, and the recomputed artifact-set digest before exposing Completed state through Get,
List, synchronous, or streaming responses. The current ledger and seal key are both
process-local; durable key management and restart replay remain persistence work rather than an
MVP claim.

Local deadline, inactivity, resource-budget, policy-rejection, and abandoned-response paths issue a
bounded dispatcher cancellation request so a failed A2A execution does not intentionally leave its
SMESH job running.

The default loopback profile uses deterministic synthetic review and test fixtures. Those
records prove policy mechanics only; issuer strings and evidence digests are not proof that
the named reviewer exists or that the evidence is true. Production identity,
authorization, durable replay protection, and trusted evidence acquisition remain separate
security milestones.

## Non-mappings

- A2A authentication does not become SMESH reputation.
- A client-supplied tenant does not become a trusted internal identity.
- Agent Card skills do not grant capabilities.
- A high-intensity SMESH signal does not automatically become an external artifact.
