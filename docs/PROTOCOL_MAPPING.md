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

When a completion profile requires human ratification, sufficient machine evidence freezes an
immutable private candidate and produces A2A `InputRequired`; it does not publish candidate artifacts.
The issue #27 production path derives a human actor from bearer or mTLS authentication, authorizes only
the `humanRatifier` role, and serves the exact packet from the integrated SQLite or PostgreSQL durable
authority. The operator-supplied 32-byte HMAC key seals packet and append-only receipt chains and is
bound to the authority by a persisted generation commitment/check, so the same key verifies across
restart and a wrong key fails reopen.

The durable state machine is `AwaitingReview -> Reviewed -> Approved | Rejected | Amended`. Review
acknowledges the complete ordered evidence hashes, artifact manifest, uncertainty, packet hash, and
revision. The same authenticated account must decide. Approve atomically publishes the sealed private
candidate task/result/transcript and artifacts; reject suppresses artifacts and transitions the task;
amend keeps the candidate private and atomically creates the next idempotent outbox dispatch (plus
PostgreSQL quota reservation when configured). Receipt, authorization audit, task/event transition,
publication/suppression, amendment work, and terminal callback rows commit or roll back together.

Browser/API mutation preconditions are opaque actor-specific strong ETags that bind the complete
current view and authenticated context; clients must compare and return their exact bytes rather than
parse packet hash or revision authority from them. Server-side idempotency scopes an untrusted header
nonce to tenant, actor/principal, task, generation, and semantic command. Stale preconditions and
conflicting nonce reuse fail closed. The public console shell/script are fixed and data-free;
packet/history APIs remain authenticated and tenant-authorized. See
[`HUMAN_RATIFICATION_RUNBOOK.md`](HUMAN_RATIFICATION_RUNBOOK.md).

`RatificationLedger` remains compatibility/test code and is not production authority. The default
loopback worker's synthetic review/test fixtures prove policy mechanics only; issuer labels, evidence
digests, and a human decision are not proof that content is true or that the named reviewer has
real-world authority. Managed enrollment/revocation, trusted evidence acquisition, and online
ratification-key rotation remain outside issue #27. This is M3 readiness evidence pending merge and CI,
not a milestone or release completion claim.

Local deadline, inactivity, resource-budget, policy-rejection, and abandoned-response paths issue a
bounded dispatcher cancellation request so a failed A2A execution does not intentionally leave its
SMESH job running.

## Non-mappings

- A2A authentication does not become SMESH reputation.
- A client-supplied tenant does not become a trusted internal identity.
- Agent Card skills do not grant capabilities.
- A high-intensity SMESH signal does not automatically become an external artifact.
