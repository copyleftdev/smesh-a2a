# ADR-0003: Standalone PostgreSQL text-concordance execution profile

- Status: Accepted
- Date: 2026-09-12
- Issue: #93
- Profile: `standalone-postgres-text-concordance/v1`

## Context

The repository currently has two mutually exclusive executable modes. Loopback mode can use durable
SQLite or PostgreSQL authority, but executes through the loopback endpoint. Runtime mode owns one
in-process SMESH runtime and worker, but is non-durable and its admission processor does not perform a
useful semantic workload or issue policy evidence. Durable configuration with runtime mode is rejected.

The repository already contains narrower building blocks: PostgreSQL leases, fences, outbox and receiver
records, replay outcomes, tenant-scoped authorization and quotas; a bounded in-process
`RuntimeTaskProcessor`; completion-policy evaluation; local runtime cancellation; and canonical runtime
trace capture. These capabilities have not yet been composed into a durable, authenticated, separately
processed standalone service. Existing loopback fixtures, LIFELINE simulations, SQLite restart tests,
and PostgreSQL multi-replica authority tests do not demonstrate that target composition.

This ADR fixes one closed execution profile so issues #94 through #98 and #105 can implement and qualify the same
contract. It is a target design, not a statement that the profile exists today and not a production-readiness
claim.

## Decision

The supported standalone reference profile is exactly
`standalone-postgres-text-concordance/v1`. A deployment selects this identifier as a closed profile, not
as a set of independently interchangeable features. Unknown profile, workload, artifact, policy, or
issuer versions fail before serving.

### Workload and deterministic artifact

The only workload in this profile is `text-concordance/v1`. Its A2A request contains exactly one current
`Message` with exactly one text part and no file, data, or additional parts. Conversation history, context
text, metadata, and prior messages are not workload input. The text part's exact UTF-8 bytes are the input;
the empty string is accepted, while malformed UTF-8, missing or multiple parts, and every non-text part are
rejected before admission. No joining, Unicode normalization, newline conversion, trimming, or character
replacement is allowed.

The authority-bearing `request_digest` is `sha256:<64 lowercase hex digits>` over this exact binary
preimage: ASCII `SMESH-A2A\0standalone-request\0v1\0` (each `\0` is one NUL byte), followed in order by an
unsigned 64-bit big-endian length and bytes for profile `standalone-postgres-text-concordance/v1`, an
unsigned 64-bit big-endian length and bytes for workload `text-concordance/v1`, and an unsigned 64-bit
big-endian length and the exact accepted input bytes. A2A metadata, history, and descriptive context are
excluded because they are rejected as workload input; authoritative tenant, task, context, dispatch,
attempt, and fence are bound separately in the candidate generation.

The gateway's configured request and artifact bounds apply. All counters are unsigned 64-bit integers;
input is rejected before admission if its byte length, maximum line or word count, any frequency, or the
worst-case canonical artifact length could overflow or exceed a configured bound. The worst case is
computed from the accepted input byte length before dispatch and includes fixed JSON syntax, decimal
counter widths, JSON escaping, frequency-entry syntax, and the trailing LF.

The artifact has exactly these fields, in this order:

```json
{"schema":"text-concordance/v1","input_sha256":"<64 lowercase hex digits>","utf8_bytes":0,"line_count":0,"ascii_word_count":0,"word_frequencies":{}}
```

Their semantics are binding:

- `schema` is the literal `text-concordance/v1`.
- `input_sha256` is SHA-256 over the exact accepted UTF-8 input bytes, rendered as 64 lowercase
  hexadecimal digits.
- `utf8_bytes` is the unsigned 64-bit length of those bytes.
- `line_count` is zero for empty input. For non-empty input it is the number of `0x0a` bytes plus one
  when the final byte is not `0x0a`. A terminal LF therefore does not create an extra empty line, and
  CR is ordinary input rather than a delimiter.
- An ASCII word is a maximal non-empty byte sequence in `[A-Za-z]+`. Non-ASCII UTF-8 bytes and every
  other byte delimit words. Each word is normalized by mapping ASCII `A` through `Z` to `a` through
  `z`; no other case folding or locale behavior applies.
- `ascii_word_count` is the unsigned 64-bit total number of ASCII-word occurrences.
- `word_frequencies` maps each normalized word to its unsigned 64-bit occurrence count. Its keys are emitted
  in ascending bytewise lexicographic order.

Canonical artifact bytes are UTF-8, one minified JSON object with the fixed top-level field order shown
above, no insignificant whitespace, decimal integers without leading zeroes, JSON string escaping as
required by RFC 8259, and exactly one trailing LF byte. Because frequency keys contain only lowercase
ASCII letters, their JSON spelling needs no escapes. The artifact content digest is
`sha256:<64 lowercase hex digits>` over these complete canonical bytes, including the trailing LF.

The completion policy is `smesh-completion/v1`. Its artifact set contains exactly one manifest:

```json
{"name":"text-concordance.v1.json","mediaType":"application/json","digest":"sha256:<artifact-content-hex>"}
```

The artifact-set digest uses the repository's `smesh-json-v1` canonical framing: serialize the one-element
manifest array above as minified UTF-8 JSON in struct-field order; hash the concatenation of
`SMESH-A2A\0completion-policy\0smesh-json-v1\0` (where each `\0` is one NUL byte), the unsigned 64-bit
big-endian byte length of the ASCII domain `artifact-set`, that domain, the unsigned 64-bit big-endian JSON
length, and the JSON bytes. Render the result as `sha256:<64 lowercase hex digits>`. It must not be
reconstructed from parsed artifact JSON.

Every accepted input has exactly one canonical artifact. Identical input bytes and profile version yield
identical artifact bytes. A change in input bytes always changes `input_sha256`; changes affecting lines
or ASCII words also change the corresponding report fields. The workload performs no URL fetch, model
call, tool use, ambient-file read, clock read, randomness, callback, shell execution, network effect, or
other external effect.

### Process topology and storage

A conforming baseline composition contains:

1. one or more authenticated A2A gateway replicas;
2. one shared PostgreSQL durable authority, with separate migration and runtime database roles;
3. at least one approved processor in a separate OS process from every gateway;
4. separate review, test, and contradiction issuer processes with separate authenticated identities;
5. PostgreSQL-authorized artifact metadata and one owner-private, shared, coherent POSIX blob namespace
   mounted at the same configured root on every gateway replica for canonical artifact bytes.

PostgreSQL is the only runtime storage authority for this profile. Database-time leases and fences,
forced row-level security, tenant-leading keys, distributed quotas, durable outbox/receiver state,
artifact authority, terminal arbitration, and exact replay are mandatory. Mixed authority backends are
forbidden.

Artifact publication is ordered rather than falsely described as one PostgreSQL/filesystem transaction.
Before staging, a PostgreSQL transaction creates an attempt/fence-bound publication reservation containing
the candidate generation, content digest, an opaque reservation ID, the derived staging path and final path,
owner token, and database-time lease. The staging path is under one owner-private staging root, derived only
from the server-generated reservation ID, and created as a new mode-0600 regular file with exclusive-create
and no-follow semantics. No bytes are written before that reservation commits. Garbage collection treats
every unexpired reservation as a reference. The owner renews and revalidates the database-time lease and
fence before every stage, promote, and commit step; an expired or stale owner cannot publish.

The reservation owner stages bytes in the shared namespace, fsyncs the file, publishes it to the immutable
content-addressed path with `renameat2(RENAME_NOREPLACE)` or an equivalent no-replace primitive, and fsyncs
the containing directory. An existing destination is never overwritten: the producer accepts it only after
opening it without following links, proving it is a regular owner-controlled file, and verifying its exact
length and digest. Otherwise publication fails closed.

Before either publication or collection for digest `D`, the actor ensures a durable
`artifact_digest_authority(D)` row exists with `INSERT ... ON CONFLICT DO NOTHING`, then locks that row
`FOR UPDATE`. Authority rows are retained as tombstones even when no blob or reference exists. Every
publisher and collector acquires the digest-authority lock first, before reservation/reference locks; a
new reservation that has computed digest `D` must acquire it before promotion or terminal publication.
This stable lock target serializes the empty-reference case as well as existing rows.

The publisher starts one bounded PostgreSQL terminal transaction, locks the digest authority,
reservation, and candidate generation `FOR UPDATE`, and revalidates owner, lease, attempt, and fence.
While retaining those row locks,
it performs the bounded no-replace promotion, directory fsync, and final byte/digest verification, then
atomically marks the blob referenced while sealing artifact metadata, completion authority, and public task
state. No publisher may promote outside this locked transaction.

Garbage collection acquires the same digest-authority and reservation/reference row locks before changing
state. It first marks
an expired unreferenced reservation `deleting` and commits that fence; any later publisher must observe and
reject that state. It then removes the exact reservation-owned staging file and removes a final
content-addressed blob only after a second locked transaction proves that no live reservation or committed
reference names its digest/path. It retains the digest-authority lock through unlink, so a concurrent
publisher cannot insert authority for or promote the same digest between the empty proof and deletion. If
collection wins, the waiting publisher revalidates after deletion and may safely promote its staged copy;
if publication wins, the collector observes the committed reference and keeps the blob. A collector never
acts from an earlier snapshot. If cleanup crashes after
the deletion fence, bounded recovery resumes that exact deletion; no publisher can resurrect it.

A crash during staging or after blob publication but before terminal commit rolls back the publisher's
transaction and leaves a reservation-owned artifact. After its lease expires, bounded reconciliation either
completes the validated reservation under the same locks or fences and garbage-collects its exact
staging/final path without scanning or deleting unrelated files. A missing or mismatched blob blocks
publication and replay. Every replica resolves committed metadata through the same namespace. #94
implements these reservation/publication invariants and #98 qualifies their crash and garbage-collection
races. Holding row locks across the bounded filesystem steps is deliberate; filesystem deadlines and the
database transaction watchdog must abort rather than leave an unbounded lock holder.

SQLite runtime support is explicitly excluded. SQLite remains only the existing Unix, exclusive-open,
single-writer loopback/local compatibility authority. It does not qualify a runtime worker, replicas,
external-artifact production, or this standalone profile.

Until #105 is complete, every gateway-to-worker and issuer SMESH connection is single-host loopback and
uses a static operator allowlist. This baseline makes no cross-host security or readiness claim.

### Processor and SDK boundary

The embeddable Rust extension seam remains:

```rust
RuntimeTaskProcessor::process(
    RuntimeTask,
    CancellationToken,
    RuntimeEventSink,
) -> Result<(), DispatchError>
```

`RuntimeTaskProcessor` is a trusted in-process extension point within its owning worker process, not a
sandbox or malicious-code containment boundary. One invocation owns every child task and subprocess it
creates and must stop and join them before returning.
`RuntimeEventSink` may emit bounded progress, private candidate artifacts, and an untrusted completion
proposal. It cannot issue policy evidence, choose tenant scope, commit a public artifact, or decide task
completion.

The embeddable SDK by itself promises none of durable dispatch, restart recovery, replica safety, tenant
isolation, authenticated evidence, remote process containment, exactly-once external effects, or
standalone operational readiness. `MeshDispatcher` remains the dispatch/cancel seam, but the current
bare `MeshRequest` lacks authoritative tenant, dispatch, attempt, and fence identity. The standalone
composition therefore uses a server-authored durable work envelope introduced by #94/#96; it never
trusts caller or peer metadata for those values.

### Tenant and completion authority

Authentication establishes a principal. Server authorization maps that immutable principal to account
and tenant scope. Tenant, account, and principal values must never be taken from A2A fields, headers,
request metadata, processor output, Agent Cards, peer metadata, or issuer labels.

PostgreSQL RLS and tenant-leading keys scope tasks, outbox entries, receiver records, evidence, artifacts,
quotas, cancellation, and replay. Two tenants may reuse the same public task, message, or context text
without visibility, correlation, quota, cancellation, evidence, or completion authority crossing the
boundary.

Processor artifacts and completion events are proposals and remain private. Each proposal is frozen as one
immutable candidate generation bound to tenant, task, context, request digest, artifact-set digest,
dispatch ID, attempt, fence, and completion-policy revision before issuer review begins. Candidate bytes,
manifest, and bindings cannot change within that generation. Its `candidate_generation_id` is the
`smesh-json-v1` domain-separated digest, using the framing defined above with domain
`candidate-generation`, of this exact minified ordered JSON object:

```json
{"tenant_scope":"<authoritative tenant>","task_id":"<authoritative task>","context_id":"<authoritative context>","request_digest":"sha256:<hex>","artifact_set_digest":"sha256:<hex>","dispatch_id":"<server dispatch>","attempt":0,"fence":0,"completion_policy":"smesh-completion/v1","completion_policy_revision":1}
```

`attempt`, `fence`, and `completion_policy_revision` are unsigned 64-bit integers. Every string is the exact
server-authored UTF-8 value already validated and durably bound to the attempt; no display-layer
normalization or untrusted alias participates.

Only the gateway's explicit versioned completion policy, followed by one atomic PostgreSQL terminal commit,
may publish canonical artifact bytes and a public completed task. That transaction locks and revalidates
the frozen generation and its complete evidence set, requires exactly one valid record for every required
issuer role, rejects any conflicting record, seals the generation against later evidence, and commits
terminal authority. Late or duplicate candidate/evidence writes for a sealed or stale generation are
rejected. Completion-first rejects later cancellation; accepted cancellation suppresses every late
completion. No worker or issuer can grant itself tenant, quota, completion, or publication authority.

### Independent authenticated evidence issuers

The completion policy requires all three independently authenticated roles:

1. `text-concordance-review/v1` independently recomputes the artifact from the durably bound input and
   compares every canonical byte and field.
2. `text-concordance-test/v1` validates schema and bounds, canonical serialization and ordering, digest,
   and fixed golden vectors.
3. `text-concordance-contradiction/v1` checks for conflicting candidate or evidence digests and emits
   clearance only when none exists. Any conflict is blocking.

Each issuer runs separately from the processor and from the other issuers. For the loopback baseline, each
issuer owns a distinct operator-provisioned Ed25519 key kept in an owner-private file; PostgreSQL enrollment
maps its 32-byte public key to the exact issuer role and allowed tenant scope. The versioned
`issuer-ed25519/v1` record renders public keys and 64-byte signatures as unpadded base64url. It signs the
ASCII bytes of the `sha256:<64 lowercase hex digits>` canonical evidence-record digest, with the signature
field excluded from that digest. Every evidence record is signed over all durable bindings, and the gateway
verifies the signature, enrollment, role, scope, expiry, and revocation before storage. Transport connection
metadata and issuer strings are descriptive only and grant no authority.
The signed `issuer-evidence/v1` preimage is a closed minified JSON object in this exact field order:

```json
{"schema":"issuer-evidence/v1","candidate_generation_id":"sha256:<hex>","tenant_scope":"<authoritative tenant>","task_id":"<authoritative task>","context_id":"<authoritative context>","request_digest":"sha256:<hex>","artifact_set_digest":"sha256:<hex>","dispatch_id":"<server dispatch>","attempt":0,"fence":0,"completion_policy":"smesh-completion/v1","completion_policy_revision":1,"issuer_role":"<closed role>","issuer_identity":"<enrolled key id>","decision":"<closed decision>"}
```

The only role/decision pairs are review/`approve`, test/`approve`, and contradiction/`clear`, using the
versioned role names above. Unknown or extra fields and any other pair are rejected. The evidence-record
digest uses the same framing with domain `evidence-record`; the Ed25519 signature is stored outside this
preimage. The gateway recomputes and compares every duplicated authority field and the generation ID rather
than trusting issuer-provided correlation.

Missing, forged, stale, duplicate, conflicting, cross-task, cross-attempt, or cross-tenant evidence fails
closed and cannot publish a candidate. Implementing issuer authentication and the additional durable
bindings and this baseline evidence-signing mechanism belongs to #95. #97/#105 own remote SMESH peer
identity and transport trust, not the local issuer's evidence authority. The current evidence structures
and policy checks are only partial capability.

### Peer trust

For the baseline, peers are loopback-only, statically configured, and explicitly enrolled by operator
configuration. Agent Cards, node names, bootstrap addresses, metadata, issuer strings, and SMESH
reinforcement or confidence establish neither identity nor authorization. Unknown peers and tenant
mismatches fail before work admission. Unsafe public bypasses remain disabled.

The peer trust contract is owned by #97. Encrypted non-loopback transport, cryptographic peer identity,
enrollment and revocation, hostile-peer limits, network-environment isolation, and cross-host qualification
are implemented and qualified by #105. The loopback
baseline must not be presented as satisfying those requirements.

### Cancellation and unknown outcome

Cancellation is correlated by authoritative tenant scope plus server-owned dispatch ID, attempt, and
fence, never by an untrusted task ID alone. One atomic durable terminal arbitration has one winner:
committed completion rejects later cancellation, while accepted cancellation fences and suppresses late
completion.

A successful cancellation response requires the remote worker to confirm processor exit and that all
owned child work has been stopped and joined. Timeout, partition, peer death, lost acknowledgement, or
forced abort is an **unknown remote outcome**, not confirmed stop. PostgreSQL retains the cancellation as pending or reconciling, blocks publication from the fenced attempt,
and performs bounded reconciliation attempts with bounded backoff. Exhausting one attempt budget preserves
an operator-visible unknown outcome and schedules only policy-bounded retries; retention and manual
resolution follow the durable audit policy rather than silently converting or discarding uncertainty.
The profile's workload has no external effects, but that fact does not turn an unconfirmed stop into a
confirmed one or establish general process containment.

### Recovery

PostgreSQL is authoritative across gateway, worker, issuer, and network loss:

- admission, quota reservation, and stable tenant-scoped dispatch identity commit before dispatch;
- claims use database-time leases plus owner, token, attempt, and epoch/fence checks with bounded renewal;
- receiver deduplication stores one authoritative outcome for a delivery identity;
- duplicate delivery replays the stored outcome, and stale claims, evidence, results, and cancellations
  cannot commit;
- gateway death after receiver result commit reconciles that result without processor re-execution;
- worker death before completion permits bounded retry after lease expiry; this workload is retry-safe
  because it is deterministic and has no external effects, while receiver deduplication remains required;
- cancellation survives restart and recovery either confirms stopped/canceled or preserves the explicit
  unknown outcome;
- after the durable POSIX stage/promote/fsync sequence, public task/result/artifact metadata and terminal
  authority commit atomically in PostgreSQL, and replay returns the verified committed canonical bytes;
- missing required dependencies and corrupt or inconsistent authority state fail loudly rather than
  skip checks or synthesize plausible state.

Existing PostgreSQL authority and local runtime tests prove individual mechanics only. They do not prove
this end-to-end recovery composition until #98 qualifies it.

## Explicit exclusions

- SQLite-backed runtime, external-artifact production under SQLite, or multi-replica operation under SQLite.
- Workloads other than `text-concordance/v1`, including arbitrary prompts or autonomous planning.
- Models, tools, shell execution, URL or network fetches, callbacks, ambient files, and external effects.
- Cross-host SMESH readiness before #105.
- Trust derived from Agent Cards, issuer strings, peer metadata, or SMESH confidence.
- Exactly-once arbitrary external effects.
- Medical, legal, operational, expertise, or real-world truth claims.
- Existing LIFELINE fixtures, generated receipts, recorded traces, or loopback output as qualification
  evidence for real remote execution.
- Embedded-SDK claims of durability, high availability, tenant safety, authenticated evidence, process
  containment, or remote-cancellation confirmation.
- General production readiness beyond this exact versioned workload and topology; this ADR itself makes
  no production-readiness claim for even that composition.

## Acceptance and implementation ownership

All issues use deterministic RED/GREEN tests, bounded owned resources, exact-tree independent review,
and verified CI. Tests retain exact canonical artifacts/evidence and explicit topology and network
limitations. Required dependencies fail rather than skip.

### #94 — durable runtime adapter

Owner: durable gateway/authority integration.

- Replace the production loopback receiver with real runtime dispatch.
- Commit stable tenant-scoped dispatch identity, authorization, quota reservation, outbox state,
  receiver deduplication, fences, stored replay, and atomic terminal arbitration.
- Prove crash windows before and after worker admission, receiver result commit, and gateway terminal
  commit; reject stale claims and late results.

### #95 — semantic processor and evidence path

Owner: workload, canonical artifact, completion policy, and issuer authentication.

- Implement the bounded `text-concordance/v1` processor and the exact artifact semantics in this ADR.
- Run separately authorized review, test, and contradiction issuers; bind complete tenant, request,
  artifact-set, dispatch, attempt/fence, policy, role, and authenticated-identity provenance.
- Prove golden vectors and changed-input behavior; reject missing, forged, stale, duplicate, conflicting,
  cross-task, cross-attempt, and cross-tenant evidence without publishing private candidates.

### #96 — separate-process SMESH work protocol

Owner: remote claim, work, result/evidence, cancellation, and lifecycle protocol.

- Execute the processor in a separate worker process through a server-authored durable work envelope.
- Correlate and fence claims, results, evidence, and cancellation; deduplicate delivery and survive
  reconnect.
- Test duplicate delivery, conflicting claims, lost responses, partitions, peer death, confirmed stop,
  unknown outcome, and bounded shutdown/kill/reap behavior.

### #97 — peer identity and trust design

Owner: the peer identity, authentication, authorization, enrollment, revocation, and hostile-peer contract.

- Publish the threat model, authorization rules, protocol bindings, bootstrap/rotation/revocation procedures,
  hostile-peer limits, and deterministic conformance vectors that constrain #96 and #105.
- Keep loopback guards in place; this issue does not implement or qualify non-loopback transport.

### #105 — secure non-loopback peer implementation and qualification

Owner: implementation of the #97 trust contract and cross-network qualification.

- Add encrypted mutually authenticated transport, enrolled peer identity, tenant-scoped authorization,
  rotation and revocation, replay/downgrade defenses, and hostile-peer resource limits.
- Relax loopback guards only for the fail-closed approved profile.
- Test two isolated network environments and reject unauthorized, revoked, wrong-role, and wrong-tenant peers.
- Do not broaden the profile's workload or completion authority.

### #98 — complete composition qualification

Owner: clean-environment end-to-end qualification.

- Launch authenticated gateway replicas, PostgreSQL, artifact storage, independent issuer processes, and
  independent SMESH worker processes with one bounded command.
- Through an official A2A client, submit fixed text to replica A, execute in the separate worker, obtain
  the exact policy-approved artifact, and replay identical committed bytes through replica B.
- Cancel a second held task remotely with no later publication; exercise crash during work, lost
  response, durable recovery, quota/authz denial, bounded contention, and peer partition.
- Retain exact-tree evidence and limitations. Secure network deployment evidence depends on #105 and is
  not supplied by the loopback baseline.

## Consequences

- Implementations and qualification target one useful, deterministic, externally effect-free workload
  rather than an open-ended autonomous engine.
- PostgreSQL is the single durable authority for standalone runtime and replicas; SQLite's compatibility
  scope remains explicit.
- Processor output, peer claims, and descriptive issuer labels cannot become completion authority.
- Separate processes and independent issuers create real failure and authentication boundaries that the
  embedded SDK does not claim to provide.
- Cancellation and recovery preserve uncertainty instead of reporting an unproven remote stop.
- Cross-host trust remains out of scope until #105, and full composition evidence remains outstanding
  until #98. No existing capability or this decision alone establishes production readiness.
