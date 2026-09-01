# Observability runbook

## Truth boundary

Durable authority rows and `runtime-trace/3` are required evidence. OTLP is an optional,
bounded, lossy projection; missing telemetry is not evidence of zero errors. Confirm any
alarm or apparent recovery against protocol probes and authoritative durable state.

The objectives in `observability/objectives.json` are bootstrap defaults, not universal
production claims. Each deployment must review them after no more than 30 days of baseline data.

## Triage

1. Check an external authenticated canary. Classify the incident as data-plane, authority, or
   telemetry-only.
2. Check the emitted edge-availability ratio and audit projection failure/lag series. Inspect durable
   outbox/receiver age, worker health, PostgreSQL pool, and lease renewal from authoritative operator
   probes; those metrics are not yet emitted and unsupported dashboard panels were deliberately removed.
3. Edge availability excludes malformed requests and authentication failures from the eligible denominator. Expected domain denial, not-found, and conflict responses plus 429 quota exhaustion are eligible-good service outcomes. A 5xx, including 503 quota/authority unavailable, is eligible-bad.
4. For PostgreSQL failure, preserve existing work, reduce or stop admission, restore connectivity,
   and let fenced reclaim run. Never edit leases or ledgers manually.
5. For a durable-driver fatal state, stop admission, capture redacted diagnostics, gracefully
   restart one replica, and prove exact replay before restoring capacity.
6. For artifact corruption, stop resolver/promotion for the affected authority, preserve encrypted
   bytes and audit evidence, and restore only from a matching sealed backup. Never regenerate data.
7. For OTLP collector failure, keep serving. Verify bounded drop counters, repair the collector,
   verify the canary resumes, and record the known telemetry gap. Do not infer durable data loss.

## Redaction and correlation

The server generates a random 128-bit request ID. Inbound `x-request-id`, `traceparent`,
`tracestate`, and `baggage` are not authority. Correlation identifiers may occur only in bounded
spans/logs, never metric labels. Do not export request bodies, bearer tokens, headers, URLs,
DSNs, SQL, artifact bytes, key paths, backend locators, panic payloads, or raw error chains.
Public URL logs contain only canonical scheme/host/port.

Dispatch correlation state is scoped by `(tenant_scope, dispatch_id, lease_generation)`. Its capacity
is bounded by the configured OTLP log queue. The state exists only for one
claimed attempt: retry, terminal, dead-letter, cancellation, shutdown, and error exits drop an RAII
guard. Retirement first flips a lock-free atomic visibility bit and only then attempts best-effort
physical removal, so optional telemetry cannot block durable progress or shutdown. A stale attempt
cannot read or remove a newer lease generation. Capacity rejection drops optional
telemetry only; it never blocks durable work. Missing correlation after retirement is rejected rather
than reusing another tenant's identity.

## Audit projection

The projector claims a bounded, leased durable outbox populated in the same transaction as committed
authoritative rows by migration-installed triggers. There is no global cursor, so an out-of-order
commit cannot be skipped. Queue acceptance precedes the fenced delivered commit; queue rejection or
sink unavailability leaves the row retryable, and stable digest-only `event.id` values make downstream
redelivery idempotent. Projection is starts-at-enable. Revision 6 protects each enabled connection
with a migrator-owned random proof and a backend-local temporary nonce; disabled pools never receive
the proof. The runtime role cannot read the proof or registration tables, and setting a custom GUC
cannot grant capability. Projector logs use `smesh.outcome=ok` and `smesh.reason=committed` strictly for
successful projection processing; they do not restate the underlying authorization, quota, or task
effect. The closed `smesh.operation` value identifies the committed authoritative fact class. A
connection's temporary nonce disappears on close, so stale PID rows cannot authorize a later backend;
registration replaces reused PIDs.

The proof is durable authority metadata and is present in physical backups. Protect backups like
migrator credentials, never copy the proof into runtime configuration or logs, and restore the secret
and registration schema atomically. Logical runtime-operator exports must exclude both protected
tables. To rotate after suspected disclosure, stop every gateway, replace the proof as migrator, clear
`audit_projection_sessions`, and restart enabled replicas so every connection re-registers.

No historical rows are scanned. Configure `SMESH_A2A_AUDIT_PROJECTOR_POLL_MS` (10..=5000, default 100)
and `SMESH_A2A_AUDIT_PROJECTOR_BATCH` (1..=1000, default 100). The worker stops and joins before the
authority and OTLP owner. This remains an OTLP-only projection, not an audit read HTTP endpoint.

Artifact restore is an offline target operation. Stop all target gateways/projectors first and run the
`artifact-restore` command alone. On a target with no causative authoritative rows, restore fences the
outbox, refuses active leases, atomically removes orphan projection rows, and keeps projection disabled
through import; any causative task/audit/quota/artifact/operator state still fails the empty-authority
check. The CLI restore remains disabled after enable. Restarting the normally OTLP-configured gateway
then begins projection at that enable point without scanning restored history.

## Resolve

Resolve only after probes pass, backlog age returns to baseline, workers are healthy, the projection
lag falls, and the emitted edge error ratio is declining. Preserve collector outage intervals as
evidence gaps.

## Issue #18 closure

Issues #72 and #73 bound authorization-denial auditing, process-global runtime trace history, and OTLP
dispatch correlations. Issues #74 and #75 add strict protocol fuzzing plus measured load/chaos recovery.
The aggregate STRIDE/data-flow model and accepted residual risks are maintained in
`docs/GATEWAY_THREAT_MODEL.md`. OTLP remains lossy and is never durable authority.
