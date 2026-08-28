# Issue #13 authorization evidence

## Implemented boundary

- Strict server-owned authorization policy keyed by verified `(issuer, subject)`, with stable account/tenant memberships, a closed role matrix, policy ID/revision/digest, and default deny.
- Authentication middleware → authorization middleware → repository-owned durable handler production stack. Deferred REST SSE state owns its resolved authorization context and scoped datastore predicate.
- SQLite schema v6 stores immutable task tenant/owner, v1/v2 digest versions, append-only authorization decisions, tenant-match triggers, and bounded frozen list snapshots.
- Admission, continuation, cancellation, replay, get, list, subscription, transcript, task-event, and final-result datastore paths use tenant/account predicates. Role denials are durably audited before the protocol denial is returned.
- Page tokens are opaque derived capabilities persisted only by hash and bind the normalized query plus tenant, account, visibility, policy ID, revision, and digest. All malformed, forged, query-reused, cross-account, cross-tenant, expired, and stale-policy tokens report the generic `invalid pageToken` error.
- Authorized admission and cancellation include their allow audit in the protected mutation transaction; injected audit writes prove rollback.

## Repeatable focused evidence

```text
cargo test --test authorization_policy
6 passed; 0 failed

cargo test --test tenant_persistence
14 passed; 0 failed

cargo test --test authorized_durable_protocol
5 passed; 0 failed

cargo test --test authorized_gateway_process
1 passed; 0 failed

cargo test --test durable_protocol_vertical
25 passed; 0 failed
```

### `authorized_durable_protocol`

- `selector_and_role_matrix_fail_closed_with_identical_transport_errors`: one-membership omission, multi-membership ambiguity, duplicate/comma/malformed/foreign selectors, unenrolled principal, viewer mutation denial, durable role-deny audit, and authentication challenge behavior.
- `two_tenant_send_replay_visibility_existence_and_audit_are_exact`: same-account alternate bearer representation, same-message replay/conflict, same public message ID in two tenants, TaskAgent owner isolation, tenant-wide operator/viewer reads, projected history/artifacts, JSON-RPC and REST foreign/missing equivalence, REST subscription preflight before SSE, exact audit count, keyed resource digests, and token canary absence from SQLite.
- The same two-tenant test sends forged foreign and nonexistent cancellation requests through JSON-RPC and REST, requires equivalent errors, proves the durable effect count is unchanged, and verifies the owned task remains completed.
- `visible_list_totals_pagination_and_cursors_are_scope_bound_across_restart`: visible-only totals/projections, stable pagination, cross-tenant and malformed cursor equivalence, policy-revision invalidation, and authorized reopen visibility.
- `deferred_stream_retains_owner_scope_after_authorization_middleware_returns`: a real official REST SSE response is polled to terminal after middleware task-local scope has ended, with deterministic endpoint barriers and watchdogs.

### Closed policy matrix and process boundary

- `authorization_policy::every_role_and_operation_has_an_explicit_fixed_grant_or_deny` enumerates every pair in the six-role × fifteen-operation matrix. It asserts tenant-wide versus owner-only scope, default-denied push operations, ExtendedCard policy, multi-tenant selector requirements, and unenrolled denial.
- `authorized_gateway_process::production_mtls_gateway_migrates_restarts_and_serves_both_protocols` launches the production binary with required mTLS, a real client certificate handshake, the authorization policy, and SQLite. It proves an unbound legacy v1 database and a mismatched owner binding fail without changing version or task count; the enrolled tenant/owner migrates to v6 with the legacy task visible; authenticated JSON-RPC and REST send/get/list work; SIGTERM is reaped under a watchdog; and a fresh process reopens the exact database with tasks visible.
- All process readiness comes from the gateway readiness event and completed connection attempts. Process exits, requests, shutdown, and output readers are bounded; no sleep/yield synchronization is used. TLS keys are copied to an owner-only RAII fixture.

The upstream `a2a-lf` error adapter always injects a fresh diagnostic timestamp into each JSON-RPC/REST `ErrorInfo`. Tests therefore require exact status, code, message, reason, content type, and `WWW-Authenticate` behavior after removing only that non-security request timestamp. Raw bodies cannot be byte-identical across sequential requests until the adapter supports an injected clock or timestamp-free security error details.

### `tenant_persistence` and migration evidence

- Fresh v6 schema, ownership/child-scope triggers, append-only audit, scoped read/list audit, same-message isolation, and restart are directly covered.
- `audit_write_fault_rolls_back_authorized_admission_and_cancellation` injects an SQLite audit trigger failure and proves no task/event/idempotency/outbox/audit admission rows escape, and cancellation leaves state/audit count unchanged.
- `atomic_lifecycle::exact_v1_schema_migrates_to_v6_with_explicit_binding_preserving_keys_and_task` and `malformed_v1_record_rolls_back_migration_without_version_or_schema_change` cover explicit legacy migration preservation and corruption rollback.
- `sqlite_store::tests::active_v4_outbox_migrates_with_preserved_legacy_dispatch_identity` covers an active historical-scope outbox row. A corrupt dispatch fails with the complete v4 schema/version intact; after repairing the fixture, migration preserves the legacy dispatch as identity version 1 and validates complete v6 semantics before commit.
- `atomic_lifecycle::expired_and_forged_outbox_leases_are_rejected_by_durable_fence` proves acknowledgement and retry/dead-letter fencing rejects forged tenant, dispatch, task, attempt, and stale lease fields without mutating the legitimate task or lease.
- `foreign_and_missing_use_one_scoped_indexed_query_with_bounded_latency_evidence` runs `EXPLAIN QUERY PLAN` for both values and proves the same single indexed scoped lookup (no table scan). Alternating 64-sample distributions have a deliberately generous p95 bound and maximum p95 difference. This is supplemental operational evidence only, never a cryptographic constant-time claim.

### Existing durable protocol matrix retained

`durable_protocol_vertical` continues to cover official JSON-RPC/REST unary and streaming admission, immediate/replay/conflict, input/auth continuation, history/artifact projection, subscription initial/tail/terminal closure, active/pending/terminal cancellation races, receiver reconciliation, process checkpoint restart, and fatal pre-stream behavior. Issue #13 tests layer tenant authorization assertions over those already-checked lifecycle semantics rather than duplicating all 25 scenarios.

`outbox_driver::tests::terminal_transcript_reuses_the_exact_committed_progress_frame` deterministically advances completion beyond the persisted Working-frame timestamp and proves terminal assembly reuses the committed prefix rather than reconstructing it from the later clock.

## Final delivery gate

Run bare, without output-masking pipes:

```bash
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
cargo +1.88.0 check --all-targets --all-features
cargo audit
git diff --check
```

The parent integration report must record actual final output. Bearer/mTLS equality is proven by policy resolution and real mTLS process traffic; a single live process request authenticated alternately by bearer and mTLS is not claimed because the checked process fixture deliberately runs required-mTLS mode and no local OIDC issuer is part of the fixture.
