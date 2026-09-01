# Issue 17 callback threat model and evidence

## Assets and adversaries

Protected assets are tenant task confidentiality, network trust boundaries, operator signing/mTLS
keys, exact terminal event bytes, callback availability, and durable task correctness. Assume an
authenticated tenant can submit hostile A2A push fields, control DNS and HTTP responses for its own
domain, race retries/revocation, and observe protocol errors. Assume callback acceptance and local
ack commit can be separated by a process crash.

## Enforced primitive invariants

| Threat | Control | Executable evidence |
|---|---|---|
| Arbitrary egress | exact tenant/endpoint/canonical-URL enrollment | `strict_policy_enrolls_exact_tenant_url_and_rejects_unknown_fields` |
| URL ambiguity | HTTPS DNS-only canonical parser, explicit port, bounded clean path | `canonical_callback_url_accepts_only_exact_https_dns_targets` |
| Private-network SSRF | all-answer deny policy for IPv4/IPv6 special use | `callback_ip_policy_rejects_special_use_and_mapped_addresses` |
| DNS rebinding | fresh all-answer validation; debug-only synthetic-public-to-loopback connector maps only after validation and records the original pin | `synthetic_public_pins_are_recorded_and_fresh_on_each_real_connection`, `dns_change_after_validation_cannot_change_the_pinned_snapshot`, `empty_mixed_and_too_many_dns_snapshots_make_zero_connections` |
| Redirect/proxy credential escape | fresh reqwest client, `no_proxy`, redirects disabled, pinned host resolution | `every_redirect_is_permanent_and_never_followed`, `ambient_proxy_variables_never_receive_callback_traffic` |
| TLS/mTLS impersonation | real CA/SAN/SNI validation and required client identity before HTTP dispatch | `real_https_pin_sni_host_and_signed_wire_succeed`, `tls_name_expiry_trust_and_mtls_fail_before_http_application`, `correct_mtls_identity_reaches_application_and_peer_is_observed` |
| Payload/header mutation | SHA-256 content digest and constant-time length-prefixed HMAC verification over the real wire | `real_https_pin_sni_host_and_signed_wire_succeed`, `synthetic_public_pins_are_recorded_and_fresh_on_each_real_connection` |
| Retry amplification | closed status taxonomy, bounded full jitter/attempt/age | `status_and_retry_after_are_closed_and_bounded`, `readiness_card_and_retry_identity_are_stable_and_bounded` |
| False capability claim | default card remains false; fatal readiness is sticky false | agent card and push security tests |

Errors and Debug implementations redact URL, file path, resolver output, and key bytes.

## Revision 7 artifact-restore closure

The revision 7 migration always creates one `callback_worker_session_secret` row. Artifact restore's
strict empty-target scan originally classified that protected bootstrap row as authoritative occupancy,
so both populated and empty artifact restores failed with `ArtifactRestoreTargetNotEmpty`. A temporary
test-only occupancy diagnostic confirmed callback policy/enrollment/config/event/delivery/attempt/audit
counts were all zero while the callback worker secret count was exactly one; the diagnostic was removed
after isolation.

Restore now treats only the callback worker proof/session rows as resettable bootstrap state. It refuses
a live callback worker backend, keeps every callback policy/enrollment/config/event/delivery/attempt/audit
row authoritative, and rechecks that authority while holding exclusive callback table locks. On an
offline empty-authority target it transactionally deletes stale worker sessions and rotates the protected
worker proof in the same transaction that disables projection and creates the restore journal. Refusals
preserve callback authority, proof, projection outbox, and projection enablement exactly.

Explicit PostgreSQL 17 evidence (all three URLs supplied explicitly, credentials redacted):

- populated and empty restore regressions passed twice consecutively in exact serial order;
- `artifact_migration`: **7 passed, 4 helper subprocess tests ignored**;
- `postgres_store`: **61 passed**;
- `callback_authority`: **11 passed**;
- `postgres_push_process`: **2 passed**, including the enabled two-gateway crash/failover vertical repeated **3/3** serial runs;
- `push_security`: **13 passed**.

## Secure callback transport matrix closure

The deterministic transport matrix now drives the actual `send_enrollment` path through rustls and
hyper fixtures rooted in owner-only temporary directories. It covers trusted roots, wrong roots,
hostname mismatch, expiry, missing/wrong/correct mTLS identity, peer-certificate observation, exact
Host/SNI and signed headers/body, material no-follow/privacy/size failures before DNS, fresh A/B pins,
a post-validation rebinding barrier, all-answer DNS refusal with zero connects, redirect refusal,
ambient proxy canaries, closed status/retry taxonomy, Retry-After delta/date handling, response bounds,
deadline hangs, DNS unavailable, refused connects, resets, and malformed responses. The public/special
IPv4/IPv6 boundary corpus includes mapped IPv4 behavior.

Green evidence on the current tree:

- debug `push_security`: **25 passed**, repeated **10/10** serial loops;
- release `push_security`: **13 passed**, repeated **10/10** serial loops (debug-only connector tests
  are intentionally not compiled into release artifacts);
- `cargo clippy --all-targets --all-features -- -D warnings`: passed;
- `cargo fmt --all -- --check` and `git diff --check`: passed.

## Separate production process gate

SQLite schema v8 and PostgreSQL revision 7 policy persistence, scoped CRUD, inline admission
binding, fenced delivery lifecycle, atomic terminal enqueue, and callback audit projection are covered
by authority/projection tests. Revision 7 extends the closed projection schema with digest-only callback
policy/config/event/delivery facts while leaving revision 6 immutable; matching SQLite triggers and
Rust mappings are exercised through create/enqueue/claim/deliver flows. The joinable worker and secure
transport provide fresh all-answer DNS pinning, enrollment-specific custom roots/paired mTLS loading,
bounded response consumption, renewal, closed retry classification, exact-fence transitions, a
pre-network `PublicEgress` quota seam, an explicit debug-only loopback DNS-map gate that preserves the
original hostname for SNI, and a named post-2xx/pre-commit crash checkpoint.

The dedicated PostgreSQL process vertical now launches two production gateway binaries with distinct
PIDs, sockets, replica IDs and pools against one revision-7 authority. Both advertise push readiness;
an operator-rooted `callback.test` receiver requires the configured client certificate and verifies
the exact `application/a2a+json` terminal bytes, digest, event/idempotency identity, timestamp, attempt,
key generation and HMAC. The parent observes the real post-2xx/pre-commit checkpoint, SIGKILLs and reaps
the accepting replica, and releases the surviving replica only after it retries the same event and body.
The receiver records three requests (503, accepted retry, crash replay) but one deduplicated effect;
PostgreSQL records one delivered row, attempt three, two committed attempt facts, digest-only revision-7
audits and revision-6 projections. Exact replay emits no fourth request. The enabled vertical remains
serial and watchdog-bounded.

## Final retry, atomicity, planning, reconciliation, and release closure

The production process vertical now starts with an HTTP 503 carrying `Retry-After: 1`, observes the
committed PostgreSQL `retry` row before the due instant, and then accepts the byte-identical event at
the same endpoint without a gateway restart. It asserts database-relative due-time clamping, exact
attempt/event/idempotency/body continuity, a terminal-closed config, and the final crash-failover
attempt. The resulting delivery is `delivered` at attempt 3 with two immutable attempt facts.

SQLite and PostgreSQL expose five closed, one-shot terminal enqueue checkpoints: before event insert,
before and after each delivery insert, before terminal config close, and after all callback rows. The
matrix rolls back task state plus callback event/delivery/config changes at every point and retries to
one event and one delivery. SQLite covers Completed, Failed, Canceled, and Rejected; nonterminal
InputRequired/AuthRequired remain outside terminal enqueue. The PostgreSQL function exercises every
checkpoint inside the same transaction as the causative terminal task mutation.

PostgreSQL callback claiming now uses a durable active-tenant turn table and the named partial
`callback_deliveries_claim` index instead of a global window sort. Populated production get/list/claim
plans use `callback_configs_task_state`, `callback_configs_task_list`, and
`callback_deliveries_claim` with no sequential scan or sort. Claim batches are closed to 1..=1000.
Higher policy generations atomically cancel/revoke removed or replaced enrollments; future leases
refuse startup without persisting the new generation, while exact database expiry permits retry.
Same-revision digest mismatch and revision downgrade remain fail-closed.

Verified on the explicit parent PostgreSQL fixture (all three URLs supplied; credentials omitted):

- `callback_authority`: **15 passed** serially, including 2,000-row populated plans, SQLite's 20-case
  terminal fault matrix, PostgreSQL's five-point matrix, and removal/lease-expiry reconciliation.
- `postgres_push_process`: **2 passed** serially, including live 503 -> 2xx retry and two-gateway
  post-acceptance crash recovery.
- debug `cargo test --locked --all-targets --all-features -- --test-threads=1`: **passed**.
- release `cargo test --release --locked --all-targets --all-features -- --test-threads=1`: **passed**.
- all-target/all-feature clippy, rustfmt, rustdoc with warnings denied, Rust 1.88 check, and
  `git diff --check`: **passed**.
- `cargo audit`: **passed with two allowed warnings** (`bincode` unmaintained and transitive yanked
  `chacha20 0.10.1`); no vulnerability advisory failed the command.
- demo JavaScript syntax, **9 tests**, 55-event schema validation, and deterministic trace comparison:
  **passed**; final trace hash `0e393f5689a022bceab436cfc765b6a7fb9b97c90a5eb3fd51adc8b7cf8a7b25`.

A dedicated 20-minute `push-postgres` CI job owns explicit role provisioning and bounded 5-minute
callback-authority plus 10-minute process commands; the general PostgreSQL job no longer duplicates
that process target. #18's broad randomized transport fuzzing and sustained high-volume load are now
closed by issues #74 and #75 without weakening this release gate; accepted residuals are recorded in the
aggregate gateway threat model.

Reviewed SHA-256 values: callback contract
`5dbb08ec3cd15ef70c570b2068801ce629e9cee7801f7091a4a24635d81365b4`; worker
`b31832151bd3bfc9470535b71ecb18784fb190af47331b56e44bb5cff0b39a51`; PostgreSQL authority
`60d491fb98dc19a3ece218a3a995105fbc208ff0d58e98be1ddbc9e8ffadc5ba`; SQLite authority
`63c14ca392cd7d3901130f157cf989ca0cc4907c8714e3d572773fc20bec860f`; policy/transport
`d442f9d2a9d56afb882bce4d7e6500da5b92e466df73e0ef9c4446ad24be6b90`; revision-7 migration
`bf54bb8190e8c7321765a042a18d25751b05bcaac34fc37832fb0fe653b013cc`; authority tests
`44a6d24cf6879ca55915fe0c1507bcdd57cd6eb97b854dd1a332028af3bd56f0`; process tests
`87d39c2c1bf3ce4bd1bd58ec93bf6319a08570fe9782613dee6f835a4ffcccb4`; CI
`c2fa1041cc0d78c28699a3ab9e6ac715338230c169cb739673d19cf82e1320f3`; runbook
`a4ede90065cd9d90435949093d9fef5b6bfeffd6dbc9e828ea5780ffa48ebd6f`.

## Post-review blocker closure (append-only)

The protocol card now advertises only implemented truth: push readiness is live while the extended
card remains false in disabled, ready, and fatal states. Supplied callback IDs replay by semantic
identity independent of a later server clock. IPv6 `3fff::/20` is denied at both boundaries and on
the all-answer zero-connect path. Delivery fences now include `config_id` end-to-end in SQLite and
PostgreSQL renew/finish predicates, retry scheduling rereads database time after network work, and
tenant config caps are persisted and transactionally serialized. PostgreSQL's physical
`callback_tenant_scheduler` is explicitly classified as its multi-replica scheduler; SQLite's
IMMEDIATE callback transactions provide the semantic equivalent.

Callback policy/config/event/attempt/delivered/retry/dead facts now write digest-only audits in the
causative transaction, and committed config/delivery operations emit the closed push telemetry
schema without identity labels. Worker roots catch panics and unexpected exits, publish sticky fatal
readiness, join every task during shutdown, and abort-and-reap every task on timeout/drop.

Current-tree verification:

- serial debug `cargo test --all-targets --no-fail-fast -- --test-threads=1`: passed;
- `callback_authority`: **15 passed**; `push_security`: **26 passed**;
- `postgres_push_process`: **2 passed**;
- all-target/all-feature clippy, rustfmt, rustdoc warnings denied, release all-target check, and
  `git diff --check`: passed;
- `cargo audit`: passed with the same two allowed warnings and no vulnerability failure.

Current reviewed SHA-256 values: callback contract
`b07712f1f1d96eaebc639f3c9890cc9f30082a43d4f570d4a4509d53532c57d0`; worker
`80ba195e4cd1aff306f4ea123c8f418db4d563483c192d2eae5be5148a9aeaa8`; PostgreSQL authority
`64ab68b3059cd72ee4aaa4deffcb680dc375624253268f6d6b21dae892823a99`; SQLite authority
`6d1c706edcf660238d0d8fff34a7c5cf26546971747baf79b5eb29793ee8d527`; policy/transport
`1261b52e529d69c6dff538dd228374694ba90969bd06820d5ff5f86c4beb865f`; revision-7 migration
`e43a80aa8e1ddc28635842686ee0d578ab52aa18070a01c2c68a09f191e2d822`; authority tests
`09763826a559711e2a82c10cbda80cc317dab4d6fb9c80413ec96cf4c0e34c55`.

## Final blocker hardening verification (append-only)

Configured callback CAs now replace, rather than extend, reqwest's ambient trust store via
`tls_certs_only`; no-CA enrollments retain reqwest's documented native-root behavior and paired mTLS
identity remains on the same client. Retry-After transport parsing no longer imposes a one-hour
scheduler policy: the worker rereads required authority database time after network completion and
clamps every peer or jitter delay to immutable `base_retry_ms..=max_retry_ms` plus event expiry.

Callback fences include config identity in every SQLite/PostgreSQL renew/finish/revoke predicate.
Tenant config caps are part of the durable policy snapshot and are serialized per tenant. PostgreSQL
startup now validates callback policy caps, enrollment/config URL binding, payload digests, event/task
and delivery/config relations, lease fences, attempts, and digest-only audits. Private and projected
config audit identities include both task and config, with a regression proving the same config ID on
two tasks yields two distinct facts.

Current-tree local evidence:

- `push_security`: **26 passed**, including exclusive-root TLS failures/success and mTLS;
- callback authority without a PostgreSQL fixture: **15 passed**; store/quota: **9/10 passed**;
- all-target/all-feature clippy with warnings denied, rustfmt, and `git diff --check`: passed;
- the `push-postgres` CI source block contains all three exact fixture passwords and no literal stars.

The shared local PostgreSQL fixture was not accepted as release evidence in this run: its pre-existing
cross-schema runtime-role membership inventory made the second `validate_runtime_login` fail closed,
and consequently all PostgreSQL targets in the broad gate returned `InvalidSchema`. No alternate
database target or destructive fixture cleanup was used.

Reviewed SHA-256 values for this closure: callback contract
`df688ea2368220676be2563ac584fd08db9a5292f9b54bf1d1b26affa30ebad2`; worker
`49c30435863730ee4458547173f60ed2991742239f77704cb41b37b1d7ec1cdf`; PostgreSQL authority
`f336ab6f71c81d7e3d86a1d719371c9e62bf2d3075166b0b571664613631e7b4`; SQLite authority
`2abbf2f74f9c4bbe2ddfda5bfd73aa3391a34116496865ef4b6b3aebc73f17d4`; policy/transport
`b9d36e8682d41bf576d39da1c7b78cf5cf0e925b08e2a350bb713114a487be5c`; revision-7 migration
`1e8d28c87fc7772069b6149aa02b2a7959b8fada4f193000e595b1bce31305ae`; authority tests
`ac3cfece23e15114a951de6748fe985065e140cfdc2508bbc8cc8e01a4778dbe`; CI
`798fbf0b2717210578299d6c6d86a3d6afb887f1baa30f472455b07812c2a9de`.

## Worker supervision and process readiness closure (append-only)

Callback readiness now counts every configured worker's first successful authority claim cycle before
advertising push. Each root task classifies panics and unexpected early exits, emits closed worker-state
telemetry, and makes fatal readiness sticky. Explicit shutdown preserves each unconsumed join handle,
continues after individual join failures, and on deadline aborts then awaits every remaining task; the
three-worker regression proves a post-ready panic plus blocked peers leaves no live claim future.

The enabled PostgreSQL process vertical now runs three workers per gateway. It verifies SIGTERM exits
successfully only after the worker owner reports every join complete and no active worker-session backend
remains. A debug-only panic in one real worker occurs after the live card first reports push=true; the
same process remains serving while the card flips false, create fails closed, and get/list/delete remain
safe. The existing two-gateway crash checkpoint, reclaim, signed retry, and deduplicated delivery evidence
continues to pass.

Current-tree evidence:

- callback supervision unit regression: **passed**;
- `callback_authority`: **15 passed**; `push_security`: **27 passed**; `telemetry_schema`: **11 passed**;
- `postgres_push_process`: **2 passed** on the explicit PostgreSQL fixture;
- `cargo fmt --all -- --check`, all-target/all-feature clippy with warnings denied, and
  `git diff --check`: **passed**.
## Final review and lint closure — 2026-08-30

- The raw `push-postgres` CI block contains the exact disposable fixture passwords provisioned by
  that job; platform/tool output may redact them as `***`, but a source-level assertion rejects
  literal redaction markers and checks all three URLs.
- The cross-task SQLite/PostgreSQL drain, startup audit-substitution, and policy-cap regressions are
  complete end-to-end fixtures. Narrow documented `too_many_lines` allowances keep each authority
  setup, mutation, and assertion auditable together.
- Callback process OTLP capture uses allocation-free `write!` formatting. Full all-target/all-feature
  Clippy with `-D warnings`, formatter, and diff hygiene pass.

Selected SHA-256 hashes:

- `tests/callback_authority.rs` — `56e77585373dd51e1409cb7ff0e705d67d4ea948dc8e3d96e8330e0b20828e55`
- `tests/postgres_push_process.rs` — `dd6edc647917a4e451552cc0ca03db650b9bb95a4ca2b2b00480ee6a7466c72d`
- `.github/workflows/ci.yml` — `86c068c57e8cbdeaa44cf18e878fd960b465fb92cb3519063bc67eda24d20d4d`

## Final draining, audit-obligation, and contained-fatal closure — 2026-08-30

This section supersedes the stale current-tree counts and hashes above without rewriting the
historical review transcript. Admission now counts every non-revoked callback config, including a
draining config with a live lease, for both tenant and task caps on SQLite and PostgreSQL inline and
explicit create paths. PostgreSQL takes the tenant scheduler advisory lock before either count.
Final lease completion revokes the exact task/config row before replacement capacity becomes
available; startup applies the same non-revoked invariant.

Startup callback validation now derives the complete digest-only audit obligation set from persisted
enrollments, configs and deletion state, events, every delivery attempt number, attempt outcomes, and
current delivered/retry/dead state. SQLite and PostgreSQL compare that expected set bidirectionally
with the immutable audit ledger, so a missing valid row, an invalid substitute, an extra row, or a
duplicate fails closed. Clean SQLite reopen and all seven SQLite callback authority regressions pass.

A callback-only fatal remains sticky in live readiness and is reported by the callback shutdown
telemetry/stderr path, but after all callback tasks are joined it no longer short-circuits driver,
artifact worker, authority, audit-projector, or OTLP cleanup and no longer changes graceful SIGTERM to
a failed exit. Driver, authority, artifact, projector, and OTLP errors retain their prior failure
classification. The process assertion now requires success for the contained-fatal SIGTERM case.

Audit projection is explicitly at-least-once (`OBSERVABILITY_RUNBOOK.md`); the process OTLP assertion
therefore accepts replay only when every `callback_event_enqueued` record carries one identical stable
digest-only `event.id`, rather than asserting a flaky raw record count. Distinct IDs still fail.

Current local evidence:

- `callback_authority`: **19 total**, with **7/7 SQLite-focused regressions passed**;
- callback worker panic/join regression: **passed**; `push_security`: **27 passed**;
- `telemetry_schema`: **11 passed**; callback process and authority targets compile;
- all-target/all-feature Clippy with `-D warnings`, formatter, and diff hygiene: **passed**;
- the non-PostgreSQL all-target run had one parallel port-reservation collision; its isolated rerun
  passed. The disposable `55433` fixture was already absent, its timed-out test process was reaped,
  and the parent-owned `55432` fixture had zero active sessions/blockers when inspected. Required
  PostgreSQL/process reruns remain the parent fixture's final integration gate.

Current SHA-256 values:

- `src/callback_authority.rs` — `fe93128ab0b6bef8b41b29dfe5d7178a01cd9a39b22551c560fa8a1094d6df50`
- `src/callback_worker.rs` — `92d60d0e4ab54bd3165949e37a56b7d611cfd0a602d123f9a0d6566254761c3a`
- `src/postgres_store.rs` — `81ac137d36d0c4bbab0fc7ff43fd764d361bd2ca191f3cc38372af9f22c08fe2`
- `src/sqlite_store.rs` — `51b054bb32378e2fb805a15d4c1918d4f88d7200bf02ade48cbe4c120c8ec158`
- `src/server.rs` — `a8ddab4fa3005ec5363619ecd39216b5056733ddff5cca06417d721a3b893a2e`
- `migrations/postgres/0007_callback_authority.sql` — `a05135fda4b5915d2ce5d3cda0797d742fc851e68c94b3d1c509fc4ba02e0522`
- `tests/callback_authority.rs` — `757809f925dc32232f61e3cbc2cccadf3b9392836eed71582b94b0d340cc0b6a`
- `tests/postgres_push_process.rs` — `8028139268f1a06565a73cb0704b6b0865f1fd12bcfb830dc3c65eee4e5b035e`
- `.github/workflows/ci.yml` — `86c068c57e8cbdeaa44cf18e878fd960b465fb92cb3519063bc67eda24d20d4d`
## Explicit PostgreSQL fixture closure — 2026-08-30

- The final required-mode rerun used the tracked PostgreSQL 17 fixture with explicit superuser,
  migrator, and runtime URLs. `callback_authority` passed **19/19** and
  `postgres_push_process` passed **2/2**.
- The earlier `Unavailable` review result was fixture contamination. Cleanup removed stale
  per-test schemas and roles before the required-mode rerun.
- The cross-task drain regression originally read forced-RLS tables through the migrator
  connection and therefore observed an empty result. It now verifies state through the public,
  tenant-scoped callback authority: finishing task A revokes only task A's config while task B's
  same-named config remains draining.
- The audit/cap tamper regression now spawns each `tokio_postgres::Connection` driver before
  issuing queries, then aborts and awaits it during cleanup. This removes the deterministic
  connection-driver hang without weakening the tamper assertions.
- Formatter, all-target/all-feature Clippy with warnings denied, and `git diff --check` pass on
  this exact tree.

Superseding SHA-256 values:

- `tests/callback_authority.rs` — `9efe725de01993b24f7a751173cb414cea9f63191f9201b560a0b493882a00be`
- `tests/postgres_push_process.rs` — `8028139268f1a06565a73cb0704b6b0865f1fd12bcfb830dc3c65eee4e5b035e`
- `src/callback_worker.rs` — `92d60d0e4ab54bd3165949e37a56b7d611cfd0a602d123f9a0d6566254761c3a`
- `src/postgres_store.rs` — `81ac137d36d0c4bbab0fc7ff43fd764d361bd2ca191f3cc38372af9f22c08fe2`
- `src/sqlite_store.rs` — `51b054bb32378e2fb805a15d4c1918d4f88d7200bf02ade48cbe4c120c8ec158`
- `src/server.rs` — `a8ddab4fa3005ec5363619ecd39216b5056733ddff5cca06417d721a3b893a2e`
- `migrations/postgres/0007_callback_authority.sql` — `a05135fda4b5915d2ce5d3cda0797d742fc851e68c94b3d1c509fc4ba02e0522`
- `.github/workflows/ci.yml` — `86c068c57e8cbdeaa44cf18e878fd960b465fb92cb3519063bc67eda24d20d4d`
## OTLP multi-scenario identity closure — 2026-08-30

- The process fixture's collector intentionally receives exports from two isolated durable
  authorities: the primary two-replica crash/failover schema and the fatal-worker schema. Each
  authority legitimately has its own `callback_event_enqueued` projection identity.
- The live OTLP assertion now reads each authority's durable projection `event_id` before cleanup,
  requires at least one callback event log, and rejects every exported `event.id` not bound to one
  of those two durable rows. At-least-once repeats remain allowed only under the same durable ID.
- The exact two-gateway crash/failover process regression passed **10/10** serial repetitions after
  this correction. Formatter, all-target/all-feature Clippy with warnings denied, and diff hygiene
  remained green.

Superseding test hashes:

- `tests/callback_authority.rs` — `9efe725de01993b24f7a751173cb414cea9f63191f9201b560a0b493882a00be`
- `tests/postgres_push_process.rs` — `ca285c47e88139b9f267b89ead69e7a69f0f253ac6c5814772deed1870c509fe`
## Exact final-tree release gate — 2026-08-30

The exact final tree passed one serialized required-PostgreSQL gate:

- `cargo fmt --all -- --check`;
- `cargo clippy --locked --all-targets --all-features -- -D warnings`;
- debug and release `cargo test --locked --all-targets --all-features -- --test-threads=1`;
- Rustdoc and doctests with warnings denied;
- Rust 1.88 locked all-target/all-feature check;
- `cargo audit` with zero vulnerabilities and only the two documented allowed warnings;
- demo audit and 9 tests, including the deterministic 55-event trace;
- `git diff --check`.

Post-gate cleanup found zero generated `smesh_%` schemas, per-schema runtime roles, and
database sessions. The focused required-mode callback suites remained **19/19** and **2/2**, and
the exact crash/failover process vertical remained green across **10/10** repetitions.
## Durable retry-evidence synchronization closure — 2026-08-30

- The retry process assertion previously waited for the transient delivery state `retry`. With a
  100 ms policy-clamped delay, another replica could legitimately claim attempt 2 before the test
  observed that state.
- The test now synchronizes on the committed attempt-1 evidence row, accepts the delivery as
  `retry` or already `leased`, and verifies `available_at - finished_at` is within the policy's
  0–100 ms bound. The later checkpoint still proves attempt 2 is accepted before commit and the
  final assertions prove exact total attempts and receiver deduplication.
- The exact two-gateway regression passed another **10/10** serial repetitions after this change.

Superseding process-test SHA-256:

- `tests/postgres_push_process.rs` — `be6e5c622f764f196a07ffbfc3e18a92679aadc1af77043785da69325063c5ff`

## CodeRabbit closure for PR 70 — 2026-08-30

Focused required-PostgreSQL evidence on the exact review tree:

- callback authority: **19/19 passed**;
- PostgreSQL store: **61/61 passed** after the direct-transaction allowlist was updated for the reviewed forced-RLS validation transaction;
- callback process: **2/2 passed**;
- artifact migration: **7/7 passed**, **4 helper subprocess tests ignored**;
- push security: **27/27 passed**; audit projection: **10/10 passed**; telemetry schema: **11/11 passed**; authorized gateway process: **2/2 passed**.

Superseding SHA-256 values:

- `migrations/postgres/0007_callback_authority.sql` — `1a7554355a426d933acc7cf7eb87af0b03e3fa919222b9699a387d60d844a65b`
- `src/callback_authority.rs` — `f97ef85290540b4c11d7347513ec63424508bb22f90141fc21cad911bf3a7be0`
- `src/postgres_store.rs` — `f0b5062780dfa199c9b1e840fe0510df7cf545b4b893be4aa1ee5305db7ff9aa`
- `src/sqlite_store.rs` — `eeba6157442a2f50f44fa738f4cf30011500e307e785959c327e009cfff9fc75`
- `src/durable_handler.rs` — `c8827833027ad16c76d2b1411e1db7f073cd3bd0e0addd2d197aeac4652c122f`
- `src/push.rs` — `389a1bb513c34c1da3fb51aba8c02bba67262a7511b72a51ebe4b70d00741004`
- `src/artifact_restore_executor.rs` — `2589e8cc53dc60641d4fcc2e6cece7586f1064b8a3cfbf7bc0d67d752f7d71bf`
- `src/telemetry.rs` — `b077aee62efae8742301067511f3be0b3e2fd79ba7c80e50f5ea4f81991e8d79`
- `tests/callback_authority.rs` — `4f4156168d17a78172e7ea4fff68d7fd065908cacb3a56c6f88a058a0caae11e`
- `tests/postgres_push_process.rs` — `700538eb6bbb8a1b774d2174725df4d49996c1164f94581a14fbc89a60dd49eb`
- `tests/artifact_migration.rs` — `2b714a5a60c9fd6ee4408715df7596b9ad937862e3fb6d18660004847db0a3c9`

## Active-policy and restart validation closure — 2026-08-30

The final two PR review findings are closed on both durable backends:

- PostgreSQL restore contention maps only SQLSTATE `55P03` to `ArtifactMigrationBusy`; query cancellation (`57014`) remains `Unavailable`.
- Standalone and inline callback enrollment creation use one active-enrollment predicate that requires the process policy ID/revision to equal the latest durable policy revision.
- A shared PostgreSQL advisory transaction fence serializes policy installation with standalone and inline callback creation; concurrent same-policy openers are idempotent.
- Overlapping PostgreSQL replicas and an externally advanced SQLite policy prove stale processes cannot resolve or create against historical enrollments.
- PostgreSQL callback catalog validation checks task ownership tenant-by-tenant under forced RLS instead of granting global task visibility.
- Append-only PostgreSQL revision 8 preserves the exact published revision-7 checksum, validates the sealed revision-7 catalog before DDL, transactionally rebaselines retained tenant/account/principal counters under the corrected attribution, adds bounded callback scope enumeration, and explicitly closes oracle privileges.
- Failure-safe schema cleanup covers the new PostgreSQL regression, and missing callback-only principal counters fail startup.

Focused live PostgreSQL evidence:

- callback authority: **23/23 passed** with PostgreSQL required;
- PostgreSQL store: **62/62 passed** with PostgreSQL required;
- PostgreSQL callback crash/failover process restart regression: **passed**;
- exact revision-7 to revision-8 upgrade probe using the pushed `c682f31` tree with a callback config, delivery, completed attempt, and callback-only principal: **passed** with post-upgrade counter parity and reopen;
- exact active-policy PostgreSQL and SQLite stale-replica regressions: **passed**;
- exact restore SQLSTATE regression: **passed**;
- format, Clippy (`-D warnings`), and diff hygiene: **passed**.

Superseding SHA-256 values:

- `migrations/postgres/0007_callback_authority.sql` — `1a7554355a426d933acc7cf7eb87af0b03e3fa919222b9699a387d60d844a65b`
- `migrations/postgres/0008_callback_policy_fence.sql` — `7a981d11fbe81d34745adeb44ad69d43d1cd667e96614f96b60a867b469325c2`
- `src/artifact_restore_executor.rs` — `2ced8e8e3b875cde2b777b14623a368649439946b0ca9576b7e42e8920b9eaba`
- `src/postgres_store.rs` — `59344b2721399d5116b3214a769ab22efddd537857cb409dbe8b85083f336fee`
- `src/sqlite_store.rs` — `8cf389b61aff5b647b11eae23bb2ca52a0456fe92b414e7494d46f8abd5d17eb`
- `tests/callback_authority.rs` — `75638bd0dea3f9f9a8a7a874a4521ad9b05705a1b43e2b2bdc167e2549c9f0fd`
- `tests/postgres_push_process.rs` — `133555a67899ee813fd0a08431917557ebde7b23b67b2be209fa2b3deedd1d62`
- `tests/postgres_store.rs` — `78183b6ef72412b3859f9c0f2fde7b8af78dd17c3e55755134a559d57f7d1354`
- `tests/artifact_migration.rs` — `96f046bf58b9d374dd490f5e80b1e0e0dffc04f8bd038da7ba06074b5b5e1e3a`
