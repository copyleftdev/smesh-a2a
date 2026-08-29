# Issue 15 — artifact authority evidence

## Implemented and locally verified

- Closed `ContentDigestV1` and immutable `ArtifactManifestV1` with exact plaintext length, fixed 4 MiB
  chunk digests, normalized media type, classification, encryption domain/key generation, full
  producer binding, sorted typed provenance, policy snapshot, retention timestamps, deterministic
  canonical JSON, and domain-separated manifest digest.
- Manifest-only A2A `DataPart` projection with relative authenticated GET/HEAD resolver relation and
  no plaintext, tenant, owner, key, encryption domain, locator, or path.
- AES-256-GCM POSIX store using random nonce, bound AAD, random tenant/domain-scoped placement,
  0600 create-new staging, fsync, atomic rename, and full verification before returning a byte.
- Opaque tenant/task/owner authorization before blob lookup; foreign and missing return the same
  error and perform no store lookup.
- Same-tenant provenance target checks, classification/domain monotonicity, read leases, legal holds,
  reference release, bounded fenced tombstone/delete flow.
- Strict production artifact policy configuration with absolute POSIX root/keyring paths, fixed 4 MiB
  chunks, bounded object/retention/lease/worker limits, and path-redacted diagnostics.
- Owner-private no-follow JSON AES-256 keyring loading with strict schema, bounded generations, active
  generation validation, and old-generation read support; key bytes are always redacted.
- PostgreSQL revision 5 schema for key generations, objects, manifests, chunks, references,
  provenance, upload/promotion intents, read leases, holds, GC jobs, tombstones, and append-only key
  audit with forced tenant RLS and scoped indexes.
- `Operation::ArtifactResolve` added to the closed role matrix.
- Receiver-produced artifact bytes are staged before completion, while objects, manifests, chunks,
  provenance, references, and upload intents now publish inside the exact fenced receiver effect,
  frame, and completion transaction. Transaction failure leaves only a non-authoritative stage file.
- The authenticated production resolver performs request and exact-length egress charging before blob
  I/O, persists digest-only allow/deny authorization decisions, acquires a fenced read lease in its
  scope-first metadata transaction, verifies the complete plaintext before headers, and closes the
  lease before returning GET/HEAD bytes.
- Production now owns joinable promoter and GC workers. PostgreSQL claims GC work with database time,
  tenant-ordered `SKIP LOCKED`, read/reference/hold fences, tombstone generations, and typed owner/token/
  epoch fencing; blob deletion precedes transactional finalization and failures return to tombstoned.

Focused RED→GREEN commands:

- `cargo test --test artifact_storage` — 10 passed.
- `cargo test --test postgres_store -- --test-threads=1` against a tracked PostgreSQL 17.10
  tmpfs-backed fixture — 48 passed, including revision-5 migration/catalog/RLS, crash reconciliation,
  transaction faults, lease fencing, process cleanup, bounded query plans, and SQLite core-row parity.
- `cargo test --lib` — 53 passed.
- `cargo test --test postgres_quota -- --test-threads=1` — 29 passed.
- `cargo test --test postgres_quota_process -- --test-threads=1` — 2 passed.
- `cargo test --locked --all-targets --all-features -- --test-threads=1` — passed with the required
  PostgreSQL fixture, including production mTLS/process suites.
- `cargo clippy --all-targets --all-features -- -D warnings` — passed.

## Current Phase-A evidence status

This pass executed the production artifact authority against the parent-owned PostgreSQL 17.11 fixture at `127.0.0.1:55432`. `artifact_receiver_publication_faults_roll_back_and_retry_exactly_once` iterates all 18 typed checkpoints against real receiver/outbox rows. At every checkpoint it asserts zero escaped content-object, manifest, chunk, provenance, reference, upload-intent, loopback-effect, or frame mutations and a still-processing receiver, then retries the byte-identical payload and asserts exactly one manifest/chunk/reference/upload/effect, exactly two frames, completed receiver state, and successful authority reopen.

`artifact_authenticated_socket_wire_matrix` starts the authorized production Axum router on a real TCP listener with a real PostgreSQL authority and encrypted POSIX blob. It verifies unauthenticated 401; owner GET and HEAD; attachment/content-length headers; unsupported range 416 with `Accept-Ranges: none`; indistinguishable foreign-owner and missing 404; immediate client disconnect with zero active read leases; ciphertext corruption returning 500 before bytes; and closed-authority outage returning 503. `artifact_two_scanners_delete_and_refund_once` starts two barrier-synchronized PostgreSQL-backed scanners against the same stage candidate and proves exactly one physical delete, one 4,096-byte refund report, and one durable orphan audit. The promoter/GC barrier test continues to prove disjoint exact claims and stale token/generation rejection.

The real wire test exposed two production defects that source-only tests had missed: canonical `ContentDigestV1` values serialized as byte arrays although both resolver and startup validation require canonical `sha256:` strings, and manifest encryption AAD used debug classification names rather than canonical lowercase names. Manual string serde and canonical classification AAD now make real staged→registered→promoted→resolved bytes and reopen validation succeed.

`artifact_authenticated_socket_wire_matrix` now also installs an enforced immutable quota policy in the real PostgreSQL authority. A direct resolver read, HEAD, GET, disconnected socket, and integrity-failing GET establish exact per-request semantics and the byte boundary; the next authenticated GET is rejected with HTTP 429 and bounded `Retry-After: 1` before a read lease or blob read and without ETag, media type, or disposition headers. A direct blob-read counter and active-lease query remain unchanged across denial. The durable denial row contains only digests (the raw artifact ID is absent). The test also exposed and closed two quota bypasses: resolver requests now use a fresh server-owned decision ID rather than a replayable artifact digest, and quota semantic uniqueness is scoped by tenant/account/principal/operation rather than allowing one principal to poison another principal's key.

Verified commands and exact results:

- `cargo test --locked --test artifact_storage -- --test-threads=1` — **28 passed**.
- `cargo test --locked --test postgres_store artifact_ -- --test-threads=1` — **4 passed**.
- `cargo test --locked --test postgres_store -- --test-threads=1` — **52 passed**.
- `cargo test --locked --test postgres_quota -- --test-threads=1` — **29 passed**.
- `cargo test --locked --test postgres_quota_process -- --test-threads=1` — **2 passed**.
- `cargo test --locked --release --all-targets --all-features -- --test-threads=1` — **passed**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check` — **passed**.

Current reviewed SHA-256 values: distributed quota migration `ead8e47023350db471e8d2d6cf68ec82f26998d91880fc3b1755510985a1bd5f`; artifact migration `3a7e2cadd67446382afa1fde1c1a5039016aef4e6836b6190017eb7600bb58b5`; PostgreSQL authority `e7a261c6b1fc22954a0ba77751a0ff1fbaa80c199b62fd93a0666a602e99ab70`; resolver `2b1645e735d72739a2f13c005c6c7bc4243ee57b4fe73c3e103f8b328a381105`; artifact store `4c059bed172d27ffa581ffbc519b1e5e2850c7302ad217893674c215bb098257`; PostgreSQL evidence harness `9c6f00ce25bb651a153ac3a1c6f6bb0625b7192c0ac98c024043c5fc09868cd7`.

## Phase-A closure

All three final Phase-A blockers are now executed and green against the required PostgreSQL 17 fixture with explicit superuser, migrator, and runtime URLs and `SMESH_POSTGRES_TEST_REQUIRED=1`.

- Scanner crash/registration: `artifact_two_scanners_delete_and_refund_once` now persists `artifact_orphan_candidates` ownership (token, generation, lease, exact ciphertext length) before unlink under the same stage-locator advisory fence used by both direct and receiver registration. It executes two disjoint scanners, registration-wins/live-stage preservation, scanner-wins/fail-closed registration, crash-after-unlink takeover, exactly one refund/audit, finalized replay returning zero, and direct file/row checks. Candidate enumeration remains POSIX-bounded and ignores malformed, nonregular, and symlink entries.
- Tamper/reopen: `artifact_tamper_reopen_matrix` creates a clean deterministic baseline in a fresh schema/root for each of **30 named semantic mutations**. Every object, manifest, chunk, provenance, upload/read/backup lease, hold, tombstone, and GC case returns `PostgresStoreError::InvalidSchema`; `artifact_tamper_baseline_reopens` proves the control fixture reopens. The matrix exposed and closed a real missing object-to-manifest plaintext-length/classification/domain seal. `encrypted_posix_roundtrip_and_corruption_fail_before_bytes` executes corrupt, truncated, swapped-ciphertext, and wrong-key reads; the socket resolver corruption case returns before response bytes/metadata.
- EXPLAIN/load/fairness/disk: `artifact_populated_default_plans_and_batch_bound` loads **2,000 rows per artifact authority family**, runs default-planner EXPLAINs for resolver, upload, GC, read, backup, hold, and provenance production fragments, and rejects every `Seq Scan`/`Sort` while asserting the exact scoped index name. It proves a 1,001 batch is rejected and a 1,000 batch is bounded. Canonical extracted function SQL hash is `sha256:fbfe42d9c0f3267964d6e62a4cfe9ef7c37fcfcb56794ff5ca9fb4aab608db03`. `artifact_claims_are_fair_across_active_tenants` runs two independent stores/workers against continuous tenant-A backlog plus tenants B/C and services all three within one active-tenant turn. Chunk tests execute 4 MiB minus one, exact, and plus one; dedupe executes same-domain reuse and tenant/classification isolation. The disk test writes **16 distinct 64 KiB-class objects**, asserts ciphertext plus at most 4 KiB/object overhead, then release/GC returns exact file bytes to baseline with no leaked CAS roots.

Verified commands and exact results for this closure:

- `cargo test --locked --test artifact_storage -- --test-threads=1` — **29 passed**.
- `cargo test --locked --test postgres_store artifact_ -- --test-threads=1` — **8 passed**.
- `cargo test --locked --test postgres_store -- --test-threads=1` — **56 passed**.
- `cargo test --locked --release --all-targets --all-features -- --test-threads=1` — **passed**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check` — **passed**.

Phase A is complete; the issue may proceed to Phase B.

## Phase-B operator-control foundation (not closure)

This tree now has validated public plan/inventory contracts and revision-5 operator journals for
inline migration, backup inventory, restore enablement, key rotation, and bounded re-encryption.
Production artifact startup checks durable artifact JSON before constructing its runtime pool and
returns `ArtifactMigrationRequired` unless the configured plan has a completed journal entry.
`ArtifactBackupInventory` sorts object evidence and seals canonical JSON with the
`smesh-artifact-backup-inventory/v1` domain; inventory exposes generation IDs and locators but no
key bytes. `ReloadingArtifactKeyring` parses strict owner-private no-follow snapshots before atomic
publication, preserves the prior snapshot after malformed reload, and the PostgreSQL reload hook
refuses replacements missing any generation referenced by live objects. Revision 5 has exact RLS,
retained-authority accounting, exclusive migration/backup/restore indexes, and a DB-time bounded
`claim_artifact_reencryption` fence.

Verified on the parent-owned PostgreSQL 17 fixture at `127.0.0.1:55432`:

- `cargo test --test artifact_storage -- --test-threads=1` — **33 passed**.
- `SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --test postgres_store -- --test-threads=1` — **56 passed**.
- `cargo clippy --all-targets --all-features -- -D warnings` — **passed**.
- `cargo doc --no-deps --all-features`, `cargo fmt --all -- --check`, and `git diff --check` — **passed**.

## Populated inline migration executor evidence

The operator executor is now present as `PostgresTaskStore::migrate_inline_artifacts` and the
`smesh-a2a-gateway artifact-migrate <private-plan.json>` command. The plan parser is strict,
no-follow and owner-private; the source schema/store and policy are digest-bound. The scanner covers
task/event, all three idempotency JSON values, outbox, receiver payload/termination/frames, stream
frames and frozen snapshots. Canonical Text/Raw/Data bytes are encrypted before the fenced SQL batch;
URL canaries are inert. The journal stores owner/token/epoch, input/output checkpoint seals and a
full-rescan completion seal. Exact completed replay returns zero rewrites and preserves refcount.

Verified on the explicit parent-owned PostgreSQL 17 fixture at `127.0.0.1:55432`:

- `cargo test --locked --test artifact_migration` — **4 passed**, including populated task/event
  causal-copy rewrite, startup fail-closed before migration, exact rerun, retained accounting, and
  successful semantic reopen.
- `cargo test --locked --test artifact_storage` — **33 passed**.
- `cargo test --locked --test postgres_store migrates_empty_real_postgres_and_reopens_with_same_identity -- --nocapture` — **1 passed**.
- `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`,
  and `git diff --check` — **passed**.

CI now runs `artifact_migration` serially in the PostgreSQL artifact evidence job.

## Physical operator executor progress

The tree now exposes strict `artifact-backup`, `artifact-restore`, and `artifact-key-rotate` commands
and owner-private no-follow plans. The PostgreSQL/POSIX migration integration test performs a real
promote → repeatable-read verified ciphertext backup → distinct-store encrypted-root restore → fresh-
nonce key-2 re-encryption → semantic reopen sequence. Backup writes canonical domain-separated
inventory/digest files atomically, persists inventory rows, and rejects stale job/object fences.
Restore verifies inventory digest, optional detached verifier hook, source/target identity separation,
all copied ciphertext/AEAD/plain metadata, and matching offline PostgreSQL metadata before recording
an enabled restore. Rotation validates a complete old+new keyring before PostgreSQL, materializes and
claims bounded jobs, swaps only physical fields under owner/token/epoch fencing, updates upload
physical evidence, retains old ciphertext through the rollback horizon, and performs bounded
lease-aware cleanup on a later join.

Verified locally against the explicit PostgreSQL 17 fixture:

- `cargo test --locked --test artifact_migration -- --test-threads=1` — **4 passed**, including the
  physical backup/restore/re-encryption/reopen path.
- `cargo test --locked --test artifact_operators -- --test-threads=1` — **1 passed**.
- `cargo test --locked --test artifact_storage -- --test-threads=1` — **33 passed**.
- `SMESH_POSTGRES_TEST_REQUIRED=1 cargo test --locked --test postgres_store -- --test-threads=1` —
  **56 passed**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`,
  and `git diff --check` — **passed**.

The dedicated two-binary crash/failover matrix and exhaustive component-corruption matrix are not yet
present, so this evidence does not claim complete Phase-B closure.

Full Phase-B closure still requires expansion of the dedicated two-binary
`tests/postgres_artifact_process.rs` into the remaining crash-checkpoint and exhaustive per-component
operator fault matrix. No release/full-issue completion claim is made.

## Two-binary production artifact tracer

A dedicated debug-only `postgres_artifact_process` test now starts two distinct real
`smesh-a2a-gateway` processes with independent sockets/pools/replica identities, shared PostgreSQL and
encrypted POSIX CAS/keyring, required mTLS, authorization, quota, and artifact configuration. It sends
an official JSON-RPC task through A, reads the terminal manifest-only task through B, proves the output
canary is absent from task/event/idempotency/receiver/stream durable JSON, verifies exact resolver
GET/HEAD bytes and headers through B, kills and reaps A, and proves replay through B preserves the task,
manifest, object, reference count, and quota-backed authority. The harness has watchdogs plus RAII child,
schema/role, and filesystem cleanup and is serially wired into the PostgreSQL CI job.

The tracer exposed and fixed three production defects: the binary ignored artifact root/keyring
configuration; the winning receiver returned pre-publication inline events to the sender instead of
reloading authoritative manifest frames; and runtime-role validation treated valid sibling schema roles
as unexpected while still needing to reject malformed sibling grants. Artifact startup is now logged as
a boolean only, without paths or key material.

Exact verification on the explicit PostgreSQL 17 fixture:

- `cargo test --locked --test postgres_artifact_process -- --test-threads=1` — **1 passed**, repeated
  three times at **1.56s, 1.49s, and 1.49s** before the final full-suite run.
- `cargo test --locked --test artifact_storage -- --test-threads=1` — **33 passed**.
- `cargo test --locked --test artifact_migration -- --test-threads=1` — **4 passed**.
- `cargo test --locked --test artifact_operators -- --test-threads=1` — **1 passed**.
- `cargo test --locked --test postgres_store -- --test-threads=1` — **56 passed**.
- `cargo test --locked --test postgres_multi_replica -- --test-threads=1` — **2 passed**.
- `cargo test --locked --all-targets --all-features -- --test-threads=1` — **passed**.
- `cargo test --locked --release --all-targets --all-features -- --test-threads=1` — **passed**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` — **passed**.

This tracer closes the real two-binary publication/failover path, but the issue's remaining enumerated
process crash cuts and exhaustive operator component-fault expansion are not represented by this single
test yet; Phase-B closure is therefore still not claimed.

## Crash-checkpoint and operator hardening progress (not closure)

The synthetic checkpoint-only child and its reachability claims have been removed. The table below
contains only production actions that now have a real parent-observed crash and verified post-restart
semantics; checkpoint reachability by itself is not recorded as evidence.

| Production checkpoint | Real scenario | Post-restart semantic assertion |
|---|---|---|
| `publication_stage_before_receiver_transaction` | An mTLS client submits a real JSON-RPC task to the production gateway; the receiver stages encrypted output, emits production `READY`, and the parent SIGKILLs and reaps that gateway before its receiver transaction. A distinct replica then retries the same semantic message. | Before kill, PostgreSQL has zero manifests, objects, upload intents, or loopback effects. After lease-based restart recovery, the task completes with exactly one manifest, one object, reference count one, and one loopback effect. |

The physical restore integration now rejects forged inventory digest, schema, source store ID, policy
digest, missing object list, key generation, manifest digest, manifest canonical JSON, provenance, and
ciphertext blob while asserting zero enabled restore rows. Restore also compares every canonical
inventory entry against the restored PostgreSQL backup journal, requires exact manifest/object/inventory
cardinality, and uses a schema/restore-ID advisory owner fence. Concurrent integration probes proved one
restore winner, one backup winner, one migration winner, and exactly one re-encrypted object across two
rotation workers.

Verified commands:

- `cargo test --locked --test postgres_artifact_process -- --test-threads=1` — **4 passed**; repeated
  three times at **1.77s, 1.72s, and 1.73s**.
- `cargo test --locked --test artifact_migration -- --test-threads=1` — **4 passed**.
- `cargo test --locked --test postgres_store artifact_ -- --test-threads=1` — **8 passed**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`,
  and `git diff --check` — **passed**.

The full debug all-target gate now passes after fixing the startup-role root cause: sibling generated runtime roles are accepted only when each remains a no-login/non-inheriting/unprivileged role paired with an existing schema and an exact admin edge from that schema's owner. The dedicated non-superuser migrator regression and all **56** serial `postgres_store` tests are green without weakening runtime privilege validation.

Detached signature integration now executes an argv-only test signer/verifier pair through the real backup and restore executors. A valid detached signature reaches final restore enablement; missing, mutated, wrong-signer, and command-failure variants fail with zero restore jobs. Hook execution has a five-second kill-on-drop timeout, signature stdout is bounded to 64 KiB, and stderr is suppressed. Artifact integration roots are centralized under a test-owned `target/artifact-tests` 0700 parent (or explicit `SMESH_TEST_ARTIFACT_ROOT`) with RAII cleanup; no artifact test relies on ambient `TMPDIR`.

The two-binary tracer additionally reads the actual child process environments to prove distinct `artifact-a`/`artifact-b` replica IDs, proves distinct PIDs and sockets, and queries `pg_stat_activity` for at least two distinct live runtime-pool backends. Its asynchronous promoter observation is now bounded and event-yielding rather than racing terminal task visibility. The complete process suite repeated three times at **3.20s, 1.80s, and 1.80s**.

Latest exact gates:

- `cargo test --locked --test postgres_store -- --test-threads=1` — **56 passed**.
- `cargo test --locked --all-targets --all-features -- --test-threads=1` with explicit PostgreSQL URLs and no `TMPDIR` override — **passed**.
- `cargo test --release --locked --all-targets --all-features -- --test-threads=1` with the same explicit fixture — **passed**.
- `cargo test --locked --test artifact_storage -- --test-threads=1` — **33 passed**.
- `cargo test --locked --test artifact_migration -- --test-threads=1` — **4 passed, 4 hook subprocess tests ignored by normal harness and invoked explicitly by the integration**.
- `cargo test --locked --test postgres_artifact_process -- --test-threads=1`, three consecutive runs — **4 passed each**.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, and `git diff --check` — **passed**.
- `cargo +1.88.0 check --locked --all-targets --all-features` — **passed**.
- `cargo audit` — **passed with 0 vulnerabilities and the two repository-allowed upstream warnings** (`bincode` unmaintained, yanked transitive `chacha20`).
- Demo high-severity audit, three Node syntax checks, nine tests, trace validation, and deterministic 55-event trace comparison — **passed**.

## Final schema and operator-blocker closure

The final focused reproduction failed on the first empty store open with `InvalidSchema`. Exact catalog
queries isolated the revision-5 mismatch to lexical table order: `artifact_backup_key_dependencies`
had been inserted before `artifact_backup_jobs` in the sealed expected arrays even though PostgreSQL
orders `artifact_backup_jobs` first. The catalog, RLS flags, policies, indexes, definer functions,
migration checksums, and computed catalog digest were otherwise exact. Correcting both expected table
arrays restores strict validation without weakening it.

The same run closed the remaining operator blockers:

- GC versus read lease, committed backup lease, and retention hold is covered in both acquisition
  orderings using two independently opened stores; exactly the first row-lock owner wins.
- Configured migration readiness now compares every plan field and all checkpoint/completion seals
  under the narrow migrator RLS capability; source identity is additionally exact for plan files.
- Physical inventories authenticate `entryCount`, including a valid sealed zero-object backup/restore.
  Restore checks every mutable authority table and authenticates inventory/ciphertext/chunks before the
  first target row, eliminating stale failed imports rather than masking them with `ON CONFLICT`.
- `clonePolicy=false` omits source quota policy; `clonePolicy=true` imports the exact row through the
  reconciliation RLS path, with digest-only actor/reason restore-journal assertions.
- Sealed-backup key dependencies block both keyring reload and process restart until released/expired.
- The backup dependency SQL parameter is explicitly cast to `bigint`; the prior untyped parameter was
  the exact `42804` backup-seal failure.

Final explicit PostgreSQL evidence: `artifact_migration` **6 passed / 4 signer helpers ignored**,
`artifact_operators` **1 passed**, `artifact_storage` **42 passed**, `postgres_store` **57 passed**, and
`postgres_artifact_process` **2 passed**. Full locked debug and release all-target/all-feature suites
passed. Formatting, Clippy `-D warnings`, Rustdoc `-D warnings`, Rust 1.88 MSRV check, and
`git diff --check` passed. `cargo audit` reported zero vulnerabilities and only the repository-allowed
`bincode` unmaintained / transitive `chacha20` yanked warnings. Demo high-severity audit, nine tests,
trace validation, and Node syntax checks passed.

Final content hashes before this evidence append:

- `migrations/postgres/0005_artifact_authority.sql`: `41244553d4d3a9b40c944f0b9611e7bc9f7a33d545f9b004c5c1ab426ccb6c74`
- `README.md`: `23ff9fa3fef9030ba98e9a25782628b60309184742ee4a42483402727cf8f40b`
- `docs/ARTIFACT_RUNBOOK.md`: `498ca2f8ce0c13ce10e73a98bfcce9c851ee78de584925c72a01cde7c234f645`

## Authenticated migration seal and re-encryption recovery closure

The migration journal now binds a domain-separated v2 completion seal to the exact plan ID/digest,
source schema/store identity, policy ID/revision/digest, deterministic final checkpoint key and chained
input/output seals, migrated artifact/row/byte totals, and a completion-time digest over every durable
JSON source. Completion is one authoritative `processing` transaction fenced by exact plan, owner,
token, epoch, and an unexpired database-time lease; the seal and full rescan are recomputed inside that
transaction. Configured startup verifies the exact journal and seal before pool creation, then performs
a fresh zero-inline scan. Corruption probes cover the plan digest, checkpoint relation/input/output,
completion/full-rescan seals, and all three totals; reintroduced inline task JSON fails closed and an
exact restored restart succeeds.

Re-encryption jobs now persist final/stage locators, nonce, ciphertext digest/length, and the new-
generation AAD seal before promotion. Claims preserve and return exact staged/promoted/swapped/cleanup
state and physical metadata. The worker resumes the registered ciphertext, authenticates an already-
promoted final object, commits `promoted` before the atomic object/upload swap, and makes old-object
delete plus cleanup/completion idempotent. Physical mismatch marks the fenced job failed without a
metadata swap. The real PostgreSQL/POSIX rotation path verifies one new ciphertext, unchanged logical
manifest digest, exact resolver bytes through the surrounding integration, and no old file after the
zero-horizon cleanup. Five production crash boundaries are present in the process checkpoint inventory;
the existing two-process publication/failover suite remains green.

Final explicit PostgreSQL 17 evidence (all URLs supplied explicitly; credential output remained
redacted): `artifact_migration` **6 passed / 4 helper subprocesses ignored**, `artifact_operators`
**1 passed**, `artifact_storage` **42 passed**, `postgres_store` **57 passed**, and
`postgres_artifact_process` **2 passed**. Full locked debug and release all-target/all-feature gates
passed. Formatting, Clippy `-D warnings`, Rustdoc `-D warnings`, Rust 1.88 all-target check, and
`git diff --check` passed. `cargo audit` found zero vulnerabilities and only the two repository-allowed
warnings (`bincode` unmaintained and transitive `chacha20` yanked).

Final content hashes before this evidence append:

- `migrations/postgres/0005_artifact_authority.sql`: `fd3367ca6a1ac05e11bc01adaf95265c9aa351cd634534b448ba4443f4829287`
- `src/artifact.rs`: `ba83a5661ff0b3a0ab6011a6cb0525418bc7331e4a496cb581f73c9f53fd0663`
- `src/artifact_migration_executor.rs`: `a4f90f8073c626c7ca2931942b50974a9de91ea45397fb5bd1edd939f3aed3ed`
- `src/artifact_reencryption_executor.rs`: `7d0e46ecd9448d6645e45b320c35604998b25e7fb919b68cd0ab4659fb420ec7`
- `src/postgres_store.rs`: `b57fa25340e6dfe24ca1037cd2f8a7278fdbbae3721d6cea7f1836484b3c0822`
- `tests/artifact_migration.rs`: `39c2e0e223998a1b56768d9c1401ae24d5b784f11cc046e6abc4c4527447fe04`
- `tests/artifact_storage.rs`: `047bf6f1f440b4b7f20e016e3db96beb09385e075341a676df641ca3832b31fc`
- `tests/postgres_artifact_process.rs`: `7cfa10fdde28516538a112e465be3ba7ffcde78b48cc908ceb9b9c16c45c2a32`

## Final promoted-ciphertext and source-compatibility closure

A debug-build production subprocess now crashes at
`reencryption_promoted_before_metadata_swap` in two real recovery paths. The corruption path truncates
the registered final ciphertext after the durable `promoted` acknowledgement. Recovery reclaims with a
new token/epoch, verifies the exact owner-private no-follow regular file, persisted ciphertext length and
digest, new-generation AEAD nonce/AAD, plaintext length/content digest, and canonical manifest/chunk
rows before any metadata transaction. The mismatch deletes the unauthoritative replacement, marks only
the re-encryption job failed, rejects the stale token, leaves content-object and upload locators/key
metadata unchanged, and resolves the original bytes and logical manifest. The valid path crashes at the
same boundary without mutation; recovery authenticates the promoted object, swaps once, performs
zero-horizon old-file cleanup, and resolves byte-identical plaintext with the unchanged manifest digest.

`AuthorityIdentity` now carries the default-`None` optional artifact extension, while `DurableAuthority`
is again an object-safe marker with a blanket implementation over the complete component-trait set.
PostgreSQL overrides the extension with `Some(self)` in its identity implementation. SQLite, the external
recording fake, and the panic fake have no explicit `DurableAuthority` implementation; the external fake
still converts to `Arc<dyn DurableAuthority>` and the pre-artifact exhaustive `MeshEvent` match remains
source-compatible. The blank-backend compile-fail example remains invalid because it lacks the required
component traits.

Final explicit PostgreSQL 17 evidence (explicit admin/runtime/superuser URLs, credentials redacted):
`artifact_migration` **6 passed / 4 helper subprocesses ignored**, `artifact_operators` **1 passed**,
`artifact_storage` **42 passed**, `postgres_store` **57 passed**, and `postgres_artifact_process`
**2 passed**. The locked debug and release all-target/all-feature gates passed. Formatting, Clippy
`-D warnings`, Rustdoc `-D warnings`, and `git diff --check` passed.

Final closure hashes before this evidence append:

- `src/durable_authority.rs`: `729b9fc8ce8bff86c84bec93f1093206795ea18a2efe46c6b07dd9e0f2de58eb`
- `src/postgres_store.rs`: `4b6aee694894ff1e10707a690d7e1a60ed3e33f7a056b9c069d4d01afa0fc23d`
- `src/sqlite_store.rs`: `269250723e30b7cab7cf564e675ac275929357a63fb5e77a79518f032fb8538c`
- `src/outbox_driver.rs`: `4b2f052464384d59c1be418bb4070783f73acfaf6f4487aa3c86d02fa299045f`
- `src/artifact.rs`: `9cbf5b67fee5078436d55d7cd9fa8b5666358d7c91e92e265b865ea236137f1c`
- `src/artifact_reencryption_executor.rs`: `94b2ccdd6864ee8e917e757304ea9c53f0f633c3ad5a5c9e28826e694e9d1fa6`
- `tests/support/durable_authority_conformance.rs`: `5a1187229626c8123a6fe829657bfcb37bdc70394a467318dd1a4217659450a7`
- `tests/durable_authority_fake.rs`: `d4e45c008ac20504cd833abf292d28b06841e76271ca4949dfc20977173e111c`
- `tests/durable_authority_public_api.rs`: `57749dd0c9fe42cf33e43e65df671dfca7351d7a34f769bd04b746f4db26e777`
- `tests/artifact_migration.rs`: `85546ec2849a0d19aa43f4e90b4442908b77df30a7d7007c7d6471679769c758`
