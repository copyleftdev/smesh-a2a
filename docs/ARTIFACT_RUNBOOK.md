# Artifact storage runbook

## Security model

PostgreSQL is the sole metadata, authorization, reference, quota, retention, lease, tombstone, and
job authority. The POSIX root stores immutable ciphertext only. A content digest or filesystem path
never grants access. Normal task rendering and replay never dereference URL parts.

## Prerequisites

1. PostgreSQL revision 5 must pass startup catalog validation with forced tenant RLS.
2. Configure an absolute artifact root owned by the gateway UID with mode 0700. The root itself
   must not be a symlink. Object files are 0600.
3. Configure an explicit 32-byte AES-256 key generation through the server keyring hook. Protected
   classifications fail closed when the generation is missing. Never store key bytes in PostgreSQL.
4. Back up PostgreSQL, the matching immutable-object inventory, and required key generations as one
   declared backup epoch. Do not restore a writable clone against the source object namespace.

## Publication

Stage and hash exact plaintext, encrypt to a same-filesystem temp object, fsync, and compute private
ciphertext evidence before starting the SQL publication transaction. The SQL transaction records the
object, canonical manifest, chunks, provenance, task reference, quota, upload intent, and terminal
workflow state. A bounded promoter atomically renames and marks only verified objects `available`.
Resolvers serve only `available` rows.

Crash before SQL leaves an unreachable stage for bounded orphan cleanup. Crash after SQL leaves a
recoverable upload intent. Promotion and acknowledgements are idempotent. Never infer authority by
inventorying the blob root.

## Resolution and corruption

Authenticate and authorize `Operation::ArtifactResolve`, then resolve the opaque ID through its exact
task/owner binding and acquire a DB-time read lease before opening the blob. Foreign and missing IDs
use the same denial. Verify ciphertext length/digest, AEAD, plaintext length, and plaintext digest in
a bounded spool before committing response headers or bytes. On mismatch, return unavailable,
transactionally quarantine the exact object, and idempotently append one digest-only
`artifact_corruption_audits` row. Subsequent reads fail closed without opening the blob. Do not
refetch or regenerate.

## Retention and GC

Retention uses PostgreSQL time. A generation is ineligible while any live task reference, policy
floor, legal hold, read/backup lease, or required provenance rule exists. GC claims bounded batches
(1..=1000) with `FOR UPDATE SKIP LOCKED`; tombstone generation, lease epoch, and opaque token fence
external deletion. Finalize metadata and release physical quota only after idempotent blob deletion
succeeds. Sweep orphan staging separately.

## Rotation and restore

### Backup inventory and fencing

A Backup lease is the authoritative GC pin for each copied object.

1. Create one `artifact_backup_jobs` row with a unique backup/store/snapshot identity, the exact
   active policy tuple, digest-only actor/reason, and an expiring owner/token/epoch fence. A second
   live job for the tenant is rejected by `artifact_backup_jobs_active`.
2. Acquire a per-object `artifact_backup_leases` fence for every available object in deterministic
   `(tenant_scope, object_id, artifact_id)` order. Renew before half-TTL. The GC predicate excludes
   every object with a non-expired backup lease.
3. Under one PostgreSQL exported snapshot, record sorted manifests, objects, chunks, provenance,
   references, holds, tombstones, key-generation identifiers, private storage locators, lengths and
   digests in `artifact_backup_inventory`. Copy ciphertext while those pins remain live.
4. Verify ciphertext length and domain-separated ciphertext digest, decrypt with the named
   generation, and verify plaintext length/content digest and canonical manifest seal before adding
   each inventory row. `ArtifactBackupInventory::seal` sorts entries and computes the
   `smesh-artifact-backup-inventory/v1` domain-separated digest. Pass `signature_message()` to an
   external HSM hook; neither the inventory nor PostgreSQL contains key bytes.
   The sealed physical inventory includes an authenticated `entryCount`; a legitimate empty
   authority is represented by `entryCount: 0` and `entries: []`, not by an omitted inventory.
5. Seal the job only after every object verifies, then release the exact leases. An expired/stale
   token or epoch cannot renew or release a replacement lease. On crash, the replacement operator
   waits for DB-time expiry and takes a new fence; it never trusts an unsealed inventory.

For a physical database copy, run `pg_dump --serializable-deferrable --format=custom` using the
same exported snapshot epoch, copy the encrypted root without following links, and retain the
sealed canonical inventory beside the dump. The dump, root and inventory are one indivisible
backup set.

### Restore

Restore into an empty PostgreSQL authority and empty 0700 artifact root. Stop every gateway and
projector that can use the target schema before invoking `artifact-restore`; the restore command is the
only permitted target process. The executor checks every mutable authoritative table, including global
orphan journals, before creating a restore journal. `audit_projection_control` and
`audit_projection_outbox` are optional derived state, not authority: with no causative authoritative
rows, restore transactionally locks the projection outbox and control row, refuses an unexpired
projector lease as busy, deletes orphan projection rows, disables projection, and creates the restore
journal in the same transaction. It never ignores arbitrary outbox rows when task, event,
authorization, quota, artifact, or operator source state exists. A gateway configured to enable
projection cannot open while a restore journal is `restoring`.

The operator `artifact-restore` command leaves projection disabled through import and atomic enable, so
restored historical rows are not projected. After successful restore, start the production gateway
with its normal OTLP configuration; that open enables starts-at-enable projection, and only newly
committed causative rows produce events. Do not start a projector early or manually edit projection
leases/checkpoints.

The source and restored
`store_id` must differ, and `artifact_restore_one_enabled_identity` prevents enabling two writable
restores with one identity. Load required keys through the owner-private no-follow keyring; stage
ciphertext at inventory locators; validate schema/catalog/policy, inventory digest/signature,
key-generation coverage, every ciphertext/decrypt/plain digest, canonical manifest, chunk topology,
provenance, reference/refcount, retention/hold/tombstone and quota oracle. Keep the restore job in
`restoring` or `failed` on any missing/wrong key, blob, locator or digest. All inventory semantics and
ciphertext/chunk evidence are authenticated before the first target journal or authority row is
committed, so a rejected restore leaves no stale import. Set `verified`, and then
`enabled`, only after all checks pass; references are never available from a partially staged root.
Restart the gateway and perform authenticated GET/HEAD digest checks before admitting writes.

`clonePolicy: false` never imports the source quota-policy snapshot. `clonePolicy: true` imports the
exact inventory policy under the dedicated reconciliation RLS capability; the restore journal retains
digest-only actor/reason evidence in either mode.

### Key rotation and re-encryption

1. Atomically replace the private keyring file with a document containing both old and new
   generations and selecting the new active generation. `ReloadingArtifactKeyring` parses a complete
   no-follow snapshot before publish; `PostgresTaskStore::reload_artifact_keyring` additionally
   rejects a replacement missing any generation referenced by a live object or by an unexpired,
   unreleased sealed-backup dependency. Restart performs the same check. Expired/released backup
   dependencies no longer pin key material.
2. Insert the digest-audited `artifact_key_rotation_plans` row. Mark the old generation decrypt-only
   and the new generation active; all new publication uses the atomically selected generation.
3. Materialize bounded `artifact_reencryption_jobs`. Workers use
   `claim_artifact_reencryption`, DB time, `FOR UPDATE SKIP LOCKED`, and owner/token/epoch fencing.
   Decrypt and verify old ciphertext, encrypt under the new generation and exact AAD, stage/fsync and
   verify the new object, then transactionally swap only under the current generation fence. Content,
   chunk and manifest digests do not change.
4. Retain old physical ciphertext until the rollback horizon and all read/backup leases expire.
   A stale worker cannot swap or delete. After the last reference to the old generation disappears,
   delete the old object and only then retire/remove old key material. Crash at stage leaves an
   orphan; crash after swap resumes from `swapped`; duplicate completion is idempotent.

### Operator commands

All three commands consume exactly one absolute owner-private (`0600`) no-follow JSON plan. They
preflight roots and keyrings before PostgreSQL acquisition and never invoke a shell. Signature hooks
are absolute executable paths plus a bounded argv; payload bytes are written on stdin.

```sh
# Required by every operator command; use explicit least-privilege URLs and a
# trusted CA file that validates the database certificate and hostname. The
# connector uses rustls native roots plus SSL_CERT_FILE (and SSL_CERT_DIR, when set).
export SSL_CERT_FILE='/run/secrets/postgres-ca.pem'
export SMESH_A2A_POSTGRES_MIGRATOR_URL='postgresql://migrator:***@db.example/smesh?sslmode=verify-full'
export SMESH_A2A_POSTGRES_RUNTIME_URL='postgresql://runtime:***@db.example/smesh?sslmode=verify-full'
export SMESH_A2A_POSTGRES_SCHEMA='smesh_prod'
export SMESH_A2A_ARTIFACT_ROOT='/srv/smesh/artifacts'
export SMESH_A2A_ARTIFACT_KEYRING_PATH='/run/secrets/smesh-artifact-keys.json'

SMESH_A2A_ARTIFACT_BACKUP_OWNER='host-a:backup-17' \
  smesh-a2a-gateway artifact-backup /run/secrets/artifact-backup-plan.json

# Run offline. A committed staging journal makes production startup return
# ArtifactRestoreIncomplete until verification and atomic enablement finish.
smesh-a2a-gateway artifact-restore /run/secrets/artifact-restore-plan.json

SMESH_A2A_ARTIFACT_ROTATION_OWNER='host-a:rotation-9' \
  smesh-a2a-gateway artifact-key-rotate /run/secrets/artifact-key-rotation-plan.json
```

Backup plans bind source schema/store identity, artifact policy, actor/reason, a pre-created private
absolute destination, batch `1..=1000`, DB lease duration, and optional signature hook. Restore plans
bind backup root/inventory/source identity to a distinct target schema/store/root, policy digest,
actor/reason, clone policy, and optional verifier hook. Rotation plans bind source identity,
encryption domain, old/new generations, policy, effective DB time, lease, batch, and rollback horizon.

## Migration

Revision 5 expands the PostgreSQL catalog only; it remains transactional and external-I/O-free.
When artifact storage is configured, production startup calls
`artifact_inline_migration_required` before creating the runtime pool. It scans A2A artifact
`text`, strict-base64 `raw`, and canonical structured `data` parts in task/event JSON,
idempotency admission/final/causative JSON, outbox, receiver inbox/frame/termination JSON, stream
frames, and frozen list entries. URL parts are never dereferenced. Any inline bytes or any incomplete
journal returns `ArtifactMigrationRequired`; merely configuring a plan never rewrites data.

The operator plan is a private (`0600`), no-follow JSON file. Unknown fields are rejected:

```json
{"schema":"smesh-artifact-migration-plan/v1","planId":"migration-2026-01","source":{"schema":"smesh_prod","storeId":"sha256:<64 lowercase hex>"},"sourceSchemaVersion":5,"policy":{"id":"artifact-migration","revision":1,"digest":"sha256:<64 lowercase hex>"},"actor":"operator identity","reason":"approved inline artifact migration","batchSize":100}
```

Run the offline executor with the normal explicit PostgreSQL and artifact environment plus a unique
operator owner:

```sh
SSL_CERT_FILE='/run/secrets/postgres-ca.pem' \
SMESH_A2A_POSTGRES_MIGRATOR_URL='postgresql://db.example/smesh?sslmode=verify-full' \
SMESH_A2A_POSTGRES_RUNTIME_URL='postgresql://db.example/smesh?sslmode=verify-full' \
SMESH_A2A_POSTGRES_SCHEMA='smesh_prod' \
SMESH_A2A_ARTIFACT_ROOT='/srv/smesh/artifacts' \
SMESH_A2A_ARTIFACT_KEYRING_PATH='/run/secrets/smesh-artifact-keys.json' \
SMESH_A2A_ARTIFACT_MIGRATION_OWNER='host-a:operator-job-17' \
  smesh-a2a-gateway artifact-migrate /run/secrets/artifact-migration-plan.json
```

The source schema/store identity, policy identity/revision/digest, actor/reason digests, and batch
`1..=1000` are sealed in the journal. `artifact_migration_one_active` plus owner/token/epoch and DB
expiry admits one migrator and fences stale workers. Before creating a plan row, the executor rejects
nonterminal task, outbox, receiver, transcript, or cancellation work.
When a plan is configured at startup, every sealed plan field and all checkpoint/completion seals must
match exactly; matching only `planId` is insufficient.

Candidates are ordered by `(tenant, task, relation, row-id, artifact-id)`. Text uses exact UTF-8,
raw uses strict standard base64, data uses recursively key-sorted compact JSON, and multipart values
use the versioned inline-artifact envelope. URL strings are inert envelope metadata and disappear from
public JSON. Encrypted CAS staging/fsync occurs outside SQL. One fenced SQL transaction registers the
object, manifest, chunks, reference and upload intent; rewrites every selected causal copy; recomputes
frame, transcript, idempotency-version and frozen-snapshot seals; and advances input/output checkpoint
seals. A pre-commit failure leaves no SQL divergence and only a scanner-owned stage orphan.

Restart reacquires only an expired lease at a higher epoch and rescans from committed state. Exact
rerun of a completed plan performs zero rewrites and no refcount or retained-quota charge. Completion
requires a full zero-inline rescan plus manifest/reference/object/upload consistency and records a
completion seal. Uploads may then be promoted by the normal fenced promoter; startup is permitted
because public JSON already contains only authenticated manifest references. SQLite remains
unsupported for this operator command.
