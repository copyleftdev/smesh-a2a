# Human ratification operator runbook (issue #27 / M3)

This runbook describes the human-ratification boundary implemented on the
`feat/27-human-ratification` tree. It is a readiness artifact for issue #27 and
the M3 gate, not a claim that the issue, milestone, release, merge, or remote CI
is complete.

## Supported production boundary

Ratification is disabled when `SMESH_A2A_RATIFICATION_HMAC_KEY_PATH` is absent.
Setting it enables the console and API only when all of these are true:

- `SMESH_A2A_MODE=loopback`;
- `SMESH_A2A_BIND` has an IPv4 or IPv6 loopback IP (not a wildcard or an
  externally routable address);
- authentication is OIDC bearer and/or direct-TLS mTLS;
- `SMESH_A2A_AUTHORIZATION_POLICY_PATH` names a valid policy;
- `SMESH_A2A_DURABLE_BACKEND=sqlite` with `SMESH_A2A_SQLITE_PATH`, or
  `SMESH_A2A_DURABLE_BACKEND=postgres` with both PostgreSQL URLs, a schema, and
  the mandatory quota policy.

`loopback` is the task-dispatch mode; it does not by itself constrain the HTTP
listener. Ratification separately checks the listener IP. The supported paths
are the production binary's integrated SQLite or PostgreSQL task authority.
`RatificationLedger` is a library compatibility/test component and is not the
production authority.

The gateway has no command-line configuration or `--help` interface. The
binary reads environment variables; an unknown argument such as `--help` does
not print usage and normal startup validation still runs. Use the environment
contracts below and the linked authentication, TLS, authorization, quota, and
PostgreSQL runbooks.

## Create and protect the decision key

The key file contains exactly 32 **raw random bytes**. It is not hex, base64,
PEM, or a line of text. Create it as the same Unix user that runs the gateway:

```bash
STATE_DIR="$HOME/.local/state/smesh-a2a"
KEY_PATH="$STATE_DIR/ratification.hmac"
umask 077
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
openssl rand 32 >"$KEY_PATH"
chmod 600 "$KEY_PATH"
test "$(wc -c <"$KEY_PATH")" -eq 32
case "$KEY_PATH" in /*) ;; *) exit 1;; esac
```

Do not print, hex-dump, copy into shell history, or pass the key bytes in an
environment variable. The configured path must be absolute. The gateway opens
it once read-only with close-on-exec and no-follow, inspects that same
descriptor, and accepts only a regular file owned by the gateway process UID
with no group/world permission bits (`mode & 077 == 0`). It reads at most 33
bytes and requires exactly 32. Relative paths, symlinks, directories, a wrong
owner, `0640`/`0604`, empty/31/33-byte files, and newline-terminated or encoded
keys fail with the redacted error `private file rejected`.

The raw key remains in zeroizing process memory. SQLite and PostgreSQL persist
a versioned generation commitment and keyed check, not the raw key. The key
seals frozen packets and chained receipts.

### Restart and key continuity

A restart of an authority already bound to ratification must supply the same key
file. A wrong key **or a missing `SMESH_A2A_RATIFICATION_HMAC_KEY_PATH`** fails
authority open before readiness, including for an initialized authority with no
ratification rows. On a fresh/unbound authority, absence of the variable keeps
ratification disabled and does not install its routes. Removing the variable is
therefore not a way to disable, rotate, or recover an already bound authority.
Preserve the key with the database backup and restore it with owner-only controls.

Online ratification-key rotation and re-signing are **not implemented**. Do not
replace the file in place or point an existing authority at a new key. A planned
rotation requires a separately reviewed migration/resealing procedure; absent
that procedure, retain the original key or restore the matching database/key
pair.

## Authorization policy

Only an account with `kind: "human"` and the `humanRatifier` role can read,
review, or decide ratification packets. A service account cannot hold that role.
The principal is derived by the server from a verified bearer token or verified
client certificate and mapped through the policy. The browser cannot submit an
authoritative actor, account, tenant membership, policy identity, timestamp,
packet identity, or key generation.

Example policy fragment (merge into a complete
`smesh-authz-policy/v1` document):

```json
{
  "id": "release-ratifier",
  "kind": "human",
  "memberships": [
    {"tenantId": "tenant-a", "roles": ["humanRatifier"]}
  ]
}
```

If the identity has more than one enrolled tenant, the console's tenant field
sends `X-Smesh-Tenant`. It is only a selector among memberships. Duplicate,
comma-combined, malformed, inaccessible, or ambiguously omitted selectors fail
with HTTP 403.

## Start the SQLite production path

All referenced paths must be absolute. This bearer example assumes the OIDC
issuer and JWKS endpoint are HTTPS and already operational:

```bash
STATE_DIR="$HOME/.local/state/smesh-a2a"
export SMESH_A2A_MODE=loopback
export SMESH_A2A_BIND=127.0.0.1:4000
export SMESH_A2A_PUBLIC_URL=http://127.0.0.1:4000
export SMESH_A2A_TRANSPORT_MODE=loopback-plain
export SMESH_A2A_AUTH_MODE=oidc
export SMESH_A2A_OIDC_ISSUER=https://issuer.example
export SMESH_A2A_OIDC_AUDIENCE=smesh-a2a
export SMESH_A2A_OIDC_JWKS_URI=https://issuer.example/.well-known/jwks.json
export SMESH_A2A_AUTHORIZATION_POLICY_PATH="$STATE_DIR/authorization.json"
export SMESH_A2A_DURABLE_BACKEND=sqlite
export SMESH_A2A_SQLITE_PATH="$STATE_DIR/tasks.sqlite3"
export SMESH_A2A_RATIFICATION_HMAC_KEY_PATH="$STATE_DIR/ratification.hmac"
cargo run --bin smesh-a2a-gateway
```

SQLite is Unix-only, owner-private, exclusive single-writer local durability.
Its parent directory must be owner-owned with no group/world permissions. The
database and sidecars are held at `0600`. Current schema is v11; opening an
older supported schema performs the append-only startup migration and validates
the migrated catalog, ratification key check, packet/event chains, state, and
revisions before readiness. Legacy tenant migration still requires both
`SMESH_A2A_LEGACY_TENANT_ID` and
`SMESH_A2A_LEGACY_OWNER_ACCOUNT_ID` to name an enrolled membership.

## Start the PostgreSQL production path

PostgreSQL ratification uses the same production routes and state machine. It
requires distinct TLS PostgreSQL migrator/runtime DSNs, a valid schema
identifier, and the quota policy required by the PostgreSQL production
authority:

```bash
STATE_DIR="$HOME/.local/state/smesh-a2a"
export SMESH_A2A_MODE=loopback
export SMESH_A2A_BIND=127.0.0.1:4000
export SMESH_A2A_PUBLIC_URL=http://127.0.0.1:4000
export SMESH_A2A_TRANSPORT_MODE=loopback-plain
export SMESH_A2A_AUTH_MODE=oidc
export SMESH_A2A_OIDC_ISSUER=https://issuer.example
export SMESH_A2A_OIDC_AUDIENCE=smesh-a2a
export SMESH_A2A_OIDC_JWKS_URI=https://issuer.example/.well-known/jwks.json
export SMESH_A2A_AUTHORIZATION_POLICY_PATH="$STATE_DIR/authorization.json"
export SMESH_A2A_DURABLE_BACKEND=postgres
export SMESH_A2A_POSTGRES_MIGRATOR_URL='postgresql://migrator@db.example/smesh?sslmode=require'
export SMESH_A2A_POSTGRES_RUNTIME_URL='postgresql://runtime@db.example/smesh?sslmode=require'
export SMESH_A2A_POSTGRES_SCHEMA=smesh_gateway
export SMESH_A2A_QUOTA_POLICY_PATH="$STATE_DIR/quota-policy.json"
export SMESH_A2A_RATIFICATION_HMAC_KEY_PATH="$STATE_DIR/ratification.hmac"
cargo run --bin smesh-a2a-gateway
```

Do not place DSNs in shared shell history or logs; prefer the deployment
platform's protected environment injection. Plaintext PostgreSQL is available
only through debug test hooks and is not a production path.

Startup applies and verifies current PostgreSQL revision 11, including sealed
`0010_human_ratification` and `0011_ratification_retained_authority`. The
runtime role is distinct from the migrator,
runtime execution is constrained by the sealed API, and ratification tables use
forced row-level security. Runtime sessions see only their tenant scope; the
runtime role has the minimum ratification table grants, cannot delete events or
packets, and immutable triggers reject packet identity changes and event
updates/deletes. RLS and triggers are defense in depth; server-derived tenant
scope and transaction checks remain authoritative.

### mTLS instead of bearer

For mTLS-only operation use direct TLS and required client authentication:

```bash
export SMESH_A2A_AUTH_MODE=disabled
export SMESH_A2A_TRANSPORT_MODE=direct-tls
export SMESH_A2A_CLIENT_AUTH_MODE=required
export SMESH_A2A_PUBLIC_URL=https://localhost:4000
export SMESH_A2A_TLS_CERT_PATH="$STATE_DIR/tls/server.pem"
export SMESH_A2A_TLS_KEY_PATH="$STATE_DIR/tls/server.key"
export SMESH_A2A_TLS_CLIENT_CA_PATH="$STATE_DIR/tls/client-ca.pem"
export SMESH_A2A_TLS_PRINCIPAL_MAP_PATH="$STATE_DIR/tls/principals.json"
```

Keep the durable backend, authorization policy, bind, and ratification key
variables from one production path above. The server accepts identity only from
the exact mapped SHA-256 fingerprint of the verified leaf certificate; CN, SAN,
forwarding headers, and request metadata do not establish a principal. Optional
mTLS may fall back to a valid bearer only when no certificate is presented. A
verified but unmapped certificate does not fall back. When both credentials are
present, issuer and subject must be identical. Follow
[`TLS_MTLS_ROTATION_RUNBOOK.md`](TLS_MTLS_ROTATION_RUNBOOK.md) for TLS material
reload; SIGHUP does not rotate the ratification HMAC key.

## Startup, readiness, shutdown, and recovery

The production binary validates configuration, authorization, transport
material, the ratification key, and initial OIDC/JWKS state before binding. It
then binds the TCP listener **before** starting telemetry or opening SQLite or
PostgreSQL. An occupied bind therefore leaves SQLite/WAL/SHM, migrations,
recovery, audit projectors, clocks, dispatch workers, and readiness absent.
After bind, it starts optional telemetry, opens and validates the authority,
installs the combined authenticated/authorized/ratification router, starts
projectors and workers, and only then logs `SMESH A2A gateway listening`.

On SIGINT or SIGTERM, stop HTTP admission, allow graceful server shutdown, then
join the clock ticker and the gateway-owned outbox, audit, callback, and other
workers before closing the authority and telemetry owner. A forced kill may
lose only uncommitted work. On restart, SQLite reconciliation or PostgreSQL
lease/fence recovery reclaims durable pending work; clients retry ambiguous
requests with the same semantic idempotency key.

Do not treat an HTTP port-open check as readiness. Require the readiness log and
then exercise authenticated API access. If startup fails, correct the cause and
restart; do not delete key-check, packet, event, audit, quota, callback, or
outbox rows.

## Browser and HTTP contract

The ratification router exposes exactly:

- public, fixed, data-free `GET /ratification/console`;
- public, fixed, data-free `GET /ratification/console.js`;
- protected `GET /ratification/v1/tasks/{task_id}`;
- protected `GET /ratification/v1/tasks/{task_id}/generations/{generation}`;
- protected `POST /ratification/v1/tasks/{task_id}/review`;
- protected `POST /ratification/v1/tasks/{task_id}/decision`.

The public files do not authenticate, query the authority, accept a task ID at
render time, or disclose task existence, tenant, packet, evidence, artifacts,
history, actor, policy, or credentials. Every protected route authenticates and
authorizes first. Every ratification response, including errors, is private
`no-store`, has a restrictive CSP, `nosniff`, `no-referrer`, and restrictive
Permissions-Policy, and emits no permissive CORS headers.

The generation route has the same authentication, tenant-membership,
`humanRatifier`, ownership/tenant visibility, privacy, and security-header
contract as the latest-view route. `{generation}` is a base-10 nonzero `u64`;
zero is 400 and parser overflow is rejected without an authority lookup. A
missing task, missing generation, foreign tenant, or owner-invisible task is the
same opaque 404. Success returns the immutable historical generation with its
complete authenticated receipt history, private `Cache-Control: no-store`, and
the same strong actor-specific ETag in both the `ETag` header and JSON `etag`
field. Historical reads never reinterpret an old terminal generation using the
current task state and never mutate, supersede, or publish it. The browser always
loads the latest generation and intentionally provides no generation chooser;
the historical route is for authorized audit/API clients.

In bearer mode, open the console at the exact `SMESH_A2A_PUBLIC_URL` origin,
enter task/optional tenant/token, and load. The token is copied from the password
input into an in-memory closure and the input is cleared. It is not placed in
the URL, fragment, cookies, DOM datasets, console, local/session storage, or
IndexedDB. Closing/reloading the tab discards it. In mTLS mode, leave the bearer
field empty and let the browser present the enrolled client certificate.

The authenticated ratification view includes canonical JSON for every private
A2A artifact. That JSON contains the exact part payloads plus artifact/part
names, media types, descriptions, filenames, metadata, and extensions that an
approval publishes. All untrusted strings are rendered with `textContent`.
Actions begin disabled. The operator must explicitly check every evidence hash,
every full-artifact digest, the canonical artifact-manifest digest, and the
uncertainty acknowledgement. Only then can review be recorded. A decision is
enabled only after the **same authenticated account** has recorded that exact
review. `HumanRatifier` receives this task-bound view through ratification
authority only; it is not granted `ArtifactRead` or `ArtifactResolve`.

### Canonical origin and mutation headers

`SMESH_A2A_PUBLIC_URL` must be an HTTP(S) URL of at most 4096 bytes, with a host
and without credentials, query, fragment, or control characters. Its normalized
scheme/host/port tuple is the canonical origin. Every mutation requires exactly
one `Origin` whose bytes equal that canonical origin. Missing, duplicate,
comma-joined, `null`, malformed, or foreign values return 403.

Mutation validation runs after authentication/authorization but before JSON
decoding, in this order:

1. exactly one canonical `Origin` (403 on failure);
2. exactly one byte-exact `Content-Type: application/json` (415 if missing,
   duplicate, parameterized, or different);
3. exactly one issued strong opaque `If-Match` formatted as
   `"ratification-v1:<64-lowercase-hex>"` (428 if missing; 400 if duplicate,
   weak, wildcard, list/comma-containing, malformed, control-bearing, or an old
   packet-hash/revision alias such as revision `00`; 412 if structurally valid
   but not the byte-exact current tag for this authenticated actor and view);
4. exactly one `Idempotency-Key`: 1..=128 visible ASCII bytes (`0x21..0x7e`),
   without comma or spaces (400 if missing, duplicate, malformed, or oversized);
5. bounded JSON decoding (400 for malformed JSON; 422 for a well-formed review
   that omits or changes required evidence/artifact selections or uncertainty).

GET returns a strong opaque, actor-specific ETag and repeats it in the JSON
`etag` field:

```text
"ratification-v1:<64-lowercase-hex>"
```

The digest binds the complete current authority view plus the authenticated
tenant, account, principal, authentication method, and authorization-policy
context. It is not a packet hash/revision encoding and must not be parsed. Use
the exact issued bytes in `If-Match`; another actor's tag does not match.
Successful review and decision mutations return 201 with `revision`, the next
actor-specific `etag`, `action`, and `receiptHash`, and also emit that ETag as a
response header. An
unknown or inaccessible task is 404 after authorization. Missing/malformed
credentials are 401; an authenticated principal without the human-ratifier
permission is 403. Authority/integrity failures are 503. Response bodies
intentionally do not disclose private diagnostics. Typed semantic idempotency
conflict (`-32621`) is HTTP
409. Precondition, lifecycle, and revision conflict (`-32620`) is HTTP 412.
Exact-review and well-formed body failures remain HTTP 422.

The review JSON is closed and contains only:

```json
{
  "evidenceHashes": ["sha256:..."],
  "artifactHashes": ["sha256:..."],
  "artifactManifestDigest": "sha256:...",
  "uncertaintyAcknowledged": true
}
```

The decision JSON is closed and contains only:

```json
{"decision": "approve", "rationale": "Reviewed against the release checklist."}
```

`decision` is exactly `approve`, `reject`, or `amend`. Do not send tenant,
actor, policy, timestamps, packet hash, revision, or idempotency scope in JSON;
the server derives them.

### Stale-tab and retry recovery

A tab retains one in-memory idempotency nonce for the exact tenant, task,
packet generation, action, and serialized semantic command body. Retry and
double-click of those exact bytes reuse it; changing rationale/body, task,
generation, or action creates a new nonce. Server idempotency additionally
binds the authenticated actor/principal. Conflicting reuse fails closed.

On 412, the console enters `STALE`, clears all acknowledgements, disables every
action, refetches the protected view, and requires review of the current packet.
HTTP 409 is a semantic idempotency conflict, is not treated as stale, and enters
`ERROR_LOCKED` for explicit operator recovery.
On 401/403 it enters `AUTH_LOCKED`. Network and 5xx failures enter
`ERROR_LOCKED` and require explicit retry. A terminal view permanently disables
review and decision controls. For scripted clients, implement the same behavior:
refetch on 412; do not blindly rewrite `If-Match` or reuse an idempotency key for
a changed command.

## Durable state and publication semantics

The state machine for one generation is:

```text
AwaitingReview(0) -> Reviewed(1) -> Approved | Rejected | Amended (2)
```

Canceled and superseded are also durable terminal/superseding states; the
browser never enables review or decision controls for either. Approve
publishes the sealed private candidate task/result/transcript and artifacts.
Reject suppresses candidate artifacts and transitions the public task to
Rejected. Amend preserves the receipt history, keeps prior candidate material
private, creates a new task continuation/outbox dispatch, and a later candidate
must freeze a new generation and be reviewed again. Machine/runtime completion
is only a proposal; candidate bytes never become public merely because a worker
reported completion.

Receipts are append-only, chained, and HMAC-sealed. They bind tenant, task,
context/request, actor and principal commitment, authentication method,
authorization and completion policies, key generation, packet/checkpoint,
ordered evidence, artifact manifest, rationale/uncertainty, server time,
idempotency digest, revision, and prior receipt. Browser projections omit the
raw idempotency key and private approved task/result/transcript bytes.

Each decision transaction rechecks tenant scope, packet/generation/revision,
policy binding, key generation, exact same-actor review, and idempotency. It then
commits the receipt, authorization audit, task/event transition, artifact
publication or suppression, and terminal callback creation together. Amendment
also reserves PostgreSQL quota (when the PostgreSQL quota authority is active)
and creates idempotency and outbox work in that transaction. Any audit, quota,
outbox, callback, publication, trigger, or commit failure rolls back the entire
decision. External callback and audit receivers remain at-least-once boundaries
and must deduplicate by their stable event/idempotency identity.

## Migration and rollback

Before upgrade, take a coordinated database backup and preserve the matching
ratification key. Stop all SQLite writers; coordinate PostgreSQL migration under
the migrator role. Startup migrations are forward, sealed, and append-only.
There is no ratification down-migration command and no supported destructive
row-by-row rollback.

If application rollback is required after SQLite schema v11 or PostgreSQL
revision 11 is installed, first verify that the older binary explicitly
supports that schema. Otherwise restore the
pre-upgrade database **and matching key** as one offline unit. Never point an old
binary at an unknown newer catalog, and never restore a database with a
different key. PostgreSQL restore must preserve/recreate the separate roles,
forced RLS, grants, immutable triggers, migration receipts, and fixed schema
search-path assumptions before serving.

## Operational verification

Build and run the checked test/package commands from the repository root:

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo test --test human_ratification -- --nocapture
cargo test --test human_ratification_process -- --nocapture
cargo test --test authorized_gateway_process -- --nocapture
cargo test --test postgres_ratification -- --nocapture
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
npm --prefix demo test
```

`postgres_ratification` requires distinct
`SMESH_TEST_POSTGRES_ADMIN_URL` and `SMESH_TEST_POSTGRES_RUNTIME_URL`. It
self-skips when either is absent unless `SMESH_POSTGRES_TEST_REQUIRED=1`, in
which case absence is a hard failure. The production PostgreSQL process
qualification uses the same two DSNs and requires the documented distinct
migrator/runtime roles and database/schema-creation grants to be provisioned.
A zero-duration/self-skipped run is compilation evidence only,
not production PostgreSQL runtime evidence. The production browser
suite is part of `npm --prefix demo test` and requires Chrome/Chromium plus its
fixture prerequisites.

With a running bearer deployment, keep the token out of command history and
store the private response only in an owner-private temporary directory. Treat
all ratification views, headers, and bearer credentials as sensitive:

```bash
umask 077
TMP_DIR=$(mktemp -d)
chmod 700 "$TMP_DIR"
cleanup() {
  rm -f "$TMP_DIR/curl.conf" "$TMP_DIR/headers" "$TMP_DIR/view.json"
  rmdir "$TMP_DIR"
  unset TOKEN
}
trap cleanup EXIT
read -rsp 'Bearer token: ' TOKEN; printf '\n'
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$TMP_DIR/curl.conf"
chmod 600 "$TMP_DIR/curl.conf"
unset TOKEN
ORIGIN=http://127.0.0.1:4000
TASK_ID='replace-with-task-id'
curl --config "$TMP_DIR/curl.conf" --fail-with-body --silent --show-error \
  "$ORIGIN/ratification/v1/tasks/$TASK_ID" \
  -D "$TMP_DIR/headers" -o "$TMP_DIR/view.json"
chmod 600 "$TMP_DIR/headers" "$TMP_DIR/view.json"
unset TOKEN
grep -i '^etag:' "$TMP_DIR/headers"
# Inspect "$TMP_DIR/view.json" before this shell exits and the trap removes it.
```

For mTLS,
use curl's protected client identity options and omit `Authorization`:

```bash
curl --fail-with-body --silent --show-error \
  --cacert "$STATE_DIR/tls/server-ca.pem" \
  --cert "$STATE_DIR/tls/client.pem" \
  --key "$STATE_DIR/tls/client.key" \
  https://localhost:4000/ratification/v1/tasks/replace-with-task-id
```

Verify additionally:

- the two public bootstrap routes return 200 without credentials and contain no
  real task/tenant/packet data;
- the protected GET returns 401 without credentials and 403 for a mapped
  non-ratifier;
- GET has `ETag`, `Cache-Control: private, no-store`, CSP, `nosniff`,
  `Referrer-Policy: no-referrer`, and restrictive `Permissions-Policy`;
- restart with the unchanged key reaches readiness and preserves packet/history;
- a controlled copy of the authority fails before readiness with a wrong key;
- wildcard/external bind and occupied-loopback bind fail before durable resource
  acquisition.

## Troubleshooting without secret leakage

- **`private file rejected`:** inspect only metadata:
  `stat -Lc '%F %u %a %n' "$KEY_PATH"`; compare the numeric UID with `id -u` and
  verify a regular file, matching owner, absolute path, and no group/world bits.
  Use `wc -c <"$KEY_PATH"` for length. Do not use `cat`, `xxd`, `od`, shell
  tracing, or attach the key to an issue.
- **Wrong-key/integrity failure:** confirm deployment secret version and backup
  pairing through secret-manager metadata, not key bytes. Do not delete the key
  check or reseal rows manually.
- **403 mutation:** compare the browser address-bar origin with the canonical
  `SMESH_A2A_PUBLIC_URL`; verify the mapped human account has `humanRatifier`
  and an unambiguous tenant selection. Do not log bearer tokens or certificate
  private keys.
- **400/409/415/428/412/422:** check header count and exact bytes, retain the
  opaque strong ETag unchanged, and refetch only on 412. Treat 409 as semantic
  idempotency conflict, not stale state. Log status, request ID, task digest, and
  receipt hash only; redact authorization, cookies, DSNs, paths, packet text,
  rationale, and key material.
- **503 or failed restart:** preserve logs and database files, but scan/redact
  credentials, tenant payloads, paths, and DSNs before sharing. Do not bypass
  startup validation or mutate immutable tables to force readiness.

## Qualification and explicit non-goals

Implemented and process-tested on the issue #27 tree:

- production SQLite and PostgreSQL binary routing, key continuity, restart,
  migration/catalog/RLS behavior, atomic decision effects, and lower-level mTLS;
- bearer production Chromium review/approve/reject/amend, with stable approve and
  reject persistence across restart;
- deterministic two-tab stale-write recovery;
- canary scans across browser URL/DOM/storage/console/wire data, process logs,
  SQLite tables, and DB/WAL/SHM bytes.

Browser-tested bearer qualification is green. Lower-level production mTLS
process tests are green, and Chromium correctly fails when no client certificate
is presented. Real Chromium mTLS client-certificate **acceptance remains
skipped**: Puppeteer/CDP has no certificate-chooser API, Chrome 152 ignored the
attempted command-line auto-select switch, and installation of the managed
`AutoSelectCertificateForUrls` exact-origin policy was denied. This limitation
must not be reported as a passing browser mTLS test.

Non-goals and residual limits:

- no online ratification HMAC-key rotation, HSM/KMS integration, managed human
  enrollment/revocation, or cross-deployment policy/key control plane;
- no claim that `RatificationLedger` is a production or multi-replica authority;
- no claim that configured reviewer/evidence labels prove real-world expertise
  or that human approval makes content true;
- no exactly-once guarantee beyond the durable sender boundary: callback and
  audit receivers are at-least-once and must deduplicate;
- no retraction of model/tool/network/storage effects already issued outside the
  owned workflow;
- no release, merge, remote-CI, or M3 milestone completion claim until the exact
  tree is merged and required CI/review gates are read back.
