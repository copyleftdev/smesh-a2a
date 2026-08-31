# Secure push notification operations

> **Production status:** callbacks remain disabled and advertise `pushNotifications: false` unless
> an enabled, validated operator policy is installed with the PostgreSQL authority. Enabled startup
> now requires successful policy reconciliation and the joinable worker's initial authority cycle;
> readiness is never set manually.

## Trust boundary

Clients cannot choose arbitrary egress origins. An eventual enabled handler must accept a task
configuration only when its canonical URL exactly matches one `(tenant, endpoint_id)` enrollment
from the operator policy. Caller `token` and `authentication.credentials` must be rejected and
must never be persisted, echoed, logged, or forwarded. Only operator-managed HMAC/mTLS material
may authenticate callbacks.

The vendored `InMemoryPushConfigStore` and `HttpPushSender` are prohibited on the production path.
They do not enforce this boundary.

## Policy installation

1. Copy `config/push.example.toml` outside the repository.
2. Keep `enabled = false` while editing. Unknown or duplicate TOML fields fail parsing.
3. Use canonical URLs of the form `https://lowercase-ascii-host:explicit-port/absolute/path`.
   Userinfo, IP literals, query, fragment, wildcard/trailing-dot hosts, controls, backslashes,
   percent encodings, dot segments, and implicit ports are rejected.
4. Generate at least 32 random secret bytes out of band. Install policy and secret as regular,
   owner-owned `0600` files. Symlinks and group/other permissions are rejected.
5. Update the immutable policy ID/revision/digest through deployment review. Every replica must
   use the same snapshot before callback readiness can become true.
6. Set `SMESH_A2A_PUSH_CONFIG_PATH` only when the durable PostgreSQL authority and worker are
   deployed. Missing/disabled policy preserves the unsupported behavior with zero worker/network
   activity. Explicit invalid enablement must abort startup, never fall back to disabled.

Policy validation performs no DNS or callback network traffic.

## Per-attempt controls

Every attempt must use a fresh resolver call. All answers are validated; one private or special-use
address denies the entire attempt. The validated socket is pinned into a fresh reqwest client while
the original hostname remains the HTTPS authority/SNI. Ambient proxies, redirects, pooling,
cookies, and HTTP/2 coalescing are disabled. Signed headers are attached only after pinning.
Responses are classified by a closed allowlist: 2xx succeeds; only network failures and
408/425/429/500/502/503/504 retry; every redirect and other response is permanent. Retries retain
the exact event ID and payload bytes and are bounded by attempts and age. `Retry-After` is honored
only for 429/503, accepts one valid delta-seconds or HTTP-date value, and is clamped to policy bounds;
duplicates, malformed/past/negative/overflowing values fall back to jitter.

The loopback DNS map and synthetic-public connector used by transport evidence are debug-only,
explicitly enabled seams. Production builds contain neither loopback authorization nor connector
remapping; they always connect to the exact validated public snapshot.

## Receiver verification

Receivers should bound headers/body, verify `Content-Digest`, reconstruct the length-prefixed
HMAC-SHA256 input, compare in constant time, and durably deduplicate `Idempotency-Key` before side
effects. Delivery is at-least-once: a crash after remote acceptance but before local commit causes
an identical retry.

## Incident handling

* Endpoint outage is a delivery retry condition, not gateway unready.
* Fatal callback authority/worker state must atomically set readiness false and dynamically make
  the Agent Card advertise false.
* Revoke an enrollment/configuration through the authority; never edit lease rows manually.
* Rotate to a new operator key generation and retain old verify-only material for the complete
  retry/replay window.
* Investigate with closed reason categories and durable audit records. Never print URLs, DNS
  answers, raw network errors, signatures, secrets, payloads, or IDs.
* During shutdown, stop callback admission, perform a bounded drain, cancel and join the worker,
  and leave pending rows durable for another replica.

## Verification

Run:

```bash
cargo test --locked --test agent_card
cargo test --locked --test push_security
cargo test --locked --release --test push_security
cargo test --locked --test callback_authority -- --test-threads=1
cargo test --locked --test postgres_push_process -- --test-threads=1
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
git diff --check
```

The dedicated `push-postgres` CI job provisions explicit PostgreSQL 17 superuser, migrator, and
runtime URLs and runs the authority plus two-gateway process targets under 5/10-minute command
watchdogs. Policy upgrades that remove or replace enrollments refuse startup while a database-time
lease is live; after exact expiry they atomically cancel retained work and revoke affected configs.
