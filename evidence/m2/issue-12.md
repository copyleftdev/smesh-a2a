# Issue #12 authentication and TLS principal evidence

## Scope

This change adds a server-derived identity boundary for the A2A gateway:

- RFC 9068 OIDC bearer access-token verification;
- bounded HTTPS JWKS retrieval, rotation, caching, and outage behavior;
- immutable Principal propagation across every RequestHandler operation, spawned execution, and deferred stream poll;
- direct rustls termination with HTTP/1.1 and HTTP/2;
- optional and required WebPKI client-certificate authentication;
- exact verified-leaf SHA-256 fingerprint-to-Principal mapping;
- atomic certificate, key, client-root, and principal-map reload;
- fail-closed public exposure and startup ordering.

## Identity invariants

- Caller metadata and forwarding/client-certificate headers never establish identity.
- Raw credentials and the authenticated principal bridge are not written to task metadata, SQLite, transcripts, runtime traces, logs, or errors.
- Bearer tokens require an explicit asymmetric algorithm, exact issuer/audience, bounded mandatory profile claims, bounded lifetime, and a trusted JWKS key.
- mTLS identity derives only from a WebPKI-verified leaf certificate whose DER fingerprint is enrolled in the bounded principal map.
- A verified but unmapped client certificate fails closed without bearer fallback.
- When bearer and mTLS credentials are both present, issuer and subject must match exactly.
- Queued pre-handshake sockets cannot pin an old security generation.
- SIGHUP publishes a replacement snapshot only when every component validates and the serving certificate still covers the configured public URL.

## Checked evidence

- 37 library tests, including JWT/JWKS, mTLS policy, spawned executor identity, deferred stream identity, and connection-generation races.
- 2 authentication redaction/effect tests.
- 2 all-operation principal propagation tests covering JSON-RPC and REST.
- 5 production startup/default/resource-order tests.
- 9 TLS configuration tests.
- 11 TLS integration tests using real sockets and the production gateway.

The real-socket matrix covers:

- HTTPS JSON-RPC and REST over HTTP/1.1 and HTTP/2;
- unknown server CA, hostname mismatch, plaintext, and stalled handshakes;
- optional and required mTLS with missing, mapped, unmapped, and untrusted certificates;
- matching and conflicting bearer+mTLS identities;
- spoofed identity headers;
- max-connection saturation, bounded recovery, and post-reload generation selection;
- successful and failed/torn SIGHUP reloads with old keepalive retention;
- durable/runtime SIGINT and SIGTERM cleanup;
- failure before listener, SQLite, runtime trace, or mesh acquisition;
- certificate, key, token, Principal, and bridge canary redaction.

The official `a2a-client-lf 0.2.2` helper does not expose client-identity configuration. HTTPS and mTLS wire evidence therefore uses reqwest/rustls and is not described as official SDK mTLS interoperability.

## Exact-tree gates

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps
cargo +1.88.0 check --all-targets --all-features
cargo audit
git diff --check
```

All gates pass at the PR head. CI directly enforces formatting, Clippy, the all-target/all-feature test command, warning-denied Rustdoc, MSRV, audit, and diff hygiene. `cargo audit` reports no vulnerability failure. It retains the accepted transitive warnings for unmaintained `bincode 1.3.3` and yanked `chacha20 0.10.1` through pinned upstream SMESH/QUIC dependencies.

## Operations

- OIDC/key rotation: `docs/OIDC_KEY_ROTATION_RUNBOOK.md`
- TLS/mTLS rotation: `docs/TLS_MTLS_ROTATION_RUNBOOK.md`
- CI now checks the declared Rust 1.88 MSRV and runs cargo audit.

## Non-goals

This issue does not implement tenant authorization (#13), ACME enrollment, OCSP/CRL distribution, HSM/PKCS#11 key custody, immediate revocation of established connections, or reverse-proxy certificate identity.