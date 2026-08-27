# Direct TLS, mTLS, and Rotation Runbook

## Boundary

The gateway has three explicit transport modes:

- `loopback-plain`: development HTTP; the bind must be loopback. Authentication may be explicitly disabled.
- `reverse-proxy-loopback`: HTTP from a same-host loopback proxy; the bind must be loopback and OIDC is mandatory. Proxy headers never establish a principal.
- `direct-tls`: rustls terminates TLS. A non-loopback bind also requires an HTTPS public URL and OIDC and/or **required** mTLS.

`SMESH_A2A_UNSAFE_PUBLIC` is ignored. Direct TLS uses ALPN `h2,http/1.1`, disables TLS early data and key logging, and bounds handshake duration and concurrent connections.

## Configuration

```bash
export SMESH_A2A_TRANSPORT_MODE=direct-tls
export SMESH_A2A_AUTH_MODE=disabled              # mTLS-only; use oidc for bearer or dual auth
export SMESH_A2A_BIND=0.0.0.0:443
export SMESH_A2A_PUBLIC_URL=https://gateway.example
export SMESH_A2A_TLS_CERT_PATH=/etc/smesh/tls/server-chain.pem
export SMESH_A2A_TLS_KEY_PATH=/etc/smesh/tls/server.key
export SMESH_A2A_CLIENT_AUTH_MODE=required       # disabled|optional|required
export SMESH_A2A_TLS_CLIENT_CA_PATH=/etc/smesh/tls/client-roots.pem
export SMESH_A2A_TLS_PRINCIPAL_MAP_PATH=/etc/smesh/tls/principals.json
export SMESH_A2A_TLS_HANDSHAKE_TIMEOUT_SECONDS=10
export SMESH_A2A_MAX_CONNECTIONS=1024
```

For optional mTLS, OIDC must also be enabled: no certificate plus a valid bearer is accepted. A verified but unmapped certificate is rejected without bearer fallback. When both credentials are present, mapped mTLS issuer/subject and bearer issuer/subject must match exactly. Required mTLS rejects missing certificates during the TLS handshake.

## Principal map

The map is a bounded JSON object. Keys are exactly `sha256:` followed by 64 lowercase hexadecimal characters and are computed over the verified leaf certificate DER. Entries and fingerprints must be unique.

```json
{
  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
    "issuer": "mtls:partner-ca-2026",
    "subject": "agent-17"
  }
}
```

Compute a key:

```bash
openssl x509 -in client.pem -outform DER |
  sha256sum | awk '{printf "sha256:%s\n", $1}'
```

CN, DN, SAN, `Forwarded`, `X-Client-Cert`, `X-Forwarded-Client-Cert`, A2A metadata, and caller principal fields are never identity inputs.

## File policy

- The server certificate file must contain a nonempty chain.
- The key file must contain exactly one supported private key; rustls verifies that it matches the leaf certificate.
- The key path must itself be a regular file (not a symlink), owned by the gateway uid, and have no group/world permission bits (normally `0600`).
- Client roots must be nonempty when mTLS is enabled. The principal map must be nonempty and valid.

Kubernetes projected Secret volumes use symlink indirection and therefore do **not** satisfy the key-path policy directly. Copy the selected key into an owner-only `emptyDir` or other private volume in an init/sidecar step, set ownership and mode `0600`, atomically replace the regular destination file, then signal the gateway. Do not point the gateway at `..data` or a projected symlink.

## Atomic rotation

1. Stage a complete new certificate chain, matching key, client roots, and principal map under owner-only paths.
2. Validate file ownership/modes and calculate every client leaf DER fingerprint.
3. Atomically rename each staged regular file onto the configured path. Keep old client roots during an overlap window when rotating a client CA.
4. Send `SIGHUP` to the gateway process.
5. Confirm `TLS snapshot reloaded generation=N` in logs.
6. Establish a **new** connection and verify server trust/hostname, expected client-certificate behavior, mapped principal, and Agent Card schemes.
7. Existing TLS connections intentionally retain their old coherent generation. Drain them according to deployment policy.
8. Remove superseded roots/map entries in a later complete rotation and repeat.

A malformed, mismatched, missing, insecure, or empty component rejects the entire reload and logs `TLS snapshot reload rejected; retaining prior generation`. No partial generation is published. Fix the staged files and retry SIGHUP; do not restart into known-invalid material.

## Shutdown

SIGINT and SIGTERM initiate bounded HTTP graceful shutdown. If the deadline expires, the owned server task is aborted and joined before durable ticker/outbox/store or runtime/mesh shutdown continues.

## Non-goals

This boundary does not implement ACME enrollment, OCSP stapling/checking, CRL distribution, HSM/PKCS#11 key custody, TLS session revocation, or client identity asserted by a reverse proxy. Reverse-proxy mode authenticates only with OIDC and deliberately ignores proxy-provided certificate identity.
