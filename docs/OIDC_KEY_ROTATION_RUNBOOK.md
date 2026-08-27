# OIDC bearer and key-rotation runbook

## Security boundary

OIDC can run behind a loopback reverse proxy or at the gateway's direct rustls boundary. A
non-loopback bind requires `direct-tls`, an HTTPS public URL covered by the serving certificate,
and OIDC and/or required mTLS. Direct TLS supports disabled, optional, and required client
certificate verification; verified leaf fingerprints are exact-mapped to principals. The legacy
`SMESH_A2A_UNSAFE_PUBLIC` setting is ignored and cannot weaken these rules. See
[`TLS_MTLS_ROTATION_RUNBOOK.md`](TLS_MTLS_ROTATION_RUNBOOK.md) for certificate/trust rotation.

## Configuration

OIDC is the production default, including when `SMESH_A2A_AUTH_MODE` is absent. Set these before
startup (the explicit `oidc` value is shown for clarity):

```text
SMESH_A2A_AUTH_MODE=oidc
SMESH_A2A_OIDC_ISSUER=https://idp.example/issuer
SMESH_A2A_OIDC_AUDIENCE=smesh-api
SMESH_A2A_OIDC_JWKS_URI=https://idp.example/issuer/jwks.json
```

Issuer and JWKS URLs must be bounded HTTPS URLs without credentials or fragments. JWKS is
same-origin with the issuer by default. A reviewed deployment may explicitly set
`SMESH_A2A_OIDC_ALLOW_CROSS_ORIGIN_JWKS=1`. Optional bounds are
`SMESH_A2A_OIDC_MAX_JWKS_BYTES` (1..=1048576, default 262144) and
`SMESH_A2A_OIDC_CLOCK_SKEW_SECONDS` (0..=300, default 30). Configuration and the initial JWKS are
validated eagerly before listeners, SQLite, or runtime resources are opened.

Tokens must be RFC 9068 RS256 access tokens with `typ` `at+jwt` or `application/at+jwt`, a `kid`,
and bounded nonempty `iss`, `sub`, `aud`, `exp`, `iat`, `client_id`, and `jti`. RSA keys must be at
least 2048 bits and use exponent 65537.

## Rotation

1. Publish the new signing key alongside the old key under a new unique `kid`.
2. Confirm the JWKS endpoint returns `200`, a bounded body, and appropriate `Cache-Control`, `Age`,
   or `Expires` headers. `no-cache`, `no-store`, and zero freshness force immediate re-fetch.
3. Begin issuing tokens with the new `kid`. An unknown `kid` triggers singleflight bounded
   revalidation. The global unknown-key refresh interval is reserved before the provider call, so
   both successful misses and provider outages throttle the rest of a request storm.
4. Keep the old key published until every old token has expired plus configured skew.
5. Remove the old key. Requests using it fail after cache freshness expires.

The client intentionally performs bounded unconditional revalidation rather than conditional
ETag/Last-Modified requests. Redirects, proxies, decompression, oversized declared or streamed
bodies, malformed sets, duplicate key IDs, weak RSA keys, and provider outages after expiry fail
closed. A fresh cached known key remains usable during a transient outage.

## Incident response

- Compromised key: remove it from JWKS, return `Cache-Control: no-store`, rotate immediately, and
  account for already issued token lifetime.
- Provider outage: restore the HTTPS JWKS endpoint; stale keys are not accepted.
- Authentication failures: missing credentials receive a bare Bearer challenge; malformed or
  invalid credentials receive `error="invalid_token"`. Tokens and principal identifiers are never
  emitted in authentication errors or debug output. A presented, verified, but unmapped client
  certificate is an mTLS identity failure and receives no Bearer challenge, even when OIDC is also
  enabled.