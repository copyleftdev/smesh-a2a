# TLS test fixtures

Every certificate and private key in this directory is public, test-only fixture material. Never use these keys or certificates with a real endpoint, identity provider, client, or trust store.

The fixture hierarchy was generated with OpenSSL for issue #12 integration tests. The paired certificates expire on 24 August 2036. Representative generation pattern:

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -subj '/CN=issue12-test-ca' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout ca.key -out ca.pem

openssl req -newkey rsa:2048 -nodes -subj '/CN=fixture-only' \
  -keyout leaf.key -out leaf.csr
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 -extfile leaf.ext -out leaf.pem
```

Server fixture extension files include the localhost DNS and `127.0.0.1` IP SANs used by the real-socket tests. Client identity is determined only by the verified leaf DER SHA-256 fingerprint in `principals.json`; certificate subject names are intentionally not identity inputs.

Git does not preserve owner-only non-executable modes. Tests copy private-key fixtures into isolated temporary paths and set mode `0600` before production key validation.