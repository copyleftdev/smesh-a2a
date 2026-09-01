# Fuzz qualification

Issue #74 adds two layers: deterministic stable-toolchain regression properties and bounded nightly
`cargo-fuzz` exploration. Fuzzing is parser-only: targets do not open sockets, files, databases, or
spawn processes.

## Stable deterministic gate

```bash
cargo test --locked --test protocol_fuzz_regressions -- --test-threads=1
cargo test --locked --test server rest_list_rejects_invalid_status_instead_of_widening_query -- --exact
```

The property suite uses fixed seed `0x5A17_0074`, 256 cases, inputs bounded to 8 KiB, and bounded
shrinking. It covers strict JSON-RPC envelopes and exactly-one protocol unions (including
ambiguous, duplicate, and unknown fields),
request/task/state decoding, strict authorization/quota/push and
principal-map policies, runtime-trace replay, task state transitions, opaque task tokens, signed callback
tokens, cross-scope mutations, invalid UTF-8/base64, excess fields, and canary redaction.

## Nightly byte fuzzing

Install a nightly toolchain and cargo-fuzz:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked --version 0.13.1
```

Run one target for five minutes:

```bash
cargo +nightly fuzz run protocol_json fuzz/corpus/protocol_json -- \
  -max_total_time=300 -max_len=65536 -timeout=5 \
  -dict=fuzz/dictionaries/protocol.dict
```

Targets:

- `protocol_json`: A2A request, response-union, task, stream, and generic JSON decoding.
- `policy_json`: strict authorization, quota, push, and principal-map policy parsing.
- `page_tokens`: opaque task token and tenant/task-bound callback token parsing.
- `state_replay`: runtime-trace, task-status, and stream-response replay.

The scheduled workflow runs every target for 60 seconds with a 90-second outer watchdog and uploads
crash artifacts for 14 days. The per-input length and parser-internal limits prevent unbounded
allocation. OTLP, network, filesystem, and authority APIs are absent from the fuzz binaries.

## Corpus promotion

1. Reproduce the artifact with the exact target and `-runs=1`.
2. Minimize it:

   ```bash
   cargo +nightly fuzz tmin <target> <artifact>
   ```

3. Add the minimized input under `fuzz/corpus/<target>/`.
4. Add a deterministic named regression under `tests/protocol_fuzz_regressions.rs` when the input
   represents a security invariant or production defect.
5. Verify stable tests, `cargo +nightly fuzz run <target> -- -runs=1000`, formatting, Clippy, and the
   full suite before committing.

Never commit secrets, raw credentials, database files, or non-minimized crash dumps.