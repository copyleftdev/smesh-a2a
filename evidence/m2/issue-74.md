# Issue #74 Evidence - Protocol, Policy, State, and Token Fuzzing

Parent qualification gate: #18

## Closed defects

- REST list parsing no longer converts an invalid status into `None` and widens the query.
- Every vendored A2A field-presence union (`Part`, send response, stream response, security scheme,
  and OAuth flow) accepts exactly one variant and rejects ambiguous, duplicate, or unknown members.
- JSON-RPC requests reject unknown/duplicate envelope members, and responses require exactly one of
  `result` or `error`.
- SQLite and PostgreSQL opaque task tokens share one bounded parser.
- SQLite and PostgreSQL callback tokens share one bounded, MAC-verified, tenant/task-scoped parser.
- SQLite and PostgreSQL durable state transitions use one closed transition matrix.
- The in-memory task store uses the same matrix; invalid regressions cannot bypass durable semantics.
- Empty task page tokens are invalid in memory, SQLite, and PostgreSQL instead of silently opening a
  fresh first page.
- Completion-policy identifiers and evidence text reject whitespace-only and control-bearing values.

## Deterministic stable gate

```bash
cargo test --locked --test protocol_fuzz_regressions -- --test-threads=1
cargo test --locked --test server rest_list_rejects_invalid_status_instead_of_widening_query -- --exact
```

The fixed-seed proptest uses `0x5A17_0074`, 256 cases, input lengths below 8 KiB, and at most 2,048
shrink iterations. It executes only pure bounded parsers:

- A2A send/list/response/stream/task JSON;
- authorization, quota, push, and principal-map policies;
- runtime-trace replay;
- opaque task tokens and signed callback tokens.

The minimized token corpus covers invalid base64, lengths 31/33, maximum overrun, MAC mutation,
additional separators, invalid UTF-8, invalid timestamp, empty ID, cross-tenant scope, and cross-task
scope. Error rendering is checked against secret and tenant canaries.

The exhaustive state matrix covers all nine `TaskState` variants and proves terminal states are
absorbing except for idempotent self-transition. Memory, SQLite, and PostgreSQL call that one
predicate; the new adapter regression drives the in-memory path, while the existing durable lifecycle
suites continue to exercise SQLite and PostgreSQL transitions.

## Nightly fuzz targets

```bash
cargo +nightly fuzz build protocol_json
cargo +nightly fuzz build policy_json
cargo +nightly fuzz build page_tokens
cargo +nightly fuzz build state_replay

for target in protocol_json policy_json page_tokens state_replay; do
  cargo +nightly fuzz run "$target" "fuzz/corpus/$target" -- \
    -runs=1000 -max_len=65536 -timeout=5 \
    -dict=fuzz/dictionaries/protocol.dict
done
```

Observed locally: all four targets built against the vendored A2A crates and completed 1,000 runs
without crash, hang, panic, or sanitizer finding. Input loops contain no network, filesystem, process,
or durable-authority calls.

`.github/workflows/fuzz.yml` installs the qualified cargo-fuzz 0.13.1 release, builds all targets
outside the execution watchdogs, then runs them on
relevant pull requests/pushes, daily, and on manual dispatch, with 60-second
libFuzzer budgets, 90-second outer watchdogs, a 15-minute job cap, bounded input lengths, and 14-day
crash-artifact retention.

## Corpus promotion

Crashes are minimized with `cargo fuzz tmin`, committed under `fuzz/corpus/<target>/`, and promoted to
a named stable regression whenever they represent an authority, scope, ambiguity, state, token, or
redaction invariant. Raw secrets, databases, and non-minimized artifacts are prohibited.

## Residual scope

The byte targets cover parser and replay surfaces without side effects. Stateful hostile load, network
faults, process crashes, slow consumers, and measured RTO/RPO remain in issue #75.