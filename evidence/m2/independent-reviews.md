# Independent Review Traceability

These are local, read-only Hermes specialist reviews of named immutable Git objects. They are not GitHub
formal reviews, approvals, or PR comments. Automatic CodeRabbit review was disabled; it was not a
required status check. Each verdict was reconciled by the integrating agent, which reran the applicable
focused/full gates and verified remote CI before merge.

## Reviewed delivery tracks

| Track | Immutable reviewed object | Binary diff SHA-256 | Verdict and scope | Merge |
|---|---|---|---|---|
| #72 denial-audit bounds | base `cc395799c2615fafb29e81825eb85d6fdec8bac6`, head `33287df1772adb22ed93ba3f3890df441ceb3460` | `06aeb1581de7f23baea4aecf23f517c0ee9d9e50ea9e7b5984de2136dc202cb7` | PASS: SQLite O(1) count/UTF-8 bytes/caps; PostgreSQL migrator-only bounded retention, forced-RLS populated migration, projection safety, privileges/catalog, docs/CI | PR #76, `20af6c580c16307a5c9c5e3c47ebe7064c02eeab` |
| #73 runtime trace/correlation | base `20af6c580c16307a5c9c5e3c47ebe7064c02eeab`, head `87f6c4192d7846e26a49c937af9d424d9d1c3b7f` | `25fb14b6ecdcc7fa1cd5f2b6eee8e73f83680f55ad837aed52f4d82312c5e929` | PASS: bounded retention, opaque task+context workload isolation, atomic completed windows, reused-hash/delayed-event safety, tenant/attempt telemetry, artifact causal shapes | PR #77, `a24aea21607b7881fc0e2d943639751eab6fba2f` |
| #74 protocol fuzzing | base `a24aea21607b7881fc0e2d943639751eab6fba2f`, final head `7b52d003d59cb87e9bd62207f4dd782e86e22e7f` | `49f60801f0488070d1169ae1d731084079293685435613ba2fe17e951ca4a5bd` | PASS review chain: protocol/JSON-RPC null-aware ambiguity, policy/state/token scope, four bounded fuzz targets/corpora; final stable-toolchain cargo-fuzz installation delta separately approved | PR #78, `bfe4b1ce2e23cfeb67aa3da6feec350549f18efd` |
| #75 load and chaos | base `bfe4b1ce2e23cfeb67aa3da6feec350549f18efd`, head `ba70c3f4d8846a1e646b037ad95be5d75acf53e5` | `82e277ae2b779737a80fe05b51bb75cc94624755d184ba68980789ba505e61a9` | PASS: continuous load metrics, slow consumer/fault proxy, SIGKILL RPO/RTO, enforced cleanup, machine schemas/validators, PostgreSQL matrix/CI; credential-display redaction independently resolved against actual bytes | PR #79, `a14ee632925b6bde140e4173cc75daff55b5557e` |

## Review semantics

- A hash identifies only the exact binary diff stated in the row. Later edits invalidate that verdict
  unless a narrow review explicitly covers the delta and the final hash.
- Reviewer self-reports are supporting evidence, not execution truth. The integrating session reran
  commands and read external state back before claiming completion.
- Remote merge state and checks are verified from GitHub. Local review verdicts must not be presented as
  GitHub review events.
- Security findings are closed through a new exact candidate; obsolete hashes are retained only as
  remediation history and are not approvals of a later tree.

## Aggregate closeout

Issue #18's threat-model closeout receives its own exact-diff review after the STRIDE/data-flow model,
residual-risk register, review table, and present-tense documentation are reconciled. Because a file
cannot contain its own final Git hash without changing that hash, the closeout verdict and immutable
reviewed hash are recorded in the PR body and issue closeout comment.
