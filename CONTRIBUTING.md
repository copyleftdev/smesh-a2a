# Contributing to SMESH A2A

SMESH A2A accepts focused, reviewable changes through an issue → branch → local
verification → independent review → pull request → exact-source-head status plus merge-ref CI → squash merge
workflow. The repository is pre-stable and contains security-, privacy-, and
durability-sensitive boundaries, so evidence must be explicit and claims must
stay within what was actually exercised.

## Before starting

1. Search existing issues and pull requests.
2. Open or select one issue with a testable outcome, acceptance criteria, explicit
   non-goals, and known operational or security constraints.
3. Keep one issue-sized concern per pull request. Split unrelated refactors,
   dependency updates, cleanup, and feature work into separate issues and PRs.
4. For security vulnerabilities, do **not** open a public issue. Follow
   [SECURITY.md](SECURITY.md) and open a private GitHub security advisory. Never
   publish live credentials, private task data, restricted trace material, or
   weaponized exploit evidence.

If investigation is required, keep exploratory work disposable. Once the
behavior is understood, start the production change again with the test-first
workflow below.

## Branches and commits

Start from an up-to-date `main` and create a branch named
`<type>/<issue>-<slug>`. The commands below assume `origin` is the repository
you can push to. In a fork, set `upstream` to the canonical repository, update
`main` from `upstream/main`, and push the topic branch to your fork's `origin`.

```bash
git switch main
git pull --ff-only origin main
git switch -c fix/123-bounded-retry
```

Common branch and commit types are `feat`, `fix`, `test`, `docs`, `refactor`,
`perf`, `ci`, and `chore`. Use a lowercase, short, hyphenated slug. Do not work
directly on `main`, rewrite `main`, or combine multiple issues in one branch.

Use Conventional Commits for every commit and for the eventual squash title:

```text
fix(dispatch): bound synchronous retries

docs(contributing): define exact-tree review
```

Use an optional scope when it adds useful context. Keep the subject imperative
and specific. Explain motivation, constraints, and important tradeoffs in the
body; do not use the commit message as a test receipt.

## Behavior changes use strict RED–GREEN–REFACTOR

Features, fixes, refactors, and any other behavior change require test-driven
development. Documentation-only and mechanical configuration changes do not
need a manufactured failing test, but still require the applicable local gates
and review.

For each small vertical behavior slice:

1. **RED:** write one focused test before production code.
2. Run that exact test and confirm it fails for the expected missing behavior,
   not because of a syntax, fixture, or environment error. Save the command and
   concise failure result.
3. **GREEN:** make the smallest production change that passes the test.
4. Run the exact test again and save the passing result.
5. Run the relevant focused suite to detect nearby regressions.
6. **REFACTOR:** improve the code only while the tests remain green.
7. Repeat for the next behavior.

A test that passed on its first run is not RED evidence. Tests written after the
implementation are regression coverage, not TDD evidence; disclose that rather
than relabeling it. Prefer real behavior over mocks, and include failure,
boundary, cancellation, restart, and privacy cases where the issue crosses
those boundaries.

## Local verification

Run commands from the repository root in a fresh checkout or dedicated clean
worktree. Provision Rust 1.88, stable Rust with `rustfmt` and Clippy,
`cargo-audit`, Node.js 22 with npm, and GNU `timeout` first. Rust 1.88 is the
minimum supported version.

First run the smallest relevant test during RED/GREEN development. Before push,
run the repository-wide baseline that mirrors the main CI workflow:

```bash
cargo +1.88.0 check --all-targets --all-features
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets --all-features -- -D warnings
cargo +stable test --all-targets --all-features
cargo +stable test --release --locked --all-targets --all-features -- --test-threads=1
RUSTDOCFLAGS='-D warnings' cargo +stable doc --all-features --no-deps
cargo audit

npm ci --prefix demo
npm audit --audit-level=high --prefix demo
node --check demo/export-film.mjs
node --check demo/record-film.mjs
node --check demo/serve-demo.mjs
npm test --prefix demo
cargo run --quiet --bin lifeline-trace -- /tmp/lifeline.trace.jsonl
cmp /tmp/lifeline.trace.jsonl demo/lifeline.trace.jsonl

git diff --check
git diff --cached --check
```

For one fail-fast, bounded baseline receipt, run the same sequence as one shell
command. The 90-minute outer watchdog is an emergency bound, not permission to
raise an inner product watchdog:

```bash
timeout --signal=TERM --kill-after=30s 90m bash -euxo pipefail -c '
cargo +1.88.0 check --all-targets --all-features
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets --all-features -- -D warnings
cargo +stable test --all-targets --all-features
cargo +stable test --release --locked --all-targets --all-features -- --test-threads=1
RUSTDOCFLAGS="-D warnings" cargo +stable doc --all-features --no-deps
cargo audit
npm ci --prefix demo
npm audit --audit-level=high --prefix demo
node --check demo/export-film.mjs
node --check demo/record-film.mjs
node --check demo/serve-demo.mjs
npm test --prefix demo
cargo run --quiet --bin lifeline-trace -- /tmp/lifeline.trace.jsonl
cmp /tmp/lifeline.trace.jsonl demo/lifeline.trace.jsonl
git diff --check
git diff --cached --check
'
```

Report command, result, and relevant test count; do not report a command as
passing if it was skipped, timed out, or used a different tree. `cargo audit`
currently has repository-documented upstream maintenance/yank warnings in
[SECURITY.md](SECURITY.md). Record the actual output and distinguish an allowed
existing warning from a vulnerability; do not silently suppress or generalize
new findings.

### Fixture-dependent and path-specific gates

CI has additional jobs whose prerequisites are not created by ordinary Cargo or
npm commands. Run every gate relevant to the paths and behavior changed. If the
required fixture is unavailable locally, say **not run**, explain which
prerequisite is missing, keep the PR in draft when it prevents meaningful
validation, and rely on the corresponding CI job before merge. Never describe a
missing fixture as a pass.

- Linux process, browser, operational-acceptance, and hostile-load checks require
  `apparmor`, `apparmor-profiles`, `apparmor-utils`, `bubblewrap`, and `strace`,
  plus a host on which `scripts/ensure-bwrap-ready.sh` succeeds. Install demo
  dependencies with `npm ci --prefix demo`. Use
  `scripts/run-browser-readiness-diagnostic.sh` and
  `scripts/run-operational-acceptance.sh <new-empty-output-directory>` as the
  workflow does. The acceptance destination must not already exist.
- PostgreSQL suites require PostgreSQL 17, a reachable clean `smesh_test`
  database, separately provisioned migrator and runtime roles, and the exact
  `SMESH_TEST_POSTGRES_*_URL` variables expected by `.github/workflows/ci.yml`.
  Set `SMESH_POSTGRES_TEST_REQUIRED=1`; use serial `--test-threads=1` where the
  workflow does. Do not put real URLs or passwords in PR text or logs.
- Observability qualification additionally requires Docker (or an equivalent
  local `promtool`) for the pinned Prometheus rule check and the PostgreSQL
  fixture used by the process tests.
- Fuzz qualification requires nightly Rust and pinned
  `cargo-fuzz 0.13.1`; run the targets, corpora, dictionary, and watchdogs from
  `.github/workflows/fuzz.yml` when fuzz, protocol, policy, token, replay, or
  related source paths change.
- Hostile-load and PostgreSQL chaos commands, watchdogs, evidence validators,
  and service setup are defined in `.github/workflows/chaos.yml`. The scheduled
  PostgreSQL matrix requires its dedicated roles and variables.
- Public-demo changes must satisfy the closed Pages allowlist in
  `scripts/stage-pages.sh`. Restricted evidence must never enter the staged
  Pages tree.

The workflow files are the source of truth when a command or fixture changes.
Do not weaken a test, watchdog, sanitizer, feature set, serial setting, or
failure policy merely to make a local environment pass.

## Freeze and review the exact tree

Local results and independent review must refer to the same complete Git tree
that will be pushed. In a clean dedicated worktree, stage only the intended
change, inspect it, and record its tree object:

```bash
git status --short
git diff --cached --stat
git diff --cached
git diff --cached --check
TREE=$(git write-tree)
printf '%s\n' "$TREE"
```

There must be no unstaged tracked edits or unintended untracked inputs. After
all gates, confirm tracked files did not change and the staged tree is still the
reviewed tree:

```bash
git diff --quiet
test -z "$(git ls-files --others --exclude-standard)"
[ "$(git write-tree)" = "$TREE" ]
```

Give an independent reviewer the issue and acceptance criteria, base revision,
full staged diff, and access to the complete tree identified by `$TREE` (for
example, an archive produced with `git archive "$TREE"`). The reviewer must be
a separate accountable person or a named isolated review-agent context with a
retained full transcript and immutable-tree receipt, not the implementer
re-reading their own work or an advisory PR bot. Review is fail-closed: any unresolved security,
privacy, correctness, race, durability, test-validity, or scope blocker—or an
inability to inspect the exact tree—means the change is not ready.

An agent review supplies independent technical analysis but cannot supply human
accountability. When an isolated agent is used, an accountable maintainer must
personally inspect its full receipt, confirm every blocker is resolved, and sign
off on readiness and merge. Advisory PR bots, automated approvals, silence, and
rate-limit failures satisfy neither independent review nor maintainer sign-off.

Record the reviewer identity/context, exact tree ID, verdict, blockers, and
resolution. Suggestions may be non-blocking; review bots such as CodeRabbit are
advisory only. A bot approval, silence, outage, rate limit, or summary cannot
waive local gates, independent accountable review, required CI, or conversation
resolution. If the tree changes, rerun affected gates and review the new tree.

After committing, verify that the commit points to the reviewed tree before
push:

```bash
[ "$(git rev-parse HEAD^{tree})" = "$TREE" ]
```

## Pull requests

Push the issue branch and open a draft PR using the repository template. The PR
must include:

- the problem and desired outcome;
- issue linkage (`Closes #123` only when the PR fully satisfies that issue;
  otherwise use `Refs #123`);
- scope and explicit non-goals;
- RED and GREEN commands/results for behavior changes;
- focused and full local gate results tied to the exact tree;
- fixture-dependent checks run or explicitly not run;
- security/privacy analysis and evidence handling;
- risks, rollback, and compatibility/migration notes;
- independent review receipt; and
- accountable maintainer sign-off when the independent reviewer is an agent; and
- an exact-source-head status and merge-ref CI checklist.

Keep the PR draft while scope, tests, local gates, or blocking review findings
are incomplete. Respond to review with code or a reasoned explanation, resolve
only conversations that are actually addressed, and request re-review after
material changes. Do not force-push merely to hide review history; if a push
changes the tree, update evidence and review.

## CI and merge lifecycle

1. Verify the PR source-head SHA and ensure every reported check is associated
   with that exact source head, not an earlier push. On `pull_request`, GitHub's
   default checkout executes the synthetic merge ref. Record both the source
   head SHA and the workflow `GITHUB_SHA`/tested merge commit; do not claim the
   source-head tree itself was executed when CI tested the merge ref.
2. The protected `main` branch requires the strict `test` status check and an
   up-to-date branch. Missing, pending, stale, or failed required checks block
   merge. Resolve failures in all triggered CI jobs; path-specific jobs may add
   qualification beyond the required branch-protection context.
3. Resolve all review conversations and confirm the independently reviewed tree
   is the PR head tree.
4. Rebase or update from `main` when required, then rerun affected local gates,
   refresh the tree receipt, and re-review changed content.
5. Auto-merge may be armed only with the squash method after the local and
   review receipts are current; it remains gated by branch protection and the
   exact-source-head-associated merge-ref CI. Whether merged manually or automatically, use **squash only**
   and a Conventional Commit title. Merge commits and rebase merges are not
   allowed.
6. Confirm the squash commit landed on `main`. For same-repository PRs, confirm
   repository settings deleted the source branch. Fork-owned source branches
   remain under the contributor's control and require contributor cleanup.

Do not bypass protection or use an admin merge when a required check is absent,
pending, stale, skipped, or failed. Maintainer authorization does not waive the
required `test` result associated with the current source head and executed on
its current merge ref.

When repository policy changes, preserve a closure receipt containing the API
readback of merge settings and branch protection, the exact-source-head blocked
and successful merge-ref CI states used to exercise enforcement, the squash commit and its
single parent, conversation-resolution state, and same-repository source-branch
deletion. A settings claim without readback or a merge that bypassed a required
check is not successful lifecycle evidence.

## Rollback and cleanup

Plan rollback before merge for changes involving schemas, durable state,
cryptographic keys, authentication, artifacts, callbacks, or public evidence.
Prefer a new, issue-linked revert/fix PR through the same gates over rewriting
history. Preserve forward-only migration and audit invariants; never delete the
only durable copy or claim remote side effects were undone without evidence.
Document irreversible effects and operator steps in the PR.

After a verified squash merge, choose the canonical remote (`origin` for a
same-repository branch, or `upstream` for a fork) and confirm its `main` contains
the expected squash commit and that the commit has the expected delivered tree. A squash does
not make the topic tip an ancestor of `main`, so normal `git branch -d` will
reject the cleanup. Only after those checks, update `main` and force-delete the
now-redundant local topic reference:

```bash
CANONICAL_REMOTE=origin # use upstream for a fork
TOPIC=<type>/<issue>-<slug>
PR_HEAD=<recorded-final-source-head-sha>
DELIVERED=<verified-squash-commit-sha>
git fetch "$CANONICAL_REMOTE" --prune
test "$(git rev-parse "$TOPIC")" = "$PR_HEAD"
test "$(git rev-parse "$TOPIC^{tree}")" = "$(git rev-parse "$DELIVERED^{tree}")"
git switch main
git pull --ff-only "$CANONICAL_REMOTE" main
git merge-base --is-ancestor "$DELIVERED" HEAD
git branch -D "$TOPIC"
```

For an abandoned branch, do not force-delete unmerged work as routine cleanup.
Archive or preserve anything still needed, then delete only with explicit owner
intent.

Stop test services and child processes, remove temporary worktrees and
owner-private fixtures, revoke temporary credentials, and delete local
restricted evidence according to its retention policy. Do not delete evidence
needed for audit, recovery, legal hold, or issue closure. Confirm the public tree
contains no secrets, private task data, restricted manifests/traces, local
databases, browser profiles, or generated build artifacts.
