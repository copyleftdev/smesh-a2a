## Problem and outcome

<!-- What is wrong or missing? What observable outcome should this PR produce? -->

## Issue linkage

<!-- Use `Closes #N` only if this PR fully satisfies the issue; otherwise use `Refs #N`. -->

Closes #

## Scope

- <!-- In-scope item -->

### Non-goals

- <!-- Explicit exclusion -->

## Approach

<!-- Describe the smallest issue-sized change, key invariants, and important tradeoffs. -->

## TDD evidence

<!-- Required for features, fixes, refactors, and other behavior changes. Add one row per vertical RED→GREEN slice. A first-run pass is not RED evidence. For docs-only/mechanical changes, state why TDD is not applicable. -->

| Behavior | RED command and expected failure | GREEN command and result | Focused regression result |
| --- | --- | --- | --- |
|  |  |  |  |

## Exact-tree local verification

<!-- Stage only the intended change in a clean worktree. Record `git write-tree`; after gates, confirm `git diff --quiet`, no output from `git ls-files --others --exclude-standard`, and `[ "$(git write-tree)" = "$TREE" ]`. After commit, confirm `git rev-parse HEAD^{tree}` matches. Never mark a skipped/timed-out command as passing. -->

- Base revision: `<!-- SHA -->`
- Reviewed/tested tree: `<!-- git write-tree -->`
- PR head commit: `<!-- SHA -->`
- PR head tree matches reviewed/tested tree: <!-- yes/no -->

### Repository-wide gates

- [ ] `cargo +1.88.0 check --all-targets --all-features`
- [ ] `cargo +stable fmt --all -- --check`
- [ ] `cargo +stable clippy --all-targets --all-features -- -D warnings`
- [ ] Focused Rust test(s): `<!-- exact command(s), counts/results -->`
- [ ] `cargo +stable test --all-targets --all-features`
- [ ] `cargo +stable test --release --locked --all-targets --all-features -- --test-threads=1`
- [ ] `RUSTDOCFLAGS='-D warnings' cargo +stable doc --all-features --no-deps`
- [ ] `cargo audit` (record actual findings, including documented existing warnings)
- [ ] `npm ci --prefix demo`
- [ ] `npm audit --audit-level=high --prefix demo`
- [ ] `node --check demo/export-film.mjs`
- [ ] `node --check demo/record-film.mjs`
- [ ] `node --check demo/serve-demo.mjs`
- [ ] `npm test --prefix demo`
- [ ] Deterministic trace generation and `cmp`
- [ ] `git diff --check` and `git diff --cached --check`

### Fixture-dependent/path-specific gates

<!-- List each relevant PostgreSQL, process/browser, operational-acceptance, observability/promtool, fuzz, chaos, or Pages-allowlist gate. Name required fixtures (PostgreSQL 17 roles/env, Linux process tools/bwrap readiness, Node 22/browser, Docker/promtool, nightly+cargo-fuzz) without exposing secrets. If unavailable, mark NOT RUN with the missing prerequisite and keep the PR draft when it blocks meaningful validation. -->

| Gate/command | Fixture/prerequisite | Result, count, or explicit NOT RUN reason |
| --- | --- | --- |
|  |  |  |

## Security and privacy

- [ ] No credentials, tokens, private task data, exploit payloads, restricted traces/manifests, local databases, or browser profiles are included in the diff, PR, logs, or public artifacts.
- [ ] Added/changed input, authorization, tenant, path, network, storage, concurrency, cancellation, and resource-boundary behavior has been reviewed as applicable.
- [ ] Public evidence is sanitized before persistence/publication; restricted evidence remains owner-private and follows `SECURITY.md` and its retention policy.
- [ ] Dependency/audit findings are stated exactly; new findings are not hidden behind existing accepted warnings.

Security/privacy notes and evidence locations:

<!-- Do not paste secrets or restricted evidence. Use a private security advisory for vulnerabilities. -->

## Risk, compatibility, and rollback

- Risk level and failure modes:
- Compatibility/schema/migration impact:
- Rollback or forward-fix procedure:
- Irreversible or external effects:
- Post-merge monitoring/verification:
- Cleanup (services, fixtures, credentials, temporary worktrees/evidence):

## Independent exact-tree review

<!-- Reviewer must be a separate accountable person or a named isolated review-agent context with a retained full transcript and immutable-tree receipt. Advisory PR bots cannot satisfy this requirement or waive local gates, CI, or conversation resolution. Any tree change invalidates this receipt until affected gates/review are refreshed. -->

- Reviewer identity/context:
- Tree reviewed: `<!-- tree SHA -->`
- Review input included issue/acceptance criteria, base, full diff, and complete tree: <!-- yes/no -->
- Verdict: <!-- PASS / BLOCKED -->
- Blocking findings and resolution:
- Non-blocking suggestions:

### Accountable maintainer sign-off

<!-- Mandatory when the independent review above came from an agent context. An agent or advisory bot cannot complete this sign-off. -->

- Maintainer:
- Full review receipt inspected: <!-- yes/no -->
- Every blocker resolved on the tree above: <!-- yes/no -->
- Ready for exact-source-head-associated merge-ref CI and squash merge: <!-- yes/no -->

## PR CI and merge

- [ ] PR source-head SHA above is current; every result below is associated with that exact source head.
- [ ] The workflow `GITHUB_SHA`/tested merge-ref commit is recorded separately; no claim says CI executed the source-head tree when it tested the merge ref.
- [ ] Required strict `test` check is present and successful on the current merge ref (not absent, pending, stale, skipped, or failed).
- [ ] All other triggered CI jobs are successful; documentation does not substitute for a missing, skipped, or failed result.
- [ ] Branch is current with protected `main`.
- [ ] All review conversations are resolved because their findings were addressed.
- [ ] PR head tree matches the locally tested and independently reviewed tree.
- [ ] Squash title is a Conventional Commit.
- [ ] If auto-merge is armed, it uses squash and remains gated by the current merge-ref CI and branch protection.
- [ ] Squash-only merge will be used; no merge commit or rebase merge.
- [ ] After merge, verify the squash commit on canonical `main`; for a same-repository PR, verify automatic remote source-branch deletion. Fork branch cleanup remains the contributor's responsibility.
