# Operational LIFELINE acceptance

Issue #29 is qualified with one bounded command:

```bash
scripts/run-operational-acceptance.sh /tmp/operational-acceptance
```

The destination must not exist. The harness sets `umask 077`, owns one temporary root, performs one Cargo `--locked` build, and runs two sequential seed-47 scenario/capture generations. It compares the exact 18-file generated allowlist between both runs and the checked fixture before running all 14 qualification-plane probes. Raw scenario journals and generated restricted trees exist only inside the task-owned temporary root until semantic evaluation completes; the exit trap removes them. The requested output contains exactly:

- `acceptance-scorecard.json`
- `acceptance-receipt.json`

Verify a local or downloaded report without network access:

```bash
target/debug/operational-lifeline-acceptance verify-report /tmp/operational-acceptance
```

The verifier rejects symlinks, extras, missing files, noncanonical JSON, unsupported schemas, files over 128 KiB, aggregate reports over 256 KiB, and inconsistent status, byte-length, criteria, input-set, or scorecard-digest bindings.

## Receipt scope

The SHA-256 values are domain-separated **integrity and reproducibility commitments**. They are not signatures, an external trust root, a human decision, or action authority. The scorecard binds repository-owned criteria, retained package evidence, and bounded probes executed by this harness. The fixture ratification evidence remains explicitly scripted and unauthenticated; no probe grants medical, shipping, messaging, callback, model, tool, URL, or other live-effect authority.

CI job `operational-acceptance` runs with Rust 1.88 and Node 22 under a 20-minute job bound. It uploads only the two report files as `operational-acceptance-RUN_ID-RUN_ATTEMPT` for 14 days. Download and verify with:

```bash
gh run download RUN_ID --name operational-acceptance-RUN_ID-RUN_ATTEMPT --dir /tmp/operational-acceptance
target/debug/operational-lifeline-acceptance verify-report /tmp/operational-acceptance
```

## Pages boundary

`scripts/stage-pages.sh NEW_DIRECTORY` creates the exact public site tree. GitHub Pages uploads that staged directory, never `demo/`. The allowlist contains the cinematic/operational HTML, CSS, modules, public operational fixture assets, narration/poster/trace assets, and the vendored Three.js module plus license. It excludes every `restricted/` directory, tests, `node_modules`, scripts, source maps, package metadata, temporary data, and acceptance raw evidence.

The checked `demo/fixtures/operational-lifeline-v1/restricted/` bytes are public-repository test evidence and therefore are **not confidential**. The Pages and demo-server boundaries make them non-addressable from the site; repository access remains public.

## Explicit exclusion

Issue #30 is not implemented here: this harness does not render or publish a film, create a release asset, publish a postmortem, or perform release-download verification.
