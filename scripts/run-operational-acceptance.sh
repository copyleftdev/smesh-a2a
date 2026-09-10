#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 1 ]; then
  printf 'usage: %s <new-report-directory>\n' "$0" >&2
  exit 64
fi
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
report=$1
case "$report" in /*) ;; *) report=$(pwd)/$report ;; esac
if [ -e "$report" ] || [ -L "$report" ]; then
  printf 'report output must not exist\n' >&2
  exit 73
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/smesh-operational-acceptance.XXXXXX")
chmod 700 "$work"
cleanup() {
  status=$?
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
cd "$repo"

# The acceptance binary owns a 120s qualification watchdog (including the
# browser's 90s watchdog) and at most 8s of process cleanup. 140s keeps the
# outer timeout strictly beyond that 128s inner worst case.
ACCEPTANCE_OUTER_TIMEOUT_SECS=140

mkdir -p "$repo/target"
# node_modules is replaced by npm ci, so keep its install and every browser
# consumer in one bounded dependency lifecycle. The descriptor closes on every
# exit path after report verification and cleanup.
exec 9>"$repo/target/.operational-acceptance-dependencies.lock"
flock -w 180 9
timeout --signal=TERM --kill-after=10s 2m \
  npm ci --prefix "$repo/demo" --ignore-scripts --no-audit --no-fund >/dev/null
timeout --signal=TERM --kill-after=10s 4m cargo build --locked --quiet \
  --bin lifeline-failure-scenario --bin operational-lifeline-capture \
  --bin operational-lifeline-qualification --bin operational-lifeline-acceptance

for run in a b; do
  mkdir -m 700 "$work/scenario-$run"
  rmdir "$work/scenario-$run"
  timeout --signal=TERM --kill-after=10s 45s \
    "$repo/target/debug/lifeline-failure-scenario" deploy/lifeline-teams.json "$work/scenario-$run" >/dev/null
  timeout --signal=TERM --kill-after=10s 45s \
    "$repo/target/debug/operational-lifeline-capture" "$work/scenario-$run" "$work/package-$run" >/dev/null
done

timeout --signal=TERM --kill-after=5s 30s python3 - "$work/package-a" "$work/package-b" "$repo/demo/fixtures/operational-lifeline-v1" <<'PY'
import os, pathlib, sys
allowed = sorted('''actors.json
browser-bootstrap.json
editorial.json
package.jsonl
public-manifest.json
receipt.json
restricted/canonical-capture.jsonl
restricted/causal-source.jsonl
restricted/criteria-evidence.json
restricted/decision-receipt.json
restricted/evidence-manifest.json
restricted/privacy-manifest.json
restricted/redaction-log.json
restricted/replay-receipt.json
restricted/review-packet.json
restricted/review-receipt.json
restricted/sealed-replay.jsonl
restricted/source-facts.json'''.splitlines())
def files(root, checked=False):
    root=pathlib.Path(root)
    found=[]
    for path in root.rglob('*'):
        if path.is_symlink(): raise SystemExit('artifact symlink rejected')
        if path.is_file():
            rel=path.relative_to(root).as_posix()
            if checked and rel == 'README.md': continue
            found.append(rel)
    return sorted(found)
roots=sys.argv[1:]
for index, root in enumerate(roots):
    if files(root, index == 2) != allowed: raise SystemExit('operational artifact allowlist mismatch')
for name in allowed:
    values=[pathlib.Path(root,name).read_bytes() for root in roots]
    if values[0] != values[1] or values[0] != values[2]: raise SystemExit(f'operational artifact divergence: {name}')
PY

timeout --signal=TERM --kill-after=10s 2m \
  "$repo/target/debug/operational-lifeline-qualification" \
  "$repo" "$work/package-a" "$work/package-b" "$work/qualification-probes.json"

timeout --signal=TERM --kill-after=10s "${ACCEPTANCE_OUTER_TIMEOUT_SECS}s" \
  "$repo/target/debug/operational-lifeline-acceptance" \
  "$work/package-a" "$work/qualification-probes.json" "$report"
timeout --signal=TERM --kill-after=10s 30s \
  "$repo/target/debug/operational-lifeline-acceptance" verify-report "$report"
printf '%s\n' "$report"
