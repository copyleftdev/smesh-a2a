#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  printf 'usage: %s <new-output-directory>\n' "$0" >&2
  exit 64
fi

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
output=$1
case "$output" in
  /*) ;;
  *) output=$(pwd)/$output ;;
esac
if [ -e "$output" ]; then
  printf 'output already exists: %s\n' "$output" >&2
  exit 73
fi

work=$(mktemp -d /tmp/smesh-operational-lifeline.XXXXXX)
chmod 700 "$work"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

cd "$repo"
timeout 180 cargo build --locked --quiet --bin lifeline-failure-scenario --bin operational-lifeline-capture
timeout 45 target/debug/lifeline-failure-scenario deploy/lifeline-teams.json "$work/scenario" >/dev/null
timeout 45 target/debug/operational-lifeline-capture "$work/scenario" "$output" >/dev/null
printf '%s\n' "$output/package.jsonl"
