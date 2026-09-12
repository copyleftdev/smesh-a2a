#!/bin/sh
set -eu
umask 077

if [ "$#" -ne 1 ]; then
  printf 'usage: %s <new-public-directory>\n' "$0" >&2
  exit 64
fi
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
out=$1
case "$out" in /*) ;; *) out=$(pwd)/$out ;; esac
if [ -e "$out" ] || [ -L "$out" ]; then
  printf 'Pages staging output must not exist\n' >&2
  exit 73
fi

files='index.html
lifeline-voiceover.mp3
lifeline.trace.jsonl
operational-app.mjs
operational-observatory.mjs
operational.css
operational.html
poster.jpg
trace.schema.json
vendor/THREE-LICENSE.txt
vendor/three.module.min.js
fixtures/operational-lifeline-v1/actors.json
fixtures/operational-lifeline-v1/browser-bootstrap.json
fixtures/operational-lifeline-v1/editorial.json
fixtures/operational-lifeline-v1/package.jsonl
fixtures/operational-lifeline-v1/receipt.json'

mkdir -m 700 "$out"
cleanup() { status=$?; if [ "$status" -ne 0 ]; then rm -rf -- "$out"; fi; exit "$status"; }
trap cleanup EXIT HUP INT TERM
for relative in $files; do
  source=$repo/demo/$relative
  if [ ! -f "$source" ] || [ -L "$source" ]; then
    printf 'invalid Pages source: %s\n' "$relative" >&2
    exit 65
  fi
  mkdir -p -- "$out/$(dirname -- "$relative")"
  cp -- "$source" "$out/$relative"
done
expected=$(printf '%s\n' "$files" | LC_ALL=C sort)
actual=$(CDPATH='' cd -- "$out" && find . -type f -print | sed 's#^./##' | LC_ALL=C sort)
if [ "$actual" != "$expected" ] || find "$out" -type l -print -quit | grep -q .; then
  printf 'Pages staging allowlist drift\n' >&2
  exit 65
fi
trap - EXIT HUP INT TERM
printf '%s\n' "$out"
