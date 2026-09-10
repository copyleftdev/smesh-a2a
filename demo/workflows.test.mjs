import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ci = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const pages = await readFile(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');

function jobBlock(source, name) {
  const start = source.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing ${name} job`);
  const remainder = source.slice(start + name.length + 3);
  const next = remainder.search(/^  [a-z][a-z-]+:/m);
  return next === -1 ? remainder : remainder.slice(0, next);
}

test('fresh Ubuntu test and operational jobs provision bounded qualification tooling', () => {
  for (const job of ['test', 'operational-acceptance']) {
    const block = jobBlock(ci, job);
    assert.match(block, /timeout --signal=TERM --kill-after=10s 2m apt-get update/);
    assert.match(block, /timeout --signal=TERM --kill-after=10s 2m apt-get install --yes bubblewrap strace/);
  }
  const npmInstalls = [...ci.matchAll(/^\s+.*npm ci --prefix demo.*$/gm)].map(([line]) => line);
  assert.ok(npmInstalls.length >= 2);
  for (const line of npmInstalls) assert.match(line, /timeout --signal=TERM --kill-after=10s 2m npm ci --prefix demo/);
});

test('general test job installs browser dependencies before Rust suites', () => {
  const block = jobBlock(ci, 'test');
  const install = block.indexOf('npm ci --prefix demo');
  const firstCargoTest = block.indexOf('cargo test');
  assert.notEqual(install, -1, 'general test job must install demo dependencies');
  assert.notEqual(firstCargoTest, -1, 'general test job must run Rust tests');
  assert.ok(install < firstCargoTest, 'npm ci must precede every cargo test in the general test job');
});

test('Pages deploy has a bounded live public and restricted-route gate', () => {
  assert.match(pages, /PAGE_URL: \$\{\{ steps\.deployment\.outputs\.page_url \}\}/);
  assert.match(pages, /timeout-minutes: 5/);
  assert.match(pages, /--connect-timeout 5 --max-time 10/);
  assert.match(pages, /operational\.html/);
  for (const name of ['canonical-capture.jsonl', 'sealed-replay.jsonl', 'evidence-manifest.json', 'criteria-evidence.json']) {
    assert.match(pages, new RegExp(name.replace('.', '\\.')));
  }
  assert.match(pages, /"\$status" = 404/);
  assert.match(pages, /attempt.*12/);
});
