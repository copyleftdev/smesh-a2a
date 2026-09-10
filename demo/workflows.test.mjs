import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ci = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const pages = await readFile(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');
const bwrapReadiness = await readFile(
  new URL('../scripts/ensure-bwrap-ready.sh', import.meta.url),
  'utf8',
).catch(() => '');

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
    assert.match(
      block,
      /timeout --signal=TERM --kill-after=10s 2m apt-get install --yes apparmor apparmor-profiles apparmor-utils bubblewrap strace/,
    );
  }
  const npmInstalls = [...ci.matchAll(/^\s+.*npm ci --prefix demo.*$/gm)].map(([line]) => line);
  assert.ok(npmInstalls.length >= 2);
  for (const line of npmInstalls) assert.match(line, /timeout --signal=TERM --kill-after=10s 2m npm ci --prefix demo/);
});

test('Ubuntu browser jobs require profile-aware bwrap readiness before tests', () => {
  for (const job of ['test', 'operational-acceptance']) {
    const block = jobBlock(ci, job);
    const readiness = block.indexOf('scripts/ensure-bwrap-ready.sh');
    const firstTest = Math.min(
      ...['cargo fmt', 'cargo clippy', 'cargo test', 'npm test', 'run-operational-acceptance.sh']
        .map((command) => block.indexOf(command))
        .filter((position) => position !== -1),
    );
    assert.notEqual(readiness, -1, `${job} must run the bwrap readiness check`);
    assert.ok(readiness < firstTest, `${job} must establish bwrap readiness before tests`);
    assert.match(
      block,
      /timeout --signal=TERM --kill-after=10s 2m scripts\/ensure-bwrap-ready\.sh/,
    );
  }

  assert.match(bwrapReadiness, /bwrap --unshare-net --die-with-parent --dev-bind \/ \/ -- \/bin\/true/);
  assert.match(bwrapReadiness, /kernel\/apparmor_restrict_unprivileged_userns/);
  assert.match(bwrapReadiness, /\/usr\/share\/apparmor\/extra-profiles\/bwrap-userns-restrict/);
  assert.match(bwrapReadiness, /\/etc\/apparmor\.d\/bwrap-userns-restrict/);
  assert.match(bwrapReadiness, /timeout --signal=TERM --kill-after=10s/);
  assert.match(bwrapReadiness, /apparmor_parser -r/);
  const initialProbe = bwrapReadiness.indexOf('if bwrap_smoke_probe; then');
  const profileLoad = bwrapReadiness.indexOf('apparmor_parser -r');
  const requiredProbe = bwrapReadiness.lastIndexOf('\nbwrap_smoke_probe');
  assert.ok(initialProbe !== -1 && initialProbe < profileLoad, 'the initial smoke probe must precede profile activation');
  assert.ok(profileLoad < requiredProbe, 'the same smoke probe must be required after profile activation');
  assert.doesNotMatch(`${ci}\n${bwrapReadiness}`, /sysctl\s+(?:--write|-w)|apparmor_restrict_unprivileged_userns\s*=\s*0/);
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
