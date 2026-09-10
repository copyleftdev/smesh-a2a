import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ci = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const pages = await readFile(new URL('../.github/workflows/pages.yml', import.meta.url), 'utf8');
const bwrapReadiness = await readFile(
  new URL('../scripts/ensure-bwrap-ready.sh', import.meta.url),
  'utf8',
).catch(() => '');
const browserReadiness = await readFile(
  new URL('./operational-browser-readiness.mjs', import.meta.url),
  'utf8',
).catch(() => '');
const browserDiagnostic = await readFile(
  new URL('../scripts/run-browser-readiness-diagnostic.sh', import.meta.url),
  'utf8',
).catch(() => '');
const appArmorFilter = await readFile(
  new URL('./filter-apparmor-denials.mjs', import.meta.url),
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

test('operational CI runs an exact canary-free browser readiness diagnostic before fixtures', () => {
  const block = jobBlock(ci, 'operational-acceptance');
  const install = block.indexOf('npm ci --prefix demo');
  const diagnostic = block.indexOf('scripts/run-browser-readiness-diagnostic.sh');
  const harness = block.indexOf('scripts/run-operational-acceptance.sh');
  assert.ok(install !== -1 && install < diagnostic, 'diagnostic dependencies must be installed first');
  assert.ok(diagnostic !== -1 && diagnostic < harness, 'diagnostic must precede every operational fixture');
  assert.match(
    block,
    /timeout --signal=TERM --kill-after=10s 45s scripts\/run-browser-readiness-diagnostic\.sh/,
  );

  assert.match(browserReadiness, /CANARY-FREE browser readiness diagnostic/);
  assert.match(browserReadiness, /mkdtemp\(join\(tmpdir\(\), 'smesh-browser-readiness-'\)\)/);
  assert.match(browserReadiness, /chmod\(profile, 0o700\)/);
  assert.match(browserReadiness, /pipe: true/);
  assert.match(browserReadiness, /userDataDir: profile/);
  assert.match(browserReadiness, /browser\.process\(\)\?\.pid/);
  assert.match(browserReadiness, /\/proc\/\$\{browserPid\}\/attr\/current/);
  assert.match(browserReadiness, /MAX_APPARMOR_LABEL_BYTES/);
  assert.match(browserReadiness, /APPARMOR_LABEL_ALLOWLIST/);
  assert.match(browserReadiness, /browser_pid=\$\{browserPid\}/);
  assert.match(browserReadiness, /browser_apparmor_label=\$\{JSON\.stringify\(browserAppArmorLabel\)\}/);
  assert.match(browserReadiness, /chromeArgs\(\{ qualificationOffline: 'true', unsafeNoSandbox: 'true' \}\)/);
  assert.match(browserReadiness, /createServer/);
  assert.match(browserReadiness, /listen\(0, '127\.0\.0\.1'/);
  assert.match(browserReadiness, /server\.address\(\)/);
  assert.match(browserReadiness, /page\.goto\(`http:\/\/127\.0\.0\.1:\$\{port\}`/);
  assert.match(browserReadiness, /document\.body\.textContent/);
  assert.match(browserReadiness, /assert\.equal/);
  assert.match(browserReadiness, /slice\(0, MAX_DIAGNOSTIC_BYTES\)/);
  assert.match(browserReadiness, /Promise\.race\(\[/);
  assert.match(browserReadiness, /bounded\('browser close', \(\) => browser\.close\(\)\)/);
  assert.match(browserReadiness, /bounded\('browser reap', \(\) => once\(child, 'exit'\)\)/);
  assert.match(browserReadiness, /server\.closeAllConnections\?\.\(\)/);
  assert.match(browserReadiness, /server\.close/);
  assert.match(browserReadiness, /rm\(profile, \{ recursive: true, force: true \}\)/);
  assert.doesNotMatch(browserReadiness, /lifeline|acceptance-scorecard|operational\.html/);

  assert.match(browserDiagnostic, /status=\$\{PIPESTATUS\[0\]\}/);
  assert.match(browserDiagnostic, /runner_kernel=\$\(uname -r\)/);
  assert.match(browserDiagnostic, /journalctl --dmesg --since "@\$\{start_epoch\}"/);
  assert.match(browserDiagnostic, /filter-apparmor-denials\.mjs "\$browser_pid" "\$browser_apparmor_label"/);
  assert.match(browserDiagnostic, /exit "\$status"/);
  assert.match(appArmorFilter, /apparmor="DENIED"/);
  assert.match(appArmorFilter, /class="net"/);
  assert.match(appArmorFilter, /MAX_DENIAL_BYTES/);
  assert.doesNotMatch(`${browserDiagnostic}\n${appArmorFilter}`, /printenv|\/proc\/self\/environ|env\s*$/m);
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
