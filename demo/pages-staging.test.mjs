import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const repo = new URL('..', import.meta.url).pathname;
const script = join(repo, 'scripts/stage-pages.sh');

async function paths(root, prefix = '') {
  const found = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...await paths(root, name)); else found.push(name);
  }
  return found.sort();
}

test('Pages staging publishes only the closed public allowlist', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'smesh-pages-'));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const output = join(root, 'public');
  const result = spawnSync(script, [output], { cwd: repo, encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const staged = await paths(output);
  assert.deepEqual(staged, [
    'fixtures/operational-lifeline-v1/actors.json',
    'fixtures/operational-lifeline-v1/browser-bootstrap.json',
    'fixtures/operational-lifeline-v1/editorial.json',
    'fixtures/operational-lifeline-v1/package.jsonl',
    'fixtures/operational-lifeline-v1/receipt.json',
    'index.html', 'lifeline-voiceover.mp3', 'lifeline.trace.jsonl',
    'operational-app.mjs', 'operational-observatory.mjs', 'operational.css', 'operational.html',
    'poster.jpg', 'trace.schema.json', 'vendor/THREE-LICENSE.txt', 'vendor/three.module.min.js',
  ]);
  assert.equal(staged.some((name) => name.includes('restricted') || name.endsWith('.map')), false);
  assert.match(await readFile(join(output, 'operational.html'), 'utf8'), /OPERATIONAL OBSERVATORY/);
  assert.notEqual((await readFile(join(output, 'poster.jpg'))).length, 0);
});

test('Pages staging refuses output reuse', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'smesh-pages-reuse-'));
  t.after(async () => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, 'occupied'), 'x');
  const result = spawnSync(script, [root], { cwd: repo, timeout: 30_000 });
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
});
