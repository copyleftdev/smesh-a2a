import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  EXPECTED_OPERATIONAL_ARTIFACTS,
  buildCoherentSyntheticSubstitution,
  verifyCompleteOperationalInputSet,
} from './operational-qualification-inputs.mjs';
import { cleanupQualification, createRequestSettlement } from './operational-request-boundary.mjs';

async function fixtureInputs() {
  return new Map(await Promise.all(EXPECTED_OPERATIONAL_ARTIFACTS.map(async ({ path }) => [
    path,
    new Uint8Array(await readFile(new URL(`./fixtures/operational-lifeline-v1/${path}`, import.meta.url))),
  ])));
}

test('all eighteen public and restricted artifacts are mandatory synthetic inputs', async () => {
  const complete = await fixtureInputs();
  assert.equal((await verifyCompleteOperationalInputSet(complete)).artifacts.length, 18);
  const restricted = EXPECTED_OPERATIONAL_ARTIFACTS.filter(({ path }) => path.startsWith('restricted/'));
  assert.equal(restricted.length, 12);
  for (const { path } of EXPECTED_OPERATIONAL_ARTIFACTS) {
    const omitted = new Map(complete);
    omitted.delete(path);
    await assert.rejects(verifyCompleteOperationalInputSet(omitted), {
      name: 'Error',
      message: 'synthetic probe requires the exact 18-artifact input set',
    });
  }
});

test('coherent 46-event substitution is bound to the verified complete input set', async () => {
  const complete = await fixtureInputs();
  const verified = await verifyCompleteOperationalInputSet(complete);
  const substitution = await buildCoherentSyntheticSubstitution(complete, verified);
  assert.equal(substitution.eventCount, 46);
  assert.match(substitution.inputSetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(substitution.files.size, 18);
  const packageText = new TextDecoder().decode(substitution.files.get('package.jsonl'));
  const header = JSON.parse(packageText.split('\n')[0]);
  assert.equal(header.runId, `lifeline-substituted-${substitution.inputSetDigest.slice(7, 19)}`);
  const receipt = JSON.parse(new TextDecoder().decode(substitution.files.get('receipt.json')));
  assert.notEqual(receipt.outputDigest, JSON.parse(new TextDecoder().decode(complete.get('receipt.json'))).outputDigest);
});

test('extra synthetic input is rejected', async () => {
  const inputs = await fixtureInputs();
  inputs.set('restricted/attacker-extra.json', new Uint8Array([123, 125]));
  await assert.rejects(verifyCompleteOperationalInputSet(inputs), /exact 18-artifact input set/);
});

test('late respond and recovery abort rejections settle before qualification can pass', async () => {
  const page = new EventEmitter();
  let rejectRespond;
  let rejectAbort;
  const respond = new Promise((_, reject) => { rejectRespond = reject; });
  const abort = new Promise((_, reject) => { rejectAbort = reject; });
  const boundary = createRequestSettlement(page, async (request) => request.respond());
  const unhandled = [];
  const captureUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', captureUnhandled);
  try {
    const request = {
      abort: () => abort,
      isInterceptResolutionHandled: () => false,
      respond: () => respond,
    };
    assert.equal(page.emit('request', request), true);
    const settled = boundary.settle();
    rejectRespond(new Error('private respond failure'));
    await Promise.resolve();
    rejectAbort(new Error('private abort failure'));
    await assert.rejects(settled, { message: 'browser request interception failed' });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', captureUnhandled);
  }
});

test('settlement synchronously closes admission before draining admitted requests', async () => {
  const page = new EventEmitter();
  let release;
  const admitted = new Promise((resolve) => { release = resolve; });
  const handled = [];
  const boundary = createRequestSettlement(page, async (request) => {
    handled.push(request);
    await admitted;
  });

  page.emit('request', 'already-admitted');
  await Promise.resolve();
  assert.deepEqual(handled, ['already-admitted']);
  assert.equal(page.listenerCount('request'), 1);

  const settled = boundary.settle();
  assert.equal(page.listenerCount('request'), 0);
  page.emit('request', 'post-settlement');
  release();
  await settled;

  assert.deepEqual(handled, ['already-admitted']);
  assert.equal(page.listenerCount('request'), 0);
});

test('cleanup removes request admission even when browser close fails', async () => {
  const server = await import('node:http').then(({ createServer }) => createServer());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const page = new EventEmitter();
  const handled = [];
  const boundary = createRequestSettlement(page, async (request) => { handled.push(request); });
  let browserCloseAttempted = false;

  await assert.rejects(cleanupQualification({
    browser: { close: async () => { browserCloseAttempted = true; throw new Error('private browser close failure'); } },
    requestSettlements: [boundary],
    server,
  }), { message: 'qualification cleanup failed' });

  assert.equal(browserCloseAttempted, true);
  assert.equal(server.listening, false);
  assert.equal(page.listenerCount('request'), 0);
  page.emit('request', 'post-cleanup');
  await Promise.resolve();
  assert.deepEqual(handled, []);
});

test('cleanup attempts browser and server closure when both fail', async () => {
  const attempted = [];
  const server = { listening: true };
  await assert.rejects(cleanupQualification({
    browser: { close: async () => { attempted.push('browser'); throw new Error('private browser close failure'); } },
    closeServer: async () => { attempted.push('server'); throw new Error('private server close failure'); },
    server,
  }), { message: 'qualification cleanup failed' });
  assert.deepEqual(attempted, ['browser', 'server']);
});

test('operational browser probe serves repository assets without reaching its listener', { timeout: 60_000 }, () => {
  const profile = mkdtempSync(join(tmpdir(), 'smesh-node-browser-profile-'));
  try {
    const result = spawnSync(process.execPath, ['operational-qualification.mjs'], {
      cwd: new URL('.', import.meta.url),
      encoding: 'utf8',
      env: {
        ...process.env,
        SMESH_QUALIFICATION_BROWSER_PROFILE: profile,
      },
      timeout: 55_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    const qualification = JSON.parse(result.stdout);
    assert.equal(qualification.evidence.nodeListenerBrowserRequests, '0');
    assert.equal(qualification.evidence.unknownSameOriginAborted, true);
    assert.equal(qualification.evidence.sameOriginOnly, true);
    assert.deepEqual(qualification.evidence.requestPaths, [
      '/fixtures/operational-lifeline-v1/actors.json',
      '/fixtures/operational-lifeline-v1/browser-bootstrap.json',
      '/fixtures/operational-lifeline-v1/editorial.json',
      '/fixtures/operational-lifeline-v1/package.jsonl',
      '/fixtures/operational-lifeline-v1/receipt.json',
      '/operational-app.mjs',
      '/operational-observatory.mjs',
      '/operational.css',
      '/operational.html',
      '/vendor/three.module.min.js',
    ]);
  } finally {
    rmSync(profile, { recursive: true, force: true });
  }
});

test('operational browser probe emits no passing evidence when any input is omitted', () => {
  for (const { path } of EXPECTED_OPERATIONAL_ARTIFACTS) {
    const profile = mkdtempSync(join(tmpdir(), 'smesh-node-browser-profile-'));
    const result = spawnSync(process.execPath, ['operational-qualification.mjs'], {
      cwd: new URL('.', import.meta.url),
      encoding: 'utf8',
      env: {
        ...process.env,
        SMESH_QUALIFICATION_BROWSER_PROFILE: profile,
        SMESH_QUALIFICATION_OMIT_ARTIFACT: path,
      },
      timeout: 60_000,
    });
    rmSync(profile, { recursive: true, force: true });
    assert.equal(result.error, undefined, path);
    assert.equal(result.status, 1, path);
    assert.equal(result.stdout, '', path);
    assert.match(result.stderr, /exact 18-artifact input set/, path);
  }
});
