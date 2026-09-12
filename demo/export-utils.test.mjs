import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';

import {
  chromeArgs,
  exportEvidenceDocument,
  guardWritable,
  numberArg,
  parseArgs,
  requireExtension,
  waitForExit,
  writeChunk,
} from './export-utils.mjs';

test('numeric exporter arguments are finite and bounded', () => {
  assert.equal(numberArg({ fps: '30' }, 'fps', 24, { min: 1, max: 60, integer: true }), 30);
  for (const value of ['NaN', 'Infinity', '0', '-1', '61', '1.5']) {
    assert.throws(() => numberArg({ fps: value }, 'fps', 24, { min: 1, max: 60, integer: true }), RangeError);
  }
});

test('unsafe Chrome sandbox downgrade is explicit', () => {
  assert.equal(chromeArgs({}).includes('--no-sandbox'), false);
  assert.equal(chromeArgs({ unsafeNoSandbox: 'true' }).includes('--no-sandbox'), true);
});

test('qualification Chrome profile disables background networking and external DNS', () => {
  const args = chromeArgs({ qualificationOffline: 'true' });
  for (const flag of [
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-domain-reliability',
    '--disable-sync',
    '--no-first-run',
    '--safebrowsing-disable-auto-update',
    '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost',
  ]) assert.equal(args.includes(flag), true, flag);
});

test('argument parser and output extension reject malformed values', () => {
  assert.deepEqual(parseArgs(['--fps=30', '--keepCapture=true']), { fps: '30', keepCapture: 'true' });
  assert.throws(() => parseArgs(['fps=30']), RangeError);
  assert.equal(requireExtension('film.mp4', '.mp4', 'out'), 'film.mp4');
  assert.throws(() => requireExtension('film.webm', '.mp4', 'out'), RangeError);
});

test('operational export evidence retains each frame state digest and contributing event IDs', () => {
  const frames = [
    { contributingEventIds: ['sha256:a'], stateDigest: 'sha256:d1', timeNs: '0' },
    { contributingEventIds: ['sha256:a', 'sha256:b'], stateDigest: 'sha256:d2', timeNs: '1' },
  ];
  assert.deepEqual(exportEvidenceDocument({ fps: 30, frames, mode: 'operational', source: '/operational.html' }), {
    fps: 30,
    frames: [
      { contributingEventIds: ['sha256:a'], frame: 0, stateDigest: 'sha256:d1', timeNs: '0' },
      { contributingEventIds: ['sha256:a', 'sha256:b'], frame: 1, stateDigest: 'sha256:d2', timeNs: '1' },
    ],
    mode: 'operational',
    schemaVersion: 'observatory-export-evidence/1',
    source: '/operational.html',
  });
  assert.throws(() => exportEvidenceDocument({ fps: 30, frames: [{ timeNs: '0' }], mode: 'operational', source: '/operational.html' }), /evidence/i);
});

test('child stdin EPIPE is observed instead of becoming uncaught', async () => {
  const child = spawn(process.execPath, ['-e', 'process.exit(7)'], {
    stdio: ['pipe', 'ignore', 'ignore'],
    timeout: 5_000,
  });
  const guard = guardWritable(child.stdin);
  const exit = waitForExit(child, 'child');
  exit.catch(() => {});
  let writeFailed = false;
  try {
    for (let index = 0; index < 16; index += 1) {
      await writeChunk(child.stdin, Buffer.alloc(1024 * 1024), guard);
    }
  } catch {
    writeFailed = true;
  }
  await assert.rejects(exit, /exited with 7/);
  assert.equal(writeFailed || guard.error !== null, true);
});
