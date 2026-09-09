import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { request } from 'node:http';
import test from 'node:test';

import { closeServer } from './export-utils.mjs';
import { createDemoServer } from './serve-demo.mjs';

function rawRequest(port, path, method = 'GET', headers = {}) {
  return new Promise((resolve, reject) => {
    const operation = request({ host: '127.0.0.1', port, path, method, headers }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }));
    });
    operation.on('error', reject);
    operation.end();
  });
}

test('demo server exposes only the explicit runtime asset allowlist', async () => {
  const server = await createDemoServer({ port: 0 });
  const { port } = server.address();
  try {
    assert.equal((await rawRequest(port, '/')).status, 200);
    assert.equal((await rawRequest(port, '/lifeline.trace.jsonl')).status, 200);
    const audio = await rawRequest(port, '/lifeline-voiceover.mp3');
    assert.equal(audio.status, 200);
    const audioSize = audio.body.length;
    const range = await rawRequest(port, '/lifeline-voiceover.mp3', 'GET', { range: 'bytes=100-199' });
    assert.equal(range.status, 206);
    assert.equal(range.body.length, 100);
    assert.deepEqual(range.body, audio.body.subarray(100, 200));
    assert.equal(range.headers['content-range'], `bytes 100-199/${audioSize}`);
    const openEnded = await rawRequest(port, '/lifeline-voiceover.mp3', 'GET', { range: 'bytes=100-' });
    assert.equal(openEnded.status, 206);
    assert.equal(openEnded.body.length, audioSize - 100);
    const suffix = await rawRequest(port, '/lifeline-voiceover.mp3', 'GET', { range: 'bytes=-100' });
    assert.equal(suffix.status, 206);
    assert.equal(suffix.body.length, 100);
    const clamped = await rawRequest(port, '/lifeline-voiceover.mp3', 'GET', { range: `bytes=${audioSize - 50}-${audioSize + 999}` });
    assert.equal(clamped.status, 206);
    assert.equal(clamped.body.length, 50);
    const head = await rawRequest(port, '/lifeline-voiceover.mp3', 'HEAD', { range: 'bytes=100-199' });
    assert.equal(head.status, 206);
    assert.equal(head.body.length, 0);
    assert.equal(head.headers['content-length'], '100');
    for (const value of ['bytes=9999999-', 'bytes=0-1,3-4', 'items=0-1', 'bytes=-0', 'bytes=200-100']) {
      const invalid = await rawRequest(port, '/lifeline-voiceover.mp3', 'GET', { range: value });
      assert.equal(invalid.status, 416);
      assert.equal(invalid.headers['content-range'], `bytes */${audioSize}`);
    }
    assert.equal((await rawRequest(port, '/vendor/three.module.min.js')).status, 200);
    assert.equal((await rawRequest(port, '/.git/config')).status, 404);
    assert.equal((await rawRequest(port, '/%2e%2e/Cargo.toml')).status, 404);
    assert.equal((await rawRequest(port, '/%E0%A4%A')).status, 400);
    assert.equal((await rawRequest(port, '/', 'POST')).status, 405);
  } finally {
    await closeServer(server);
  }
});

test('vendored Three.js bytes match the reviewed SHA-256 contract', async () => {
  const bytes = await readFile(new URL('./vendor/three.module.min.js', import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), 'f7cee3c7533449a1505cc12cb5128b89e3d4fd3d7ea62b05f9f5464a217472ee');
});

test('security headers cover success and every explicit error status', async () => {
  const server = await createDemoServer({ port: 0 });
  const { port } = server.address();
  try {
    const responses = [
      await rawRequest(port, '/operational.html'),
      await rawRequest(port, '/missing'),
      await rawRequest(port, '/%E0%A4%A'),
      await rawRequest(port, '/', 'POST'),
      await rawRequest(port, '/lifeline-voiceover.mp3', 'GET', { range: 'bytes=9999999-' }),
    ];
    assert.deepEqual(responses.map(({ status }) => status), [200, 404, 400, 405, 416]);
    for (const response of responses) {
      assert.equal(response.headers['cache-control'], 'no-store');
      assert.equal(response.headers['x-content-type-options'], 'nosniff');
      assert.equal(response.headers['x-frame-options'], 'DENY');
      assert.equal(response.headers['referrer-policy'], 'no-referrer');
      assert.match(response.headers['content-security-policy'], /default-src '(?:self|none)'/);
    }
    assert.equal(responses[0].headers['content-security-policy'].includes("'unsafe-inline'"), false);
  } finally {
    await closeServer(server);
  }
});

test('demo server refuses non-loopback hosts', () => {
  assert.throws(() => createDemoServer({ port: 0, host: '0.0.0.0' }), /loopback/);
});
