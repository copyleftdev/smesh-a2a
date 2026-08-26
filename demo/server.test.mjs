import assert from 'node:assert/strict';
import { request } from 'node:http';
import test from 'node:test';

import { closeServer } from './export-utils.mjs';
import { createDemoServer } from './serve-demo.mjs';

function rawRequest(port, path, method = 'GET') {
  return new Promise((resolve, reject) => {
    const operation = request({ host: '127.0.0.1', port, path, method }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }));
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
    assert.equal((await rawRequest(port, '/vendor/three.module.min.js')).status, 200);
    assert.equal((await rawRequest(port, '/.git/config')).status, 404);
    assert.equal((await rawRequest(port, '/%2e%2e/Cargo.toml')).status, 404);
    assert.equal((await rawRequest(port, '/%E0%A4%A')).status, 400);
    assert.equal((await rawRequest(port, '/', 'POST')).status, 405);
  } finally {
    await closeServer(server);
  }
});

test('demo server refuses non-loopback hosts', () => {
  assert.throws(() => createDemoServer({ port: 0, host: '0.0.0.0' }), /loopback/);
});
