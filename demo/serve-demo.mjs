#!/usr/bin/env node
import { createServer } from 'node:http';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const demoRoot = realpathSync(dirname(fileURLToPath(import.meta.url)));
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/operational.html', ['operational.html', 'text/html; charset=utf-8']],
  ['/operational.css', ['operational.css', 'text/css; charset=utf-8']],
  ['/operational-app.mjs', ['operational-app.mjs', 'text/javascript; charset=utf-8']],
  ['/operational-observatory.mjs', ['operational-observatory.mjs', 'text/javascript; charset=utf-8']],
  ['/fixtures/operational-observatory-v1/package.jsonl', ['fixtures/operational-observatory-v1/package.jsonl', 'application/x-ndjson']],
  ['/fixtures/operational-observatory-v1/receipt.json', ['fixtures/operational-observatory-v1/receipt.json', 'application/json']],
  ['/fixtures/operational-observatory-v1/actors.json', ['fixtures/operational-observatory-v1/actors.json', 'application/json']],
  ['/fixtures/operational-observatory-v1/editorial.json', ['fixtures/operational-observatory-v1/editorial.json', 'application/json']],
  ['/fixtures/operational-observatory-v1/browser-bootstrap.json', ['fixtures/operational-observatory-v1/browser-bootstrap.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/package.jsonl', ['fixtures/operational-lifeline-v1/package.jsonl', 'application/x-ndjson']],
  ['/fixtures/operational-lifeline-v1/receipt.json', ['fixtures/operational-lifeline-v1/receipt.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/actors.json', ['fixtures/operational-lifeline-v1/actors.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/editorial.json', ['fixtures/operational-lifeline-v1/editorial.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/browser-bootstrap.json', ['fixtures/operational-lifeline-v1/browser-bootstrap.json', 'application/json']],
  ['/lifeline.trace.jsonl', ['lifeline.trace.jsonl', 'application/x-ndjson']],
  ['/lifeline-voiceover.mp3', ['lifeline-voiceover.mp3', 'audio/mpeg']],
  ['/trace.schema.json', ['trace.schema.json', 'application/schema+json']],
  ['/poster.jpg', ['poster.jpg', 'image/jpeg']],
  ['/vendor/three.module.min.js', ['vendor/three.module.min.js', 'text/javascript; charset=utf-8']],
]);

const LEGACY_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const STRICT_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
export function securityHeaders(route = '') {
  return {
    'cache-control': 'no-store',
    'content-security-policy': route === '/operational.html' ? STRICT_CSP : LEGACY_CSP,
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'camera=(), geolocation=(), microphone=()',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  };
}
function respond(response, status, route, headers = {}, body) {
  response.writeHead(status, { ...securityHeaders(route), ...headers });
  response.end(body);
}

function loadAsset(relativeFile) {
  const canonical = realpathSync(join(demoRoot, relativeFile));
  const fromRoot = relative(demoRoot, canonical);
  if (fromRoot.startsWith('..') || isAbsolute(fromRoot) || !lstatSync(canonical).isFile()) {
    throw new Error('asset escaped the demo root');
  }
  return readFileSync(canonical);
}

function parseRange(value, size) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(value || '');
  if (!match || (!match[1] && !match[2]) || size === 0) return null;
  let start;
  let end;
  if (!match[1]) {
    const suffix = Number(match[2]);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) return null;
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] ? Number(match[2]) : size - 1;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start >= size || end < start) return null;
    end = Math.min(end, size - 1);
  }
  return { start, end };
}

export function createDemoServer({ port = 43130, host = '127.0.0.1' } = {}) {
  if (!Number.isInteger(port) || (port !== 0 && (port < 1024 || port > 65535))) {
    throw new RangeError('port must be zero or an integer from 1024 through 65535');
  }
  if (host !== '127.0.0.1' && host !== '::1') {
    throw new RangeError('demo server only permits loopback hosts');
  }

  const server = createServer((request, response) => {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      respond(response, 405, '', { allow: 'GET, HEAD' }, 'method not allowed');
      return;
    }
    let route;
    try {
      route = decodeURIComponent((request.url || '/').split('?')[0]);
    } catch {
      respond(response, 400, '', {}, 'bad request');
      return;
    }
    const asset = assets.get(route);
    if (!asset) {
      respond(response, 404, route, {}, 'not found');
      return;
    }
    try {
      const [relativeFile, contentType] = asset;
      const fullBody = loadAsset(relativeFile);
      const requestedRange = request.headers.range;
      const range = requestedRange ? parseRange(requestedRange, fullBody.length) : null;
      if (requestedRange && !range) {
        respond(response, 416, route, { 'content-range': `bytes */${fullBody.length}` });
        return;
      }
      const body = range ? fullBody.subarray(range.start, range.end + 1) : fullBody;
      respond(response, range ? 206 : 200, route, {
        'content-type': contentType,
        'content-length': body.length,
        'accept-ranges': 'bytes',
        ...(range ? { 'content-range': `bytes ${range.start}-${range.end}/${fullBody.length}` } : {}),
      }, request.method === 'HEAD' ? undefined : body);
    } catch {
      respond(response, 500, route, {}, 'asset unavailable');
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (import.meta.url === invokedPath) {
  const port = Number(process.env.PORT || 43130);
  const server = await createDemoServer({ port });
  console.log(`LIFELINE demo: http://127.0.0.1:${port}/`);
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => server.close(() => process.exit(0)));
  }
}
