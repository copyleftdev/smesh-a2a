#!/usr/bin/env node
import { createServer } from 'node:http';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const demoRoot = realpathSync(dirname(fileURLToPath(import.meta.url)));
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/lifeline.trace.jsonl', ['lifeline.trace.jsonl', 'application/x-ndjson']],
  ['/trace.schema.json', ['trace.schema.json', 'application/schema+json']],
  ['/poster.jpg', ['poster.jpg', 'image/jpeg']],
  ['/vendor/three.module.min.js', ['vendor/three.module.min.js', 'text/javascript; charset=utf-8']],
]);

function loadAsset(relativeFile) {
  const canonical = realpathSync(join(demoRoot, relativeFile));
  const fromRoot = relative(demoRoot, canonical);
  if (fromRoot.startsWith('..') || isAbsolute(fromRoot) || !lstatSync(canonical).isFile()) {
    throw new Error('asset escaped the demo root');
  }
  return readFileSync(canonical);
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
      response.writeHead(405, { allow: 'GET, HEAD' }).end('method not allowed');
      return;
    }
    let route;
    try {
      route = decodeURIComponent((request.url || '/').split('?')[0]);
    } catch {
      response.writeHead(400).end('bad request');
      return;
    }
    const asset = assets.get(route);
    if (!asset) {
      response.writeHead(404).end('not found');
      return;
    }
    try {
      const [relativeFile, contentType] = asset;
      const body = loadAsset(relativeFile);
      response.writeHead(200, {
        'content-type': contentType,
        'content-length': body.length,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'",
      });
      response.end(request.method === 'HEAD' ? undefined : body);
    } catch {
      response.writeHead(500).end('asset unavailable');
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
