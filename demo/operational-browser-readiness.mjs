#!/usr/bin/env node
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import puppeteer from 'puppeteer-core';

import { chromeArgs } from './export-utils.mjs';

const MAX_DIAGNOSTIC_BYTES = 16 * 1024;
const MAX_APPARMOR_LABEL_BYTES = 1024;
const CLEANUP_TIMEOUT_MS = 5_000;
const NAVIGATION_TIMEOUT_MS = 5_000;
const LABEL = 'CANARY-FREE browser readiness diagnostic';
const DIRECT_RESPONSE = 'chrome-node-loopback-ready';
const INTERCEPTED_RESPONSE = 'chrome-cdp-intercepted-ready';
const INTERCEPTED_RESPONSE_HTML = `<!doctype html><html><body><main id="cdp-intercepted-ready">${INTERCEPTED_RESPONSE}</main></body></html>`;
const APPARMOR_LABEL_ALLOWLIST = /^[A-Za-z0-9_./:+,@=()& -]+$/;

function bounded(label, operation) {
  let timer;
  return Promise.race([
    operation(),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} exceeded 5 seconds`)), CLEANUP_TIMEOUT_MS);
    }),
  ]).finally(() => clearTimeout(timer));
}

const profile = await mkdtemp(join(tmpdir(), 'smesh-browser-readiness-'));
await chmod(profile, 0o700);
let browser;
let server;
let failure;

try {
  let interceptedSocketRequests = 0;
  server = createServer((request, response) => {
    if (request.url === '/intercepted') interceptedSocketRequests += 1;
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    response.end(DIRECT_RESPONSE);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert(address && typeof address === 'object');
  const { port } = address;
  const directUrl = `http://127.0.0.1:${port}/direct`;
  const interceptedUrl = `http://127.0.0.1:${port}/intercepted`;

  browser = await puppeteer.launch({
    executablePath: process.env.CHROME || '/usr/bin/google-chrome',
    headless: true,
    pipe: true,
    userDataDir: profile,
    args: chromeArgs({ qualificationOffline: 'true', unsafeNoSandbox: 'true' }),
  });
  const browserPid = browser.process()?.pid;
  assert(Number.isSafeInteger(browserPid) && browserPid > 0, 'browser PID unavailable');
  const rawAppArmorLabel = await readFile(`/proc/${browserPid}/attr/current`, 'utf8');
  assert(
    Buffer.byteLength(rawAppArmorLabel) <= MAX_APPARMOR_LABEL_BYTES + 1,
    'browser AppArmor label exceeds diagnostic cap',
  );
  const browserAppArmorLabel = rawAppArmorLabel.endsWith('\n')
    ? rawAppArmorLabel.slice(0, -1)
    : rawAppArmorLabel;
  assert(browserAppArmorLabel.length > 0, 'browser AppArmor label is empty');
  assert(APPARMOR_LABEL_ALLOWLIST.test(browserAppArmorLabel), 'browser AppArmor label contains a disallowed byte');
  const browserVersion = await browser.version();
  assert(Buffer.byteLength(browserVersion) <= 1024, 'browser version exceeds diagnostic cap');
  assert(APPARMOR_LABEL_ALLOWLIST.test(browserVersion), 'browser version contains a disallowed byte');
  process.stdout.write(
    `[${LABEL}] AUTHORITY browser_pid=${browserPid} browser_apparmor_label=${JSON.stringify(browserAppArmorLabel)} browser_version=${JSON.stringify(browserVersion)}\n`,
  );

  const page = await browser.newPage();
  try {
    await page.goto(directUrl, { waitUntil: 'domcontentloaded', timeout: NAVIGATION_TIMEOUT_MS });
    assert.equal(await page.evaluate(() => document.body.textContent), DIRECT_RESPONSE);
    process.stdout.write(`[${LABEL}] DIRECT_LOOPBACK=UNEXPECTED_READY\n`);
  } catch (error) {
    const detail = String(error?.message ?? error);
    if (detail.includes('net::ERR_ACCESS_DENIED')) {
      process.stdout.write(`[${LABEL}] DIRECT_LOOPBACK=DENIED\n`);
    } else {
      process.stdout.write(`[${LABEL}] DIRECT_LOOPBACK=UNEXPECTED_FAILED\n`);
    }
  }

  let interceptionHandlerFailure;
  await page.setRequestInterception(true);
  page.on('request', (request) => {
    const operation = request.url() === interceptedUrl
      ? request.respond({
          status: 200,
          contentType: 'text/html; charset=utf-8',
          body: INTERCEPTED_RESPONSE_HTML,
        })
      : request.abort('blockedbyclient');
    void operation.catch((error) => {
      interceptionHandlerFailure ??= error;
    });
  });

  try {
    await page.goto(interceptedUrl, { waitUntil: 'domcontentloaded', timeout: NAVIGATION_TIMEOUT_MS });
    if (interceptionHandlerFailure) throw interceptionHandlerFailure;
    assert.equal(
      await page.evaluate(() => document.querySelector('#cdp-intercepted-ready')?.textContent),
      INTERCEPTED_RESPONSE,
    );
    assert.equal(interceptedSocketRequests, 0, 'intercepted navigation reached the loopback socket');
    process.stdout.write(`[${LABEL}] INTERCEPTED_LOOPBACK=READY\n`);
  } catch (error) {
    process.stderr.write(`[${LABEL}] INTERCEPTED_LOOPBACK=FAILED\n`);
    throw error;
  }
} catch (error) {
  failure = error;
} finally {
  if (browser) {
    try {
      await bounded('browser close', () => browser.close());
    } catch (error) {
      const child = browser.process();
      child?.kill('SIGKILL');
      if (child && child.exitCode === null && child.signalCode === null) {
        try {
          await bounded('browser reap', () => once(child, 'exit'));
        } catch (reapError) {
          failure ??= reapError;
        }
      }
      failure ??= error;
    }
  }
  if (server) {
    server.closeAllConnections?.();
    try {
      await bounded('server close', () => new Promise((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      }));
    } catch (error) {
      failure ??= error;
    }
  }
  try {
    await bounded('profile removal', () => rm(profile, { recursive: true, force: true }));
  } catch (error) {
    failure ??= error;
  }
}

if (failure) {
  const detail = String(failure?.stack ?? failure).slice(0, MAX_DIAGNOSTIC_BYTES);
  process.stderr.write(`[${LABEL}] FAILED; no fixture, canary, or private input was loaded\n${detail}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`[${LABEL}] READY; fixed loopback response only; no fixture, canary, or private input was loaded\n`);
}
