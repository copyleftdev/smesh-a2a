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
const LABEL = 'CANARY-FREE browser readiness diagnostic';
const RESPONSE = 'chrome-node-loopback-ready';
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
  server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    response.end(RESPONSE);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert(address && typeof address === 'object');
  const { port } = address;

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
  process.stdout.write(
    `[${LABEL}] AUTHORITY browser_pid=${browserPid} browser_apparmor_label=${JSON.stringify(browserAppArmorLabel)}\n`,
  );
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}`, { waitUntil: 'domcontentloaded', timeout: 10_000 });
  assert.equal(await page.evaluate(() => document.body.textContent), RESPONSE);
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
