#!/usr/bin/env node
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import puppeteer from 'puppeteer-core';

import { chromeArgs } from './export-utils.mjs';

const MAX_DIAGNOSTIC_BYTES = 16 * 1024;
const CLEANUP_TIMEOUT_MS = 5_000;
const LABEL = 'CANARY-FREE browser readiness diagnostic';

const profile = await mkdtemp(join(tmpdir(), 'smesh-browser-readiness-'));
await chmod(profile, 0o700);
let browser;
let failure;

try {
  browser = await puppeteer.launch({
    executablePath: process.env.CHROME || '/usr/bin/google-chrome',
    headless: true,
    pipe: true,
    userDataDir: profile,
    args: chromeArgs({ qualificationOffline: 'true', unsafeNoSandbox: 'true' }),
  });
  const page = await browser.newPage();
  await page.goto('about:blank', { waitUntil: 'domcontentloaded', timeout: 10_000 });
} catch (error) {
  failure = error;
} finally {
  if (browser) {
    let cleanupTimer;
    try {
      await Promise.race([
        browser?.close(),
        new Promise((_, reject) => {
          cleanupTimer = setTimeout(() => reject(new Error('browser close exceeded 5 seconds')), CLEANUP_TIMEOUT_MS);
        }),
      ]);
    } catch (error) {
      browser.process()?.kill('SIGKILL');
      failure ??= error;
    } finally {
      clearTimeout(cleanupTimer);
    }
  }
  try {
    await rm(profile, { recursive: true, force: true });
  } catch (error) {
    failure ??= error;
  }
}

if (failure) {
  const detail = String(failure?.stack ?? failure).slice(0, MAX_DIAGNOSTIC_BYTES);
  process.stderr.write(`[${LABEL}] FAILED; no fixture, canary, or private input was loaded\n${detail}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`[${LABEL}] READY; about:blank only; no fixture, canary, or private input was loaded\n`);
}
