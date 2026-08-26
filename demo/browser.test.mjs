import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import puppeteer from 'puppeteer-core';

import { chromeArgs, closeServer } from './export-utils.mjs';
import { createDemoServer } from './serve-demo.mjs';

test('browser rejects malformed trace events and camera is time-derived', { timeout: 45_000 }, async () => {
  const server = await createDemoServer({ port: 0 });
  const { port } = server.address();
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: process.env.CHROME || '/usr/bin/google-chrome',
      headless: true,
      args: chromeArgs({}),
    });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__lifelineReady === true);
    const result = await page.evaluate(async () => {
      const line = (await fetch('./lifeline.trace.jsonl').then((response) => response.text())).split('\n')[0];
      const valid = JSON.parse(line);
      const missingMetrics = structuredClone(valid); delete missingMetrics.metrics;
      const maliciousLayer = structuredClone(valid); maliciousLayer.layer = '<img src=x onerror=alert(1)>';
      const rejected = [];
      for (const event of [missingMetrics, maliciousLayer]) {
        try { window.LIFELINE_VALIDATE_EVENT(event); rejected.push(false); }
        catch { rejected.push(true); }
      }
      const first = window.LIFELINE_CAMERA_ROTATION_AT(70_000);
      window.LIFELINE_CAMERA_ROTATION_AT(1_000);
      const second = window.LIFELINE_CAMERA_ROTATION_AT(70_000);
      return { rejected, first, second, ready: window.__lifelineReady };
    });
    assert.equal(result.ready, true);
    assert.deepEqual(result.rejected, [true, true]);
    assert.deepEqual(result.first, result.second);
  } finally {
    if (browser) await browser.close();
    await closeServer(server);
  }
});

test('event log implementation never assigns trace data through innerHTML', () => {
  const source = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.equal(source.includes('.innerHTML'), false);
  assert.equal(source.includes('replaceChildren(fragment)'), true);
});
