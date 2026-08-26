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

test('play starts the bundled voiceover and advances the synchronized timeline', { timeout: 45_000 }, async () => {
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
    assert.equal(await page.$eval('#play', (button) => button.textContent), 'PLAY');
    await page.click('#play');
    await page.waitForFunction(() => {
      const audio = document.querySelector('#voiceover');
      return audio && !audio.paused && audio.currentTime > 0;
    }, { timeout: 5_000 });
    const state = await page.evaluate(() => ({
      audioTime: document.querySelector('#voiceover').currentTime,
      timeline: Number(document.querySelector('#scrub').value) / 1000,
    }));
    assert.ok(state.audioTime > 0);
    assert.ok(Math.abs(state.audioTime - state.timeline) < 0.25);
    await page.click('#play');
    const pausedAt = await page.$eval('#voiceover', (audio) => audio.currentTime);
    await new Promise((resolve) => setTimeout(resolve, 250));
    const pausedState = await page.evaluate(() => ({
      currentTime: document.querySelector('#voiceover').currentTime,
      paused: document.querySelector('#voiceover').paused,
      button: document.querySelector('#play').textContent,
    }));
    assert.equal(pausedState.paused, true);
    assert.equal(pausedState.button, 'PLAY');
    assert.ok(Math.abs(pausedState.currentTime - pausedAt) < 0.1);
    await page.$eval('#scrub', (scrub) => {
      scrub.value = '30000';
      scrub.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await page.waitForFunction(() => Math.abs(document.querySelector('#voiceover').currentTime - 30) < 0.1);
    await page.click('#speed');
    const speedState = await page.evaluate(() => ({
      rate: document.querySelector('#voiceover').playbackRate,
      label: document.querySelector('#speed').textContent,
    }));
    assert.deepEqual(speedState, { rate: 2, label: '2.0×' });
    await page.click('#play');
    await page.waitForFunction(() => document.querySelector('#voiceover').currentTime > 30);
    await page.$eval('#voiceover', (audio) => audio.dispatchEvent(new Event('ended')));
    await page.waitForFunction(() => Number(document.querySelector('#scrub').value) > 175000, { timeout: 2_000 });
    await page.click('#play');
    await page.$eval('#scrub', (scrub) => {
      scrub.value = '176000';
      scrub.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await page.click('#play');
    await page.waitForFunction(() => Number(document.querySelector('#scrub').value) > 176000, { timeout: 2_000 });
    await page.waitForFunction(() => document.querySelector('#play').textContent === 'PLAY' && Number(document.querySelector('#scrub').value) === 180000, { timeout: 4_000 });
  } finally {
    if (browser) await browser.close();
    await closeServer(server);
  }
});
