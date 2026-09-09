import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import puppeteer from 'puppeteer-core';

import { chromeArgs, closeServer } from './export-utils.mjs';
import { canonicalJson, protocolHash } from './operational-observatory.mjs';
import { createDemoServer } from './serve-demo.mjs';

async function withBrowser(run, { reducedMotion = false } = {}) {
  const server = await createDemoServer({ port: 0 });
  const { port } = server.address();
  let browser;
  try {
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: chromeArgs({}) });
    const page = await browser.newPage();
    if (reducedMotion) await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
    const consoleErrors = [];
    page.on('console', (message) => { if (message.type() === 'error') consoleErrors.push(message.text()); });
    page.on('pageerror', (error) => consoleErrors.push(error.message));
    await run(page, `http://127.0.0.1:${port}`, consoleErrors);
  } finally {
    if (browser) await browser.close();
    await closeServer(server);
  }
}

test('initial state digest failure leaves no published operational state', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.evaluateOnNewDocument(() => { window.__operationalTestHooks = { failAt: 'digest', remaining: 1 }; });
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true || typeof window.__operationalError === 'string');
    const failure = await page.evaluate(() => ({
      alertCount: document.querySelectorAll('#load-error:not([hidden])').length,
      controlsDisabled: [...document.querySelectorAll('#controls button, #controls input')].every((control) => control.disabled),
      digest: document.body.dataset.stateDigest || '',
      error: window.__operationalError,
      gaps: document.querySelectorAll('#gap-list .gap').length,
      inspector: document.querySelector('#inspector').textContent,
      metadata: window.__operationalRendererMetadata,
      narration: document.querySelector('#narration-text').textContent,
      narrationSource: document.querySelector('#narration-source').textContent,
      ready: window.__operationalReady,
      rows: document.querySelectorAll('.event-row').length,
      sceneObjects: window.__operationalSceneObjects.length,
      time: document.querySelector('#time-readout').textContent,
      validation: document.body.dataset.validation,
      visuals: window.__operationalVisualObjects.length,
    }));
    assert.deepEqual(failure, {
      alertCount: 1,
      controlsDisabled: true,
      digest: '',
      error: failure.error,
      gaps: 0,
      inspector: '',
      metadata: null,
      narration: '',
      narrationSource: '',
      ready: false,
      rows: 0,
      sceneObjects: 0,
      time: '',
      validation: 'failed',
      visuals: 0,
    });
    assert.match(failure.error, /not ready/i);
    assert.ok(failure.error.length <= 340);
    assert.deepEqual(consoleErrors, []);
  });
});

test('initial preparation failure also leaves no published operational state', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.evaluateOnNewDocument(() => { window.__operationalTestHooks = { failAt: 'prepare', remaining: 1 }; });
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof window.__operationalError === 'string');
    const failure = await page.evaluate(() => ({
      controlsDisabled: [...document.querySelectorAll('#controls button, #controls input')].every((control) => control.disabled),
      digest: document.body.dataset.stateDigest || '',
      metadata: window.__operationalRendererMetadata,
      ready: window.__operationalReady,
      rows: document.querySelectorAll('.event-row').length,
      sceneObjects: window.__operationalSceneObjects.length,
      visuals: window.__operationalVisualObjects.length,
    }));
    assert.deepEqual(failure, { controlsDisabled: true, digest: '', metadata: null, ready: false, rows: 0, sceneObjects: 0, visuals: 0 });
    assert.deepEqual(consoleErrors, []);
  });
});

test('initial commit failure removes partially attached WebGL objects', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.evaluateOnNewDocument(() => { window.__operationalTestHooks = { failAt: 'commit', remaining: 1 }; });
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true || typeof window.__operationalError === 'string');
    const failure = await page.evaluate(() => {
      const canvas = document.querySelector('#observatory');
      const gl = canvas.getContext('webgl2');
      const pixels = new Uint8Array(canvas.width * canvas.height * 4);
      gl.readPixels(0, 0, canvas.width, canvas.height, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
      let nonBackgroundPixels = 0;
      for (let offset = 0; offset < pixels.length; offset += 4) {
        if (pixels[offset] !== 13 || pixels[offset + 1] !== 18 || pixels[offset + 2] !== 16 || pixels[offset + 3] !== 255) nonBackgroundPixels += 1;
      }
      return {
        controlsDisabled: [...document.querySelectorAll('#controls button, #controls input')].every((control) => control.disabled),
        nonBackgroundPixels,
        ready: window.__operationalReady,
        rows: document.querySelectorAll('.event-row').length,
        sceneObjects: window.__operationalSceneObjects.length,
      };
    });
    assert.deepEqual(failure, { controlsDisabled: true, nonBackgroundPixels: 0, ready: false, rows: 0, sceneObjects: 0 });
    assert.deepEqual(consoleErrors, []);
  });
});

test('ready playback, scrub, restart, and direct-frame failures share the clearing transition', { timeout: 90_000 }, async () => {
  for (const mode of ['playback', 'scrub', 'restart', 'direct-frame']) {
    await withBrowser(async (page, origin, consoleErrors) => {
      await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => window.__operationalReady === true);
      await page.evaluate((selected) => { window.__operationalTestHooks = { failAt: selected === 'scrub' || selected === 'restart' ? 'prepare' : 'digest', remaining: 1 }; }, mode);
      if (mode === 'playback') await page.click('#play');
      else if (mode === 'scrub') await page.$eval('#scrub', (input) => { input.value = '500000'; input.dispatchEvent(new Event('input', { bubbles: true })); });
      else if (mode === 'restart') await page.click('#restart');
      else {
        const rejected = await page.evaluate(async () => {
          try { await window.OPERATIONAL_RENDER_FRAME(30, 30); return false; } catch { return true; }
        });
        assert.equal(rejected, true);
      }
      await page.waitForFunction(() => typeof window.__operationalError === 'string');
      const failure = await page.evaluate(() => ({
        alertCount: document.querySelectorAll('#load-error:not([hidden])').length,
        controlsDisabled: [...document.querySelectorAll('#controls button, #controls input')].every((control) => control.disabled),
        digest: document.body.dataset.stateDigest || '',
        gaps: document.querySelectorAll('#gap-list .gap').length,
        inspector: document.querySelector('#inspector').textContent,
        metadata: window.__operationalRendererMetadata,
        narration: document.querySelector('#narration-text').textContent,
        narrationSource: document.querySelector('#narration-source').textContent,
        playing: document.querySelector('#play').getAttribute('aria-pressed'),
        ready: window.__operationalReady,
        rows: document.querySelectorAll('.event-row').length,
        sceneObjects: window.__operationalSceneObjects.length,
        time: document.querySelector('#time-readout').textContent,
        visuals: window.__operationalVisualObjects.length,
      }));
      assert.deepEqual(failure, {
        alertCount: 1, controlsDisabled: true, digest: '', gaps: 0, inspector: '', metadata: null,
        narration: '', narrationSource: '', playing: 'false', ready: false, rows: 0, sceneObjects: 0, time: '', visuals: 0,
      }, mode);
      await page.click('#debug-toggle');
      assert.equal(await page.$eval('#debug-toggle', (button) => button.getAttribute('aria-pressed')), 'false');
      assert.deepEqual(consoleErrors, [], mode);
    });
  }
});

test('operational mode renders only verified source-linked deterministic state', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    const requests = [];
    page.on('request', (request) => requests.push(request.url()));
    await page.goto(`${origin}/operational.html?frame=0`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true);
    await page.setOfflineMode(true);
    const offlineEvidence = await page.evaluate(() => window.OPERATIONAL_RENDER_FRAME(0, 30));
    await page.setOfflineMode(false);
    assert.match(offlineEvidence.stateDigest, /^sha256:[0-9a-f]{64}$/);
    const snapshot = await page.evaluate(async () => {
      const atEnd = await window.OPERATIONAL_RENDER_FRAME(300, 30);
      const atStart = await window.OPERATIONAL_RENDER_FRAME(0, 30);
      const atEndAgain = await window.OPERATIONAL_RENDER_FRAME(300, 30);
      document.querySelector('.event-row').click();
      return {
        atEnd, atStart, atEndAgain,
        authority: document.querySelector('#authority').textContent,
        modeLabel: document.querySelector('#mode-status').textContent,
        canvasName: document.querySelector('canvas').getAttribute('aria-label'),
        controls: [...document.querySelectorAll('#controls button, #controls input')].map((item) => ({ disabled: item.disabled, id: item.id })),
        inspector: document.querySelector('#inspector').textContent,
        logRole: document.querySelector('#event-log').getAttribute('role'),
        mode: document.body.dataset.mode,
        rows: [...document.querySelectorAll('.event-row')].map((row) => ({ eventId: row.dataset.eventId, sourceIds: JSON.parse(row.dataset.sourceEventIds) })),
        renderer: {
          engine: window.__operationalRendererMetadata.engine,
          renderCount: window.__operationalRendererMetadata.renderCount,
          revision: window.__operationalRendererMetadata.revision,
          vendorPath: window.__operationalRendererMetadata.vendorPath,
          webgl: window.__operationalRendererMetadata.webgl,
        },
        resourcesBefore: window.__operationalRendererMetadata.resourceCounts,
        stateStyles: window.__operationalRendererMetadata.stateStyles,
        sceneObjects: window.__operationalSceneObjects.map((object) => ({
          eventId: object.userData.eventId,
          frozenIds: Object.isFrozen(object.userData.sourceEventIds),
          sourceEventIds: object.userData.sourceEventIds,
          state: object.userData.state,
          type: object.type,
        })),
        visualSources: window.__operationalVisualObjects.map((object) => object.sourceEventIds),
      };
    });
    assert.equal(snapshot.mode, 'operational-verified');
    assert.match(snapshot.authority, /projection receipt and input commitment verified/i);
    assert.match(snapshot.authority, /not cryptographically re-verified/i);
    assert.equal(snapshot.modeLabel, 'VERIFIED OPERATIONAL LIFELINE · 46 CAPTURED EVENTS · SIX GATEWAYS · FIVE PROVIDERS');
    assert.equal(snapshot.modeLabel.includes('TWO-EVENT CONTRACT FIXTURE'), false);
    assert.match(snapshot.canvasName, /verified operational event observatory/i);
    assert.equal(snapshot.logRole, 'log');
    assert.equal(snapshot.controls.some(({ disabled, id }) => disabled && id !== 'play'), false);
    assert.ok(snapshot.inspector.includes(snapshot.rows[0].eventId));
    assert.ok(snapshot.rows.every((row) => row.sourceIds.length === 1 && row.sourceIds[0] === row.eventId));
    assert.ok(snapshot.visualSources.every((ids) => ids.length > 0));
    assert.deepEqual(snapshot.renderer, {
      engine: 'Three.js',
      renderCount: snapshot.renderer.renderCount,
      revision: '169',
      vendorPath: '/vendor/three.module.min.js',
      webgl: true,
    });
    assert.deepEqual(snapshot.stateStyles, {
      completed: { color: '#87d5a0', shape: 'icosahedron' },
      control: { color: '#65c7ff', shape: 'octahedron' },
      failure: { color: '#ff4f64', shape: 'octahedron' },
      gap: { color: '#ffd45d', shape: 'triangle' },
      restricted: { color: '#ff7654', shape: 'square' },
      transition: { color: '#c6a7ff', shape: 'tetrahedron' },
      verified: { color: '#87d5a0', shape: 'icosahedron' },
    });
    assert.ok(snapshot.resourcesBefore.geometries <= snapshot.sceneObjects.length + 3);
    assert.ok(snapshot.sceneObjects.length > 2);
    assert.ok(snapshot.sceneObjects.every(({ eventId, frozenIds, sourceEventIds, state }) => frozenIds && sourceEventIds.length === 1 && sourceEventIds[0] === eventId && ['verified', 'completed', 'control', 'failure', 'restricted', 'transition'].includes(state)));
    assert.deepEqual(snapshot.atEnd, snapshot.atEndAgain);
    assert.notEqual(snapshot.atStart.stateDigest, snapshot.atEnd.stateDigest);
    assert.ok(requests.every((url) => new URL(url).origin === origin));
    assert.deepEqual([...new Set(requests.map((url) => new URL(url).pathname))].sort(), [
      '/fixtures/operational-lifeline-v1/actors.json',
      '/fixtures/operational-lifeline-v1/browser-bootstrap.json',
      '/fixtures/operational-lifeline-v1/editorial.json',
      '/fixtures/operational-lifeline-v1/package.jsonl',
      '/fixtures/operational-lifeline-v1/receipt.json',
      '/operational-app.mjs',
      '/operational-observatory.mjs',
      '/operational.css',
      '/operational.html',
      '/vendor/three.module.min.js',
    ]);
    assert.equal(requests.some((url) => url.endsWith('/lifeline.trace.jsonl')), false);
    assert.deepEqual(consoleErrors, []);
  });
});

test('failure and restriction facts survive into distinct source-linked browser semantics', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.goto(`${origin}/operational.html?frame=1380`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true);
    const observed = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('.event-row')].map((row) => ({
        eventId: row.dataset.eventId,
        state: row.dataset.status,
        text: row.textContent,
      }));
      return { rows, sceneStates: window.__operationalSceneObjects.map(({ userData }) => userData.state) };
    });
    const packageRecords = (await readFile(new URL('./fixtures/operational-lifeline-v1/package.jsonl', import.meta.url), 'utf8')).trimEnd().split('\n').slice(1).map(JSON.parse);
    const rowsById = new Map(observed.rows.map((row) => [row.eventId, row]));
    const required = new Map([
      ['event-5', 'primary-outage-observed'], ['event-6', 'primary-stream-failed'],
      ['event-7', 'cancel-requested'], ['event-10', 'cancel-confirmed'],
      ['event-8', 'late-output-fenced'], ['event-11', 'sibling-completed'],
      ['event-14', 'fallback-selected'], ['event-15', 'fallback-submitted'],
      ['event-16', 'fallback-completed'], ['event-19', 'scenario-completed'],
    ]);
    for (const [sourceId, kind] of required) {
      const record = packageRecords.find(({ interactionId }) => interactionId === sourceId);
      assert.equal(record.sourceFacts.failureKind, kind);
      assert.match(rowsById.get(record.eventId).text, new RegExp(kind.replaceAll('-', ' '), 'i'));
    }
    const restricted = packageRecords.filter((record) => record.sourceFacts?.fieldRestrictions?.length);
    assert.equal(restricted.length, 5);
    assert.ok(restricted.every((record) => record.subjectId === null && rowsById.get(record.eventId).state === 'restricted' && /source identifier unavailable/i.test(rowsById.get(record.eventId).text)));
    assert.ok(observed.sceneStates.includes('failure'));
    assert.ok(observed.sceneStates.includes('control'));
    assert.ok(observed.sceneStates.includes('transition'));
    assert.deepEqual(consoleErrors, []);
  });
});

test('operational mode starts validating and never ships the stale contract-fixture label', async () => {
  const source = await readFile(new URL('./operational.html', import.meta.url), 'utf8');
  assert.match(source, /id="mode-status">VALIDATING PINNED OPERATIONAL PACKAGE…</);
  assert.equal(source.includes('TWO-EVENT CONTRACT FIXTURE'), false);
  assert.equal(source.includes('NOT A SIX-ORGANIZATION RUN'), false);
});

test('WebGL scene selection inspects the exact immutable source event', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.goto(`${origin}/operational.html?frame=1320`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true);
    const target = await page.evaluate(() => {
      const visual = window.__operationalVisualObjects.find(({ bounds }) => bounds?.width > 0);
      return { eventId: visual.eventId, x: visual.bounds.x + visual.bounds.width / 2, y: visual.bounds.y + visual.bounds.height / 2 };
    });
    const box = await page.$eval('#observatory', (canvas) => {
      const value = canvas.getBoundingClientRect();
      return { left: value.left, top: value.top, width: value.width, height: value.height, backingWidth: canvas.width, backingHeight: canvas.height };
    });
    await page.mouse.click(box.left + target.x * box.width / box.backingWidth, box.top + target.y * box.height / box.backingHeight);
    const inspected = await page.$eval('#inspector', (node) => node.textContent);
    assert.equal(JSON.parse(inspected).eventId, target.eventId);
    assert.deepEqual(consoleErrors, []);
  });
});

test('checked Chrome evidence matches portable state and environment-bound pixels', { timeout: 45_000 }, async () => {
  const evidenceUrl = new URL('./evidence/operational-lifeline-chrome152-linux.json', import.meta.url);
  const evidence = JSON.parse(await readFile(evidenceUrl));
  assert.equal(evidence.capture.frame, 1380);
  assert.equal(evidence.capture.renderer.engine, 'Three.js');
  assert.equal(evidence.capture.renderer.revision, '169');
  assert.equal(evidence.capture.renderer.vendorSha256, 'f7cee3c7533449a1505cc12cb5128b89e3d4fd3d7ea62b05f9f5464a217472ee');
  assert.ok(evidence.contributingEventIds.length >= 40);
  const checkedPng = await readFile(new URL(evidence.artifact, evidenceUrl));
  assert.equal(createHash('sha256').update(checkedPng).digest('hex'), evidence.pngSha256);
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.setViewport({ width: evidence.capture.width, height: evidence.capture.height, deviceScaleFactor: evidence.capture.deviceScaleFactor });
    await page.goto(`${origin}/operational.html?frame=0`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true);
    const state = await page.evaluate(([frame, fps]) => window.OPERATIONAL_RENDER_FRAME(frame, fps), [evidence.capture.frame, evidence.capture.fps]);
    assert.equal(state.stateDigest, evidence.stateDigest);
    assert.deepEqual(state.contributingEventIds, evidence.contributingEventIds);
    const freshPng = await page.screenshot({ type: 'png' });
    assert.equal(createHash('sha256').update(freshPng).digest('hex'), evidence.pngSha256);
    assert.deepEqual(consoleErrors, []);
  });
});

test('operational mode rejects the two-event contract fixture as its production default', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.setRequestInterception(true);
    page.on('request', async (request) => {
      const match = /\/fixtures\/operational-lifeline-v1\/([^/?]+)$/.exec(request.url());
      if (match) {
        const body = await readFile(new URL(`./fixtures/operational-observatory-v1/${match[1]}`, import.meta.url));
        await request.respond({ status: 200, body });
      } else await request.continue();
    });
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof window.__operationalError === 'string');
    const state = await page.evaluate(() => ({ error: window.__operationalError, ready: window.__operationalReady, rows: document.querySelectorAll('.event-row').length }));
    assert.equal(state.ready, false);
    assert.equal(state.rows, 0);
    assert.match(state.error, /complete six-gateway LIFELINE capture/);
    assert.deepEqual(consoleErrors, []);
  });
});

test('operational mode rejects a coherent three-event production substitution', { timeout: 45_000 }, async () => {
  const fixture = new URL('./fixtures/operational-lifeline-v1/', import.meta.url);
  const packageValues = (await readFile(new URL('package.jsonl', fixture), 'utf8')).trimEnd().split('\n').map(JSON.parse).slice(0, 4);
  const keptIds = new Set(packageValues.slice(1).map(({ eventId }) => eventId));
  const actorIds = new Set(packageValues.slice(1).map(({ actorId }) => actorId));
  const actors = JSON.parse(await readFile(new URL('actors.json', fixture)));
  actors.actors = actors.actors.filter(({ actorId }) => actorIds.has(actorId));
  const actorBytes = Buffer.from(canonicalJson(actors));
  const editorial = JSON.parse(await readFile(new URL('editorial.json', fixture)));
  editorial.entries = editorial.entries.filter(({ eventId }) => keptIds.has(eventId));
  const editorialBytes = Buffer.from(canonicalJson(editorial));
  packageValues[0].actorManifestDigest = await protocolHash('operational-actor-manifest', actorBytes);
  packageValues[0].editorialOverlayDigest = await protocolHash('operational-editorial-overlay', editorialBytes);
  const sourceFacts = packageValues.slice(1).map(({ sourceFacts: facts }) => facts).filter(Boolean).sort((a, b) => a.eventId.localeCompare(b.eventId));
  packageValues[0].sourceFactsDigest = await protocolHash('operational-source-facts', Buffer.from(canonicalJson({ entries: sourceFacts, schemaVersion: 'operational-observatory-source-facts/1' })));
  const packageBytes = Buffer.from(`${packageValues.map(canonicalJson).join('\n')}\n`);
  const receipt = JSON.parse(await readFile(new URL('receipt.json', fixture)));
  receipt.outputByteLength = String(packageBytes.byteLength);
  receipt.outputDigest = await protocolHash('operational-observatory-output', packageBytes);
  const replacements = new Map([
    ['actors.json', actorBytes],
    ['editorial.json', editorialBytes],
    ['package.jsonl', packageBytes],
    ['receipt.json', Buffer.from(canonicalJson(receipt))],
  ]);
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.setRequestInterception(true);
    page.on('request', async (request) => {
      const name = /\/fixtures\/operational-lifeline-v1\/([^/?]+)$/.exec(request.url())?.[1];
      if (replacements.has(name)) await request.respond({ status: 200, body: replacements.get(name) });
      else await request.continue();
    });
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof window.__operationalError === 'string');
    const state = await page.evaluate(() => ({ error: window.__operationalError, ready: window.__operationalReady, rows: document.querySelectorAll('.event-row').length }));
    assert.equal(state.ready, false);
    assert.equal(state.rows, 0);
    assert.match(state.error, /production fixture commitment/);
    assert.deepEqual(consoleErrors, []);
  });
});

test('coherent receipt and bootstrap substitutions cannot replace pinned production commitments', { timeout: 90_000 }, async () => {
  const fixture = new URL('./fixtures/operational-lifeline-v1/', import.meta.url);
  const base = Object.fromEntries(await Promise.all(['package.jsonl', 'receipt.json', 'browser-bootstrap.json'].map(async (name) => [name, await readFile(new URL(name, fixture))])));
  for (const mutation of ['inputDigest', 'runSeal', 'duration']) {
    const packageValues = base['package.jsonl'].toString().trimEnd().split('\n').map(JSON.parse);
    const receipt = JSON.parse(base['receipt.json']);
    const bootstrap = JSON.parse(base['browser-bootstrap.json']);
    if (mutation === 'inputDigest') {
      const changed = `sha256:${'a'.repeat(64)}`;
      receipt.inputDigest = changed; bootstrap.expectedInputDigest = changed;
    } else if (mutation === 'runSeal') {
      const changed = `sha256:${'b'.repeat(64)}`;
      packageValues[0].inputRunSeal = changed; bootstrap.expectedRunSeal = changed;
      const packageBytes = Buffer.from(`${packageValues.map(canonicalJson).join('\n')}\n`);
      receipt.outputByteLength = String(packageBytes.byteLength);
      receipt.outputDigest = await protocolHash('operational-observatory-output', packageBytes);
      base.packageMutation = packageBytes;
    } else bootstrap.finalDurationNs = '47000000000';
    const replacements = new Map([
      ['package.jsonl', base.packageMutation || base['package.jsonl']],
      ['receipt.json', Buffer.from(canonicalJson(receipt))],
      ['browser-bootstrap.json', Buffer.from(canonicalJson(bootstrap))],
    ]);
    await withBrowser(async (page, origin, consoleErrors) => {
      await page.setRequestInterception(true);
      page.on('request', async (request) => {
        const name = /\/fixtures\/operational-lifeline-v1\/([^/?]+)$/.exec(request.url())?.[1];
        if (replacements.has(name)) await request.respond({ status: 200, body: replacements.get(name) });
        else await request.continue();
      });
      await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => typeof window.__operationalError === 'string');
      const failure = await page.evaluate(() => ({
        controlsDisabled: [...document.querySelectorAll('#controls button, #controls input')].every((control) => control.disabled),
        ready: window.__operationalReady,
        rows: document.querySelectorAll('.event-row').length,
        sceneObjects: window.__operationalSceneObjects.length,
      }));
      assert.deepEqual(failure, { controlsDisabled: true, ready: false, rows: 0, sceneObjects: 0 });
      assert.deepEqual(consoleErrors, []);
    });
    delete base.packageMutation;
  }
});

test('tampered operational package stays not-ready with bounded error and no partial visuals', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.setRequestInterception(true);
    page.on('request', async (request) => {
      if (request.url().endsWith('/package.jsonl')) {
        const original = await readFile(new URL('./fixtures/operational-lifeline-v1/package.jsonl', import.meta.url));
        await request.respond({ status: 200, contentType: 'application/x-ndjson', body: Buffer.from(original.toString().replace('"mergeIndex":"1"', '"mergeIndex":"2"')) });
      } else await request.continue();
    });
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof window.__operationalError === 'string');
    const failure = await page.evaluate(() => ({
      controlsDisabled: [...document.querySelectorAll('#controls button, #controls input')].every((control) => control.disabled),
      error: document.querySelector('#load-error').textContent,
      ready: window.__operationalReady,
      rows: document.querySelectorAll('.event-row').length,
      validation: document.body.dataset.validation,
      visuals: window.__operationalVisualObjects.length,
      sceneObjects: window.__operationalSceneObjects.length,
      modeLabel: document.querySelector('#mode-status').textContent,
    }));
    assert.equal(failure.ready, false);
    assert.equal(failure.validation, 'failed');
    assert.equal(failure.controlsDisabled, true);
    assert.equal(failure.rows, 0);
    assert.equal(failure.visuals, 0);
    assert.equal(failure.sceneObjects, 0);
    assert.equal(failure.modeLabel, 'OPERATIONAL PACKAGE NOT READY');
    assert.ok(failure.error.length <= 340);
    assert.match(failure.error, /not ready/i);
    assert.deepEqual(consoleErrors, []);
  });
});

test('reduced motion stops automatic advance while scrub, cues, and keyboard inspection remain exact', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true);
    const initial = await page.evaluate(() => ({
      digest: document.body.dataset.stateDigest,
      motion: document.body.dataset.motion,
      playDisabled: document.querySelector('#play').disabled,
      time: document.querySelector('#time-readout').textContent,
      renderCount: window.__operationalRendererMetadata.renderCount,
    }));
    assert.deepEqual(initial, { digest: initial.digest, motion: 'reduced', playDisabled: true, time: '0 ns', renderCount: initial.renderCount });
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.$eval('#time-readout', (node) => node.textContent), '0 ns');
    assert.equal(await page.evaluate(() => window.__operationalRendererMetadata.renderCount), initial.renderCount);
    await page.$eval('#scrub', (input) => { input.value = '500000'; input.dispatchEvent(new Event('input', { bubbles: true })); });
    await page.waitForFunction(() => document.querySelector('#time-readout').textContent !== '0 ns');
    const sought = await page.evaluate(() => ({
      cue: document.querySelector('#narration-text').textContent,
      source: document.querySelector('#narration-source').textContent,
      valueText: document.querySelector('#scrub').getAttribute('aria-valuetext'),
    }));
    assert.match(sought.cue, /^Captured source event:/);
    assert.match(sought.source, /^SOURCE sha256:[0-9a-f]{64} · \[/);
    assert.equal(sought.valueText, '23000000000 ns');
    await page.click('#restart');
    assert.equal(await page.$eval('#narration-text', (node) => node.textContent), 'No cue at this time.');
    const firstEventId = await page.$eval('.event-row', (row) => row.dataset.eventId);
    await page.focus('canvas'); await page.keyboard.press('Enter');
    const keyboardInspection = await page.$eval('#inspector', (node) => node.textContent);
    assert.ok(keyboardInspection.includes(firstEventId));
    assert.deepEqual(consoleErrors, []);
  }, { reducedMotion: true });
});

test('operational canvas, log, controls, and event distinctions expose accessible semantics', { timeout: 45_000 }, async () => {
  await withBrowser(async (page, origin, consoleErrors) => {
    await page.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__operationalReady === true);
    const client = await page.createCDPSession();
    const tree = await client.send('Accessibility.getFullAXTree');
    const roles = tree.nodes.map((node) => ({ name: node.name?.value || '', role: node.role?.value || '' }));
    assert.ok(roles.some(({ name, role }) => role === 'image' && /verified operational event observatory/i.test(name)));
    assert.ok(roles.some(({ role }) => role === 'log'));
    assert.ok(roles.some(({ name, role }) => role === 'button' && name === 'PLAY'));
    const semantics = await page.evaluate(() => {
      const contrast = (foreground, background) => {
        const rgb = (color) => color.match(/[\d.]+/g).slice(0, 3).map(Number).map((part) => { const unit = part / 255; return unit <= .04045 ? unit / 12.92 : ((unit + .055) / 1.055) ** 2.4; });
        const luminance = ([r, g, b]) => .2126 * r + .7152 * g + .0722 * b;
        const [light, dark] = [luminance(rgb(foreground)), luminance(rgb(background))].sort((a, b) => b - a);
        return (light + .05) / (dark + .05);
      };
      const row = document.querySelector('.event-row'); const style = getComputedStyle(row);
      return {
        accessibility: document.body.dataset.accessibility,
        contrast: contrast(style.color, style.backgroundColor),
        glyph: row.querySelector('.status').textContent.slice(0, 1),
        status: row.querySelector('.status').textContent,
      };
    });
    assert.equal(semantics.accessibility, 'canvas-log-controls');
    assert.ok(semantics.contrast >= 4.5);
    assert.equal(semantics.glyph, '▸');
    assert.match(semantics.status, /transition.*sibling submitted/i);
    await page.focus('#debug-toggle'); await page.keyboard.press('Enter');
    assert.equal(await page.$eval('#debug-toggle', (button) => button.getAttribute('aria-pressed')), 'true');
    assert.deepEqual(consoleErrors, []);
  });
});
