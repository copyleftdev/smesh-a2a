#!/usr/bin/env node
import { readFile, readdir, readlink, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import puppeteer from 'puppeteer-core';
import { chromeArgs } from './export-utils.mjs';
import { createDemoServer, securityHeaders } from './serve-demo.mjs';
import { cleanupQualification, createRequestSettlement } from './operational-request-boundary.mjs';
import {
  EXPECTED_OPERATIONAL_ARTIFACTS,
  buildCoherentSyntheticSubstitution,
  verifyCompleteOperationalInputSet,
} from './operational-qualification-inputs.mjs';

async function completeSyntheticInputs() {
  const root = new URL('./fixtures/operational-lifeline-v1/', import.meta.url);
  const rootEntries = await readdir(root, { withFileTypes: true });
  const expectedRoot = [...new Set(EXPECTED_OPERATIONAL_ARTIFACTS.map(({ path }) => path.split('/')[0])), 'README.md'].sort();
  const actualRoot = rootEntries.map(({ name }) => name).sort();
  if (JSON.stringify(actualRoot) !== JSON.stringify(expectedRoot)
      || rootEntries.some((entry) => entry.name === 'restricted' ? !entry.isDirectory() : !entry.isFile())) {
    throw new Error('synthetic probe requires the exact 18-artifact input set');
  }
  const restrictedEntries = await readdir(new URL('restricted/', root), { withFileTypes: true });
  const expectedRestricted = EXPECTED_OPERATIONAL_ARTIFACTS
    .filter(({ path }) => path.startsWith('restricted/'))
    .map(({ path }) => path.slice('restricted/'.length))
    .sort();
  if (restrictedEntries.some((entry) => !entry.isFile())
      || JSON.stringify(restrictedEntries.map(({ name }) => name).sort()) !== JSON.stringify(expectedRestricted)) {
    throw new Error('synthetic probe requires the exact 18-artifact input set');
  }
  const files = new Map(await Promise.all(EXPECTED_OPERATIONAL_ARTIFACTS.map(async ({ path }) => [
    path,
    new Uint8Array(await readFile(new URL(path, root))),
  ])));
  if (process.env.SMESH_QUALIFICATION_OMIT_ARTIFACT) files.delete(process.env.SMESH_QUALIFICATION_OMIT_ARTIFACT);
  return files;
}

const plantedStderr = process.env.SMESH_QUALIFICATION_PLANTED_STDERR;
if (plantedStderr) {
  process.stderr.write(plantedStderr);
  throw new Error('planted browser diagnostic failure');
}

const BROWSER_ASSET_DESCRIPTORS = new Map([
  ['/operational.html', ['operational.html', 'text/html; charset=utf-8']],
  ['/operational.css', ['operational.css', 'text/css; charset=utf-8']],
  ['/operational-app.mjs', ['operational-app.mjs', 'text/javascript; charset=utf-8']],
  ['/operational-observatory.mjs', ['operational-observatory.mjs', 'text/javascript; charset=utf-8']],
  ['/vendor/three.module.min.js', ['vendor/three.module.min.js', 'text/javascript; charset=utf-8']],
  ['/fixtures/operational-lifeline-v1/package.jsonl', ['fixtures/operational-lifeline-v1/package.jsonl', 'application/x-ndjson']],
  ['/fixtures/operational-lifeline-v1/receipt.json', ['fixtures/operational-lifeline-v1/receipt.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/actors.json', ['fixtures/operational-lifeline-v1/actors.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/editorial.json', ['fixtures/operational-lifeline-v1/editorial.json', 'application/json']],
  ['/fixtures/operational-lifeline-v1/browser-bootstrap.json', ['fixtures/operational-lifeline-v1/browser-bootstrap.json', 'application/json']],
]);

async function repositoryBrowserAssets(syntheticFiles = null) {
  const assets = new Map(await Promise.all([...BROWSER_ASSET_DESCRIPTORS].map(async ([path, [relativeFile, contentType]]) => [
    path,
    { body: await readFile(new URL(relativeFile, import.meta.url)), contentType },
  ])));
  if (syntheticFiles) {
    for (const [artifactPath, body] of syntheticFiles) {
      const path = `/fixtures/operational-lifeline-v1/${artifactPath}`;
      const asset = assets.get(path);
      if (asset) assets.set(path, { ...asset, body });
    }
  }
  return assets;
}

const server = await createDemoServer({ port: 0 });
const { port } = server.address();
const origin = `http://127.0.0.1:${port}`;
const deniedRequests = [];
const deniedSameOriginRequests = [];
const requestSettlements = [];
let nodeListenerBrowserRequests = 0;
server.on('request', () => { nodeListenerBrowserRequests += 1; });
async function ownRequests(page, syntheticFiles = null) {
  const assets = await repositoryBrowserAssets(syntheticFiles);
  await page.setRequestInterception(true);
  requestSettlements.push(createRequestSettlement(page, async (request) => {
    const url = new URL(request.url());
    if (url.origin !== origin) {
      deniedRequests.push(request.url());
      await request.abort('blockedbyclient');
      return;
    }
    const asset = assets.get(url.pathname);
    if (!asset) {
      deniedSameOriginRequests.push(url.pathname);
      await request.abort('blockedbyclient');
      return;
    }
    await request.respond({
      status: 200,
      contentType: asset.contentType,
      headers: securityHeaders(url.pathname),
      body: asset.body,
    });
  }));
}
let browser;
try {
  const userDataDir = process.env.SMESH_QUALIFICATION_BROWSER_PROFILE;
  if (!userDataDir) throw new Error('Rust-owned browser profile is required');
  browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, pipe: true, userDataDir, args: chromeArgs({ qualificationOffline: 'true', unsafeNoSandbox: 'true' }) });
  if (process.env.SMESH_QUALIFICATION_LIFECYCLE_MARKER) {
    const browserProcess = browser.process();
    await writeFile(process.env.SMESH_QUALIFICATION_LIFECYCLE_MARKER, JSON.stringify({
      browserPid: browserProcess?.pid ?? null,
      listenerSocket: process.platform === 'linux'
        ? await readlink(`/proc/self/fd/${server._handle.fd}`)
        : null,
      nodePid: process.pid,
      ownedRoots: JSON.parse(process.env.SMESH_QUALIFICATION_LIFECYCLE_OWNED_ROOTS ?? '[]'),
      port,
      profileArgument: process.env.SMESH_QUALIFICATION_LIFECYCLE_REPORTED_PROFILE
        ? `--user-data-dir=${process.env.SMESH_QUALIFICATION_LIFECYCLE_REPORTED_PROFILE}`
        : browserProcess?.spawnargs.find((argument) => argument.startsWith('--user-data-dir=')) ?? null,
    }), { flag: 'wx', mode: 0o600 });
  }
  if (process.env.SMESH_QUALIFICATION_FORCE_BROWSER_HANG === '1') {
    await new Promise(() => {});
  }
  const page = await browser.newPage();
  await ownRequests(page);
  const requests = [];
  page.on('request', (request) => requests.push(request.url()));
  const documentResponse = await page.goto(`${origin}/operational.html?frame=0`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await page.waitForFunction(() => window.__operationalReady === true, { timeout: 30_000 });
  const expectedDocumentHeaders = securityHeaders('/operational.html');
  const documentHeaders = documentResponse.headers();
  if (Object.entries(expectedDocumentHeaders).some(([name, value]) => documentHeaders[name] !== value)) throw new Error('intercepted document security headers mismatch');
  await page.setOfflineMode(true);
  const state = await page.evaluate(() => window.OPERATIONAL_RENDER_FRAME(0, 30));
  await page.setOfflineMode(false);
  const egress = await browser.newPage();
  await ownRequests(egress);
  const externalSucceeded = await egress.evaluate(async () => {
    try { await fetch('https://qualification-egress.invalid/planted'); return true; } catch { return false; }
  });
  await egress.close();
  if (externalSucceeded || !deniedRequests.some((url) => url.startsWith('https://qualification-egress.invalid/planted'))) throw new Error('owned egress boundary did not bite');
  const unknown = await browser.newPage();
  await ownRequests(unknown);
  let unknownSameOriginAborted = false;
  try {
    await unknown.goto(`${origin}/qualification-route-not-owned`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  } catch {
    unknownSameOriginAborted = true;
  }
  await unknown.close();
  if (!unknownSameOriginAborted || !deniedSameOriginRequests.includes('/qualification-route-not-owned')) throw new Error('unknown same-origin route did not fail closed');
  const sameOriginRequests = requests.filter((url) => new URL(url).origin === origin);
  const paths = [...new Set(sameOriginRequests.map((url) => new URL(url).pathname))].sort();
  const expectedPaths = [
    '/fixtures/operational-lifeline-v1/actors.json',
    '/fixtures/operational-lifeline-v1/browser-bootstrap.json',
    '/fixtures/operational-lifeline-v1/editorial.json',
    '/fixtures/operational-lifeline-v1/package.jsonl',
    '/fixtures/operational-lifeline-v1/receipt.json',
    '/operational-app.mjs', '/operational-observatory.mjs', '/operational.css',
    '/operational.html', '/vendor/three.module.min.js',
  ].sort();
  if (JSON.stringify(paths) !== JSON.stringify(expectedPaths)) throw new Error('request allowlist mismatch');

  const synthetic = await browser.newPage();
  const originalSyntheticFiles = await completeSyntheticInputs();
  const verifiedInputSet = await verifyCompleteOperationalInputSet(originalSyntheticFiles);
  const substitution = await buildCoherentSyntheticSubstitution(originalSyntheticFiles, verifiedInputSet);
  const syntheticFiles = substitution.files;
  await ownRequests(synthetic, syntheticFiles);
  await synthetic.goto(`${origin}/operational.html`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
  await synthetic.waitForFunction(() => typeof window.__operationalError === 'string', { timeout: 30_000 });
  const rejection = await synthetic.evaluate(() => ({ error: window.__operationalError, ready: window.__operationalReady, rows: document.querySelectorAll('.event-row').length }));
  if (rejection.ready !== false || rejection.rows !== 0 || !rejection.error.includes('production fixture commitment')) throw new Error('synthetic fixture did not reach profile mismatch');
  const syntheticCompleteInputSet = verifiedInputSet.artifacts.length === 18
    && verifiedInputSet.inputSetDigest === substitution.inputSetDigest
    && substitution.eventCount === 46;
  await Promise.all([page.close(), synthetic.close()]);
  await Promise.all(requestSettlements.map((settlement) => settlement.settle()));
  if (nodeListenerBrowserRequests !== 0) throw new Error('browser reached the Node listener');
  const evidence = { attemptKinds: ['browserExternalFetch'], nodeListenerBrowserRequests: String(nodeListenerBrowserRequests), offlineRendered: true, requestPaths: paths, sameOriginOnly: true, stateDigest: state.stateDigest, syntheticCompleteInputSet, syntheticRejected: true, syntheticSemanticRejected: true, unknownSameOriginAborted };
  const bytes = Buffer.from(JSON.stringify(evidence));
  process.stdout.write(JSON.stringify({ evidence, evidenceDigest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, schemaVersion: 'operational-browser-qualification/1' }));
} finally {
  await cleanupQualification({ browser, requestSettlements, server });
}
