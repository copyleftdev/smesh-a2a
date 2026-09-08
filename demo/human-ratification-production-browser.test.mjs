import assert from 'node:assert/strict';
import { createSign, randomBytes, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import puppeteer from 'puppeteer-core';

const ROOT = resolve(import.meta.dirname, '..');
const BIN = join(ROOT, 'target/debug/smesh-a2a-gateway');
const TLS = join(ROOT, 'tests/fixtures/tls');
const JWT_KEY = join(ROOT, 'tests/fixtures/issue12-test-private.pem');
const RSA_N = 'p26N-Nwoj5-nUmncx2MHcT01-VCtp6LLQaOPv6tFIE4J3GS6Acccllk_QqMUamBnfwzgFErmBznMY8MfqZUM1-HNd_9GgvlJHIJUbYrU5Jbn1QnkY51GW5L4BXpyMeovuTPOjyKuAgRuAlaRI0W8JjZXGZt6stPFyofx-wZLT5eM0_ppclD-jJUQ_yt5tmkidf7SeXE7zDt8eg1aR2wolmhYfVzELkPRLYF4mLcMWXK7eV5Oc9L_u4NobVqAMlFX309TALcS_zrs7EbY9aB7m75RAhLjhPw8F-f_CLpvw5XMQ9OACg5NDqXEfTQUzHf9GWIHCC8JmJufvAn9jJI04Q';
const WATCHDOG = 10_000;

function b64url(value) { return Buffer.from(value).toString('base64url'); }
function jwt(issuer, subject, canary) {
  const now = Math.floor(Date.now() / 1000);
  const encoded = [
    b64url(JSON.stringify({ alg: 'RS256', kid: 'browser-key', typ: 'at+jwt' })),
    b64url(JSON.stringify({ iss: issuer, sub: subject, aud: 'smesh-browser', exp: now + 300, nbf: now - 1, iat: now - 1, client_id: 'browser-client', jti: canary })),
  ];
  const signer = createSign('RSA-SHA256'); signer.update(encoded.join('.')); signer.end();
  return `${encoded.join('.')}.${signer.sign(readFileSync(JWT_KEY)).toString('base64url')}`;
}
async function freePort() {
  const server = createNetServer();
  await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok); });
  const port = server.address().port;
  await new Promise((ok, no) => server.close(error => error ? no(error) : ok()));
  return port;
}
async function oidcFixture() {
  const requests = [];
  const server = createHttpsServer({ key: readFileSync(join(TLS, 'server.key')), cert: readFileSync(join(TLS, 'server.pem')) }, (req, res) => {
    requests.push(req.url);
    if (req.url !== '/jwks') { res.writeHead(404).end(); return; }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=300' });
    res.end(JSON.stringify({ keys: [{ kty: 'RSA', kid: 'browser-key', use: 'sig', alg: 'RS256', n: RSA_N, e: 'AQAB' }] }));
  });
  await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok); });
  const issuer = `https://localhost:${server.address().port}`;
  return { issuer, requests, close: () => new Promise((ok, no) => server.close(error => error ? no(error) : ok())) };
}
function waitExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise(resolve => {
    const exited = () => resolve();
    child.once('exit', exited);
    if (child.exitCode !== null || child.signalCode !== null) {
      child.off('exit', exited);
      resolve();
    }
  });
}
function policy(issuer, subject) {
  return JSON.stringify({ schemaVersion: 'smesh-authz-policy/v1', policyId: 'browser-production', revision: 1,
    tenants: [{ id: 'tenant-browser', enabled: true }],
    accounts: [{ id: 'browser-human', kind: 'human', memberships: [{ tenantId: 'tenant-browser', roles: ['humanRatifier', 'taskViewer'] }] }],
    principalBindings: [{ principal: { issuer, subject }, accountId: 'browser-human' }] });
}
function seed(root, database, key, policyPath, issuer, subject, taskId) {
  const result = spawnSync(BIN, ['test-seed-ratification'], { cwd: ROOT, encoding: 'utf8', timeout: WATCHDOG,
    env: { PATH: process.env.PATH ?? '', SMESH_TEST_RATIFICATION_SEED_SQLITE_PATH: database,
      SMESH_TEST_RATIFICATION_SEED_KEY_PATH: key, SMESH_TEST_RATIFICATION_SEED_POLICY_PATH: policyPath,
      SMESH_TEST_RATIFICATION_SEED_ISSUER: issuer, SMESH_TEST_RATIFICATION_SEED_SUBJECT: subject,
      SMESH_TEST_RATIFICATION_SEED_TASK_ID: taskId, SMESH_TEST_RATIFICATION_SEED_AUTHENTICATION: 'bearer-jwt' } });
  assert.equal(result.status, 0, `seed failed: ${result.stderr.replaceAll(root, '[root]')}`);
}
async function gateway(root, database, key, policyPath, issuer, port) {
  const env = { PATH: process.env.PATH ?? '', RUST_LOG: 'info', SSL_CERT_FILE: join(TLS, 'server-ca.pem'),
    SMESH_A2A_AUTH_MODE: 'oidc', SMESH_A2A_OIDC_ISSUER: issuer, SMESH_A2A_OIDC_AUDIENCE: 'smesh-browser',
    SMESH_A2A_OIDC_JWKS_URI: `${issuer}/jwks`, SMESH_A2A_MODE: 'loopback', SMESH_A2A_BIND: `127.0.0.1:${port}`,
    SMESH_A2A_PUBLIC_URL: `http://127.0.0.1:${port}`, SMESH_A2A_DURABLE_BACKEND: 'sqlite',
    SMESH_A2A_SQLITE_PATH: database, SMESH_A2A_RATIFICATION_HMAC_KEY_PATH: key,
    SMESH_A2A_AUTHORIZATION_POLICY_PATH: policyPath, SMESH_A2A_TRANSPORT_MODE: 'loopback-plain',
    SMESH_A2A_CLIENT_AUTH_MODE: 'disabled', SMESH_TEST_RATIFICATION_AMEND_CANDIDATE: '1' };
  const child = spawn(BIN, [], { cwd: ROOT, env, stdio: ['ignore', 'ignore', 'pipe'] });
  let logs = ''; child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { logs += chunk; });
  await new Promise((ok, no) => {
    const timer = setTimeout(() => no(new Error(`gateway readiness timeout: ${logs.replaceAll(root, '[root]')}`)), WATCHDOG);
    const inspect = () => { if (logs.includes('gateway listening')) { clearTimeout(timer); ok(); } };
    child.stderr.on('data', inspect); child.once('exit', code => { clearTimeout(timer); no(new Error(`gateway exited ${code}: ${logs.replaceAll(root, '[root]')}`)); }); inspect();
  }).catch(async error => { child.kill('SIGKILL'); await waitExit(child); throw error; });
  return { child, base: `http://127.0.0.1:${port}`, logs: () => logs, stop: async () => {
    if (child.exitCode === null) child.kill('SIGTERM');
    await Promise.race([waitExit(child), new Promise((_, no) => setTimeout(() => no(new Error('gateway stop timeout')), WATCHDOG))])
      .catch(async error => { child.kill('SIGKILL'); await waitExit(child); throw error; });
  } };
}
function copyTls(root) {
  const output = join(root, 'tls'); mkdirSync(output);
  for (const name of ['server.pem', 'server.key', 'server-ca.pem', 'client-ca.pem', 'client.pem', 'client.key', 'principals.json']) copyFileSync(join(TLS, name), join(output, name));
  chmodSync(join(output, 'server.key'), 0o600); chmodSync(join(output, 'client.key'), 0o600);
  return output;
}
function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: WATCHDOG });
  assert.equal(result.status, 0, `${command} failed: ${result.stderr}`);
}
function chromeHome(root, tls, includeClient) {
  const home = join(root, includeClient ? 'chrome-client' : 'chrome-no-client');
  const nss = join(home, '.pki', 'nssdb'); mkdirSync(nss, { recursive: true });
  run('certutil', ['-N', '--empty-password', '-d', `sql:${nss}`]);
  run('certutil', ['-A', '-d', `sql:${nss}`, '-n', 'task-server-ca', '-t', 'C,,', '-i', join(tls, 'server-ca.pem')]);
  if (includeClient) {
    const password = randomBytes(24).toString('hex'); const bundle = join(root, 'client.p12');
    run('openssl', ['pkcs12', '-export', '-inkey', join(tls, 'client.key'), '-in', join(tls, 'client.pem'), '-certfile', join(tls, 'client-ca.pem'), '-out', bundle, '-passout', `pass:${password}`]);
    run('pk12util', ['-i', bundle, '-d', `sql:${nss}`, '-W', password]); rmSync(bundle, { force: true });
  }
  return home;
}
async function mtlsGateway(root, database, key, policyPath, tls, port) {
  const env = { PATH: process.env.PATH ?? '', RUST_LOG: 'info', SMESH_A2A_AUTH_MODE: 'disabled', SMESH_A2A_CLIENT_AUTH_MODE: 'required',
    SMESH_A2A_MODE: 'loopback', SMESH_A2A_BIND: `127.0.0.1:${port}`, SMESH_A2A_PUBLIC_URL: `https://localhost:${port}`,
    SMESH_A2A_DURABLE_BACKEND: 'sqlite', SMESH_A2A_SQLITE_PATH: database, SMESH_A2A_RATIFICATION_HMAC_KEY_PATH: key,
    SMESH_A2A_AUTHORIZATION_POLICY_PATH: policyPath, SMESH_A2A_TRANSPORT_MODE: 'direct-tls', SMESH_A2A_TLS_CERT_PATH: join(tls, 'server.pem'),
    SMESH_A2A_TLS_KEY_PATH: join(tls, 'server.key'), SMESH_A2A_TLS_CLIENT_CA_PATH: join(tls, 'client-ca.pem'), SMESH_A2A_TLS_PRINCIPAL_MAP_PATH: join(tls, 'principals.json') };
  const child = spawn(BIN, [], { cwd: ROOT, env, stdio: ['ignore', 'ignore', 'pipe'] }); let logs = '';
  child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { logs += chunk; });
  await new Promise((ok, no) => { const timer = setTimeout(() => no(new Error(`mTLS readiness timeout: ${logs.replaceAll(root, '[root]')}`)), WATCHDOG);
    child.stderr.on('data', () => { if (logs.includes('gateway listening')) { clearTimeout(timer); ok(); } }); child.once('exit', code => { clearTimeout(timer); no(new Error(`mTLS gateway exited ${code}`)); });
  }).catch(async error => { child.kill('SIGKILL'); await waitExit(child); throw error; });
  return { child, base: `https://localhost:${port}`, logs: () => logs, stop: async () => { if (child.exitCode === null) child.kill('SIGTERM'); await Promise.race([waitExit(child), new Promise((_, no) => setTimeout(() => no(new Error('mTLS stop timeout')), WATCHDOG))]).catch(async error => { child.kill('SIGKILL'); await waitExit(child); throw error; }); } };
}
async function load(page, base, taskId, token) {
  await page.goto(`${base}/ratification/console`, { waitUntil: 'domcontentloaded', timeout: WATCHDOG });
  await page.evaluate(({ taskId, token }) => {
    document.querySelector('#task').value = taskId;
    document.querySelector('#tenant').value = 'tenant-browser';
    document.querySelector('#token').value = token;
    document.querySelector('#bootstrap').requestSubmit();
  }, { taskId, token });
  await page.waitForSelector('#ack-uncertainty', { timeout: WATCHDOG });
}
async function acknowledge(page) { await page.evaluate(() => { for (const box of document.querySelectorAll('#review-items input[type=checkbox]')) box.click(); }); }
function sqliteValue(database, sql) {
  const result = spawnSync('sqlite3', [database, sql], { encoding: 'utf8', timeout: WATCHDOG });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
async function waitForSqliteValue(database, sql, expected, label) {
  const deadline = Date.now() + WATCHDOG;
  let actual = sqliteValue(database, sql);
  while (actual !== expected && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 25));
    actual = sqliteValue(database, sql);
  }
  assert.equal(actual, expected, `${label} did not reach its exact durable barrier`);
}
async function assertSuppressedPublicSurfaces(page, base, token, taskId, database) {
  const headers = { authorization: `Bearer ${token}`, 'x-smesh-tenant': 'tenant-browser' };
  const ratification = await fetch(`${base}/ratification/v1/tasks/${taskId}`, { headers });
  assert.equal(ratification.status, 200);
  await ratification.arrayBuffer();
  const rest = await fetch(`${base}/rest/tasks/${taskId}`, { headers });
  assert.equal(rest.status, 200);
  const rpc = await jsonrpc(base, token, 'GetTask', { id: taskId });
  const surfaces = [
    ['rest', await rest.text()],
    ['jsonrpc', JSON.stringify(rpc)],
    ['dom', await page.content()],
    ['durable-public', sqliteValue(database, `SELECT group_concat(value,'') FROM (
      SELECT task_json AS value FROM tasks WHERE task_id='${taskId}'
      UNION ALL SELECT event_json FROM task_events WHERE task_id='${taskId}'
      UNION ALL SELECT payload_json FROM outbox WHERE task_id='${taskId}'
      UNION ALL SELECT payload_json FROM receiver_inbox WHERE task_id='${taskId}'
      UNION ALL SELECT COALESCE(termination_json,'') FROM receiver_inbox WHERE task_id='${taskId}'
      UNION ALL SELECT frame_json FROM stream_frames WHERE message_id='message-${taskId}'
    );`)],
  ];
  for (const [name, surface] of surfaces) {
    assert.equal(surface.includes('sealed candidate'), false, `${name} exposed sealed artifact content`);
    assert.equal(surface.includes('candidate ready'), false, `${name} exposed suppressed candidate result`);
  }
}
function scanFiles(root, forbidden) {
  const paths = readdirSync(root).filter(name => name.includes('.sqlite3')).map(name => join(root, name));
  for (const path of paths) { const bytes = readFileSync(path); for (const value of forbidden) assert.equal(bytes.includes(Buffer.from(value)), false, `canary leaked to ${path}`); }
}
async function jsonrpc(base, token, method, params) {
  const response = await fetch(`${base}/jsonrpc`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'x-smesh-tenant': 'tenant-browser' }, body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method, params }) });
  assert.equal(response.status, 200); return response.json();
}

test('real production binary bearer console records all decisions, restarts stable terminals, and recovers stale tabs', { timeout: 60_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'smesh-browser-production-')); chmodSync(root, 0o700);
  const keyCanary = `key-${randomUUID()}`.padEnd(32, 'k').slice(0, 32);
  const pathCanary = `path-${randomUUID()}`;
  const bearerCanary = `bearer-${randomUUID()}`;
  const key = join(root, pathCanary); writeFileSync(key, keyCanary); chmodSync(key, 0o600);
  let oidc; let running; let browser;
  try {
    oidc = await oidcFixture(); const subject = 'browser-subject';
    const policyPath = join(root, 'policy.json'); writeFileSync(policyPath, policy(oidc.issuer, subject));
    const database = join(root, 'approve.sqlite3'); const taskId = 'task-browser-approve'; seed(root, database, key, policyPath, oidc.issuer, subject, taskId);
    const token = jwt(oidc.issuer, subject, bearerCanary); const port = await freePort(); running = await gateway(root, database, key, policyPath, oidc.issuer, port).catch(error => { error.message = `initial: ${error.message}`; throw error; });
    const errors = []; const wire = [];
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const page = await browser.newPage(); page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); }); page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => wire.push({ url: request.url(), method: request.method(), headers: request.headers(), body: request.postData() ?? '' }));
    await load(page, running.base, taskId, token); await acknowledge(page); await page.click('#review-submit');
    await page.waitForFunction(() => document.querySelector('#status').dataset.state !== 'REVIEW_SUBMITTING', { timeout: WATCHDOG });
    assert.equal(await page.$eval('#status', node => `${node.dataset.state}:${node.textContent}`), 'REVIEWED:Review recorded. Choose a decision.');
    await page.waitForFunction(() => !document.querySelector('#approve').disabled, { timeout: WATCHDOG }); await page.type('#rationale', 'approved in real Chromium'); await page.click('#approve');
    await page.waitForFunction(() => document.querySelector('#status').dataset.state !== 'DECISION_SUBMITTING', { timeout: WATCHDOG });
    assert.equal(await page.$eval('#status', node => `${node.dataset.state}:${node.textContent}`), 'TERMINAL:Decision recorded.');
    const residue = await page.evaluate(() => ({ url: location.href, dom: document.documentElement.outerHTML, local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
    assert.equal(residue.url, `${running.base}/ratification/console`); assert.equal(residue.dom.includes(token), false); assert.deepEqual(residue.local, []); assert.deepEqual(residue.session, []); assert.deepEqual(errors, []);
    for (const item of wire) { assert.equal(item.url.includes(token), false); assert.equal(item.body.includes(token), false); assert.equal(JSON.stringify(item.headers).includes(keyCanary), false); assert.equal(JSON.stringify(item.headers).includes(pathCanary), false); }
    assert.ok(wire.some(item => item.headers.authorization === `Bearer ${token}`));

    const clearDb = join(root, 'clear-bearer.sqlite3'); const clearTask = 'task-browser-clear-bearer'; seed(root, clearDb, key, policyPath, oidc.issuer, subject, clearTask);
    await running.stop(); running = undefined;
    const clearPort = await freePort(); running = await gateway(root, clearDb, key, policyPath, oidc.issuer, clearPort);
    const clearPage = await browser.newPage(); const clearWire = [];
    clearPage.on('request', request => clearWire.push({ url: request.url(), method: request.method(), headers: request.headers() }));
    await load(clearPage, running.base, clearTask, token);
    assert.equal(await clearPage.$eval('#review-surface', node => node.hidden), false);
    await clearPage.type('#token', 'x');
    assert.equal(await clearPage.$eval('#review-surface', node => node.hidden), true);
    await clearPage.$eval('#token', node => { node.value = ''; });
    const beforeEmptySubmit = clearWire.length;
    await clearPage.$eval('#bootstrap', form => form.requestSubmit());
    await clearPage.waitForFunction(() => document.querySelector('#status').dataset.state === 'AUTH_LOCKED', { polling: 'mutation', timeout: WATCHDOG });
    const afterEmptySubmit = clearWire.slice(beforeEmptySubmit);
    const emptyGet = afterEmptySubmit.find(item => item.method === 'GET' && item.url.endsWith(`/tasks/${clearTask}`));
    assert.ok(emptyGet); assert.equal(Object.hasOwn(emptyGet.headers, 'authorization'), false);
    assert.equal(afterEmptySubmit.some(item => item.url.endsWith('/review') || item.url.endsWith('/decision')), false);
    assert.equal(await clearPage.$$eval('#review-submit,#approve,#reject,#amend', buttons => buttons.every(button => button.disabled)), true);
    assert.equal(await clearPage.$eval('#review-surface', node => node.hidden), true);
    await clearPage.close();

    const firstLogs = running.logs(); await running.stop(); running = undefined;
    assert.equal(firstLogs.includes(token), false); assert.equal(firstLogs.includes(keyCanary), false); assert.equal(firstLogs.includes(pathCanary), false); scanFiles(root, [token, keyCanary, pathCanary]);
    running = await gateway(root, database, key, policyPath, oidc.issuer, port).catch(error => { error.message = `restart: ${error.message}`; throw error; });
    const terminal = await fetch(`${running.base}/ratification/v1/tasks/${taskId}`, { headers: { authorization: `Bearer ${token}`, 'x-smesh-tenant': 'tenant-browser' } });
    assert.equal(terminal.status, 200); const terminalView = await terminal.json(); assert.equal(terminalView.terminalDecision, 'approve'); assert.equal(terminalView.history.length, 2);
    const task = await jsonrpc(running.base, token, 'GetTask', { id: taskId }); assert.ok(task.result, JSON.stringify(task)); assert.equal(task.result.status.state, 'TASK_STATE_COMPLETED');

    for (const [decision, expectedTaskState] of [['reject', 'TASK_STATE_REJECTED'], ['amend', 'TASK_STATE_INPUT_REQUIRED']]) {
      await running.stop(); running = undefined; await browser.close(); browser = undefined;
      const decisionDb = join(root, `${decision}.sqlite3`); const decisionTask = `task-browser-${decision}`; seed(root, decisionDb, key, policyPath, oidc.issuer, subject, decisionTask);
      const decisionPort = await freePort(); running = await gateway(root, decisionDb, key, policyPath, oidc.issuer, decisionPort).catch(error => { error.message = `${decision} initial: ${error.message}`; throw error; });
      browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
      const decisionPage = await browser.newPage(); await load(decisionPage, running.base, decisionTask, token); await acknowledge(decisionPage); await decisionPage.click('#review-submit');
      await decisionPage.waitForFunction(() => document.querySelector('#status').dataset.state === 'REVIEWED', { polling: 'mutation', timeout: WATCHDOG });
      const beforeDecision = await fetch(`${running.base}/ratification/v1/tasks/${decisionTask}`, { headers: { authorization: `Bearer ${token}`, 'x-smesh-tenant': 'tenant-browser' } });
      assert.equal(beforeDecision.status, 200);
      const beforeDecisionView = await beforeDecision.json();
      assert.equal(beforeDecisionView.packet.generation, 1);
      assert.equal(beforeDecisionView.terminalDecision, null);
      assert.equal(beforeDecisionView.history.length, 1);
      await decisionPage.type('#rationale', `${decision} in real Chromium`); await decisionPage.click(`#${decision}`);
      await decisionPage.waitForFunction(() => document.querySelector('#status').dataset.state === 'TERMINAL', { polling: 'mutation', timeout: WATCHDOG });
      let amendmentRevision;
      if (decision === 'amend') {
        await assertSuppressedPublicSurfaces(decisionPage, running.base, token, decisionTask, decisionDb);
        amendmentRevision = beforeDecisionView.packet.taskRevision + 1;
        const awaitingDelivery = await jsonrpc(running.base, token, 'GetTask', { id: decisionTask });
        assert.equal(awaitingDelivery.result.status.state, 'TASK_STATE_INPUT_REQUIRED');
        assert.equal(awaitingDelivery.result.artifacts == null, true);
      } else {
        const recorded = await fetch(`${running.base}/ratification/v1/tasks/${decisionTask}`, { headers: { authorization: `Bearer ${token}`, 'x-smesh-tenant': 'tenant-browser' } });
        assert.equal(recorded.status, 200, `${decision} live read`); const recordedView = await recorded.json(); assert.equal(recordedView.terminalDecision, decision); assert.equal(recordedView.history.length, 2);
        const decisionTaskView = await jsonrpc(running.base, token, 'GetTask', { id: decisionTask });
        assert.equal(decisionTaskView.result.status.state, expectedTaskState);
      }
      const decisionLogs = running.logs(); await running.stop(); running = undefined; await browser.close(); browser = undefined;
      assert.equal(decisionLogs.includes(token), false); assert.equal(decisionLogs.includes(keyCanary), false); assert.equal(decisionLogs.includes(pathCanary), false); scanFiles(root, [token, keyCanary, pathCanary]);
      running = await gateway(root, decisionDb, key, policyPath, oidc.issuer, decisionPort).catch(error => { error.message = `${decision} restart: ${error.message}`; throw error; });
      if (decision !== 'amend') {
        const persisted = await fetch(`${running.base}/ratification/v1/tasks/${decisionTask}`, { headers: { authorization: 'Bearer ' + token, 'x-smesh-tenant': 'tenant-browser' } });
        assert.equal(persisted.status, 200); const persistedView = await persisted.json(); assert.equal(persistedView.terminalDecision, decision); assert.equal(persistedView.history.length, 2);
      }
      browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
      if (decision === 'amend') {
        await waitForSqliteValue(
          decisionDb,
          `SELECT count(*)||':'||min(state)||':'||min(causative_revision)||':'||max(causative_revision) FROM outbox WHERE task_id='${decisionTask}' AND causative_revision=${amendmentRevision};`,
          `1:delivered:${amendmentRevision}:${amendmentRevision}`,
          'amendment outbox delivery after recovery',
        );
        const reopenedView = await fetch(`${running.base}/ratification/v1/tasks/${decisionTask}`, { headers: { authorization: `Bearer ${token}`, 'x-smesh-tenant': 'tenant-browser' } });
        assert.equal(reopenedView.status, 200);
        const generationTwo = await reopenedView.json();
        assert.equal(generationTwo.packet.generation, 2);
        assert.equal(generationTwo.phase, 'awaitingReview');
        assert.equal(generationTwo.terminalDecision, null);
        assert.equal(generationTwo.history.length, 0);
        const reopened = await browser.newPage();
        await reopened.setExtraHTTPHeaders({ authorization: `Bearer ${token}`, 'x-smesh-tenant': 'tenant-browser' });
        await reopened.goto(`${running.base}/rest/tasks/${decisionTask}`, { waitUntil: 'domcontentloaded', timeout: WATCHDOG });
        const persistedTask = await jsonrpc(running.base, token, 'GetTask', { id: decisionTask });
        assert.equal(persistedTask.result.status.state, 'TASK_STATE_INPUT_REQUIRED');
        assert.equal(persistedTask.result.artifacts == null, true);
        await assertSuppressedPublicSurfaces(reopened, running.base, token, decisionTask, decisionDb);
        await reopened.close();
      } else {
        const persistedTask = await jsonrpc(running.base, token, 'GetTask', { id: decisionTask }); assert.equal(persistedTask.result.status.state, expectedTaskState);
      }
    }

    if (running) { await running.stop(); running = undefined; }
    if (browser) { await Promise.race([browser.close(), new Promise((_, no) => setTimeout(() => no(new Error('browser close timeout')), WATCHDOG))]); browser = undefined; }
    const staleDb = join(root, 'stale.sqlite3'); const staleTask = 'task-browser-stale'; seed(root, staleDb, key, policyPath, oidc.issuer, subject, staleTask);
    const stalePort = await freePort(); running = await gateway(root, staleDb, key, policyPath, oidc.issuer, stalePort).catch(error => { error.message = `stale: ${error.message}`; throw error; });
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const first = await browser.newPage(); const second = await browser.newPage();
    const firstLoaded = first.waitForResponse(response => response.request().method() === 'GET' && response.url().endsWith(`/tasks/${staleTask}`), { timeout: WATCHDOG });
    const secondLoaded = second.waitForResponse(response => response.request().method() === 'GET' && response.url().endsWith(`/tasks/${staleTask}`), { timeout: WATCHDOG });
    await Promise.all([load(first, running.base, staleTask, token), load(second, running.base, staleTask, token)]);
    const [firstView, secondView] = await Promise.all([firstLoaded, secondLoaded]);
    assert.ok(firstView.headers().etag); assert.equal(secondView.headers().etag, firstView.headers().etag);
    await Promise.all([acknowledge(first), acknowledge(second)]);
    // The two response promises and acknowledgement promise are the explicit
    // barrier: both tabs rendered and acknowledged one ETag before mutation.
    const firstResponse = first.waitForResponse(response => response.url().endsWith('/review'), { timeout: WATCHDOG });
    await first.evaluate(() => document.querySelector('#review-submit').click());
    const completedReview = await firstResponse;
    assert.equal(completedReview.status(), 201);
    await first.waitForFunction(() => document.querySelector('#status').dataset.state !== 'REVIEW_SUBMITTING', { polling: 'mutation', timeout: WATCHDOG });
    assert.equal(await first.$eval('#status', node => `${node.dataset.state}:${node.textContent}`), 'REVIEWED:Review recorded. Choose a decision.');
    const staleResponse = second.waitForResponse(response => response.url().endsWith('/review'), { timeout: WATCHDOG });
    await second.evaluate(() => document.querySelector('#review-submit').click());
    assert.equal((await staleResponse).status(), 412);
    await second.waitForFunction(() => document.querySelector('#status').dataset.state === 'REVIEWED', { polling: 'mutation', timeout: WATCHDOG });
    assert.equal(await second.$$eval('#review-items input', boxes => boxes.every(box => !box.checked)), true); assert.equal(await second.$eval('#review-submit', button => button.disabled), true);
    assert.equal(await second.$eval('#approve', button => button.disabled), false);
    await second.type('#rationale', 'safe resume after stale reload');
    await second.click('#approve');
    await second.waitForFunction(() => document.querySelector('#status').dataset.state === 'TERMINAL', { polling: 'mutation', timeout: WATCHDOG });
  } catch (error) {
    if (process.env.SMESH_KEEP_BROWSER_FIXTURE === '1') error.message = `${error.message} fixture=${root}`;
    throw error;
  } finally {
    if (browser) await browser.close().catch(() => {}); if (running) await running.stop().catch(() => {}); if (oidc) await oidc.close().catch(() => {}); if (process.env.SMESH_KEEP_BROWSER_FIXTURE !== '1') rmSync(root, { recursive: true, force: true });
  }
});

test('real Chromium presents an exact-origin mTLS identity to the production binary', { timeout: 60_000 }, async t => {
  if (process.env.SMESH_CHROME_MTLS_POLICY_READY !== '1' || !process.env.SMESH_MTLS_BROWSER_PORT) {
    t.skip('requires a task-owned exact-origin AutoSelectCertificateForUrls Linux policy'); return;
  }
  const root = mkdtempSync(join(tmpdir(), 'smesh-browser-mtls-')); chmodSync(root, 0o700);
  const keyCanary = `mtls-${randomUUID()}`.padEnd(32, 'm').slice(0, 32); const pathCanary = `mtls-path-${randomUUID()}`;
  const key = join(root, pathCanary); writeFileSync(key, keyCanary); chmodSync(key, 0o600);
  let running; let browser;
  try {
    const tls = copyTls(root); const policyPath = join(root, 'policy.json'); writeFileSync(policyPath, policy('mtls:test', 'agent-17'));
    const database = join(root, 'mtls.sqlite3'); const taskId = 'task-browser-mtls';
    const seeded = spawnSync(BIN, ['test-seed-ratification'], { cwd: ROOT, encoding: 'utf8', timeout: WATCHDOG, env: { PATH: process.env.PATH ?? '',
      SMESH_TEST_RATIFICATION_SEED_SQLITE_PATH: database, SMESH_TEST_RATIFICATION_SEED_KEY_PATH: key, SMESH_TEST_RATIFICATION_SEED_POLICY_PATH: policyPath,
      SMESH_TEST_RATIFICATION_SEED_ISSUER: 'mtls:test', SMESH_TEST_RATIFICATION_SEED_SUBJECT: 'agent-17', SMESH_TEST_RATIFICATION_SEED_TASK_ID: taskId,
      SMESH_TEST_RATIFICATION_SEED_AUTHENTICATION: 'mutual-tls' } });
    assert.equal(seeded.status, 0, seeded.stderr.replaceAll(root, '[root]'));
    const port = Number(process.env.SMESH_MTLS_BROWSER_PORT); running = await mtlsGateway(root, database, key, policyPath, tls, port);
    const noClientHome = chromeHome(root, tls, false);
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, env: { ...process.env, HOME: noClientHome }, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const refused = await browser.newPage(); await assert.rejects(refused.goto(`${running.base}/ratification/console`, { timeout: WATCHDOG }), /ERR_BAD_SSL_CLIENT_AUTH_CERT|ERR_SSL_CLIENT_AUTH_CERT_NEEDED|net::ERR/);
    await browser.close(); browser = undefined;

    const clientHome = chromeHome(root, tls, true);
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, env: { ...process.env, HOME: clientHome },
      args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const page = await browser.newPage(); const requests = []; page.on('request', request => requests.push(request.headers()));
    await load(page, running.base, taskId, ''); await acknowledge(page); await page.click('#review-submit');
    await page.waitForFunction(() => document.querySelector('#status').dataset.state === 'REVIEWED', { polling: 'mutation', timeout: WATCHDOG });
    assert.equal(await page.$eval('#approve', button => button.disabled), false); await page.type('#rationale', 'mTLS Chromium decision'); await page.click('#approve');
    await page.waitForFunction(() => document.querySelector('#status').dataset.state === 'TERMINAL', { polling: 'mutation', timeout: WATCHDOG });
    assert.equal(requests.some(headers => Object.hasOwn(headers, 'authorization')), false);
    const beforeRestart = running.logs(); await running.stop(); running = undefined; await browser.close(); browser = undefined;
    assert.equal(beforeRestart.includes(keyCanary), false); assert.equal(beforeRestart.includes(pathCanary), false); scanFiles(root, [keyCanary, pathCanary]);
    running = await mtlsGateway(root, database, key, policyPath, tls, port);
    browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', headless: true, env: { ...process.env, HOME: clientHome },
      args: ['--no-sandbox', '--disable-dev-shm-usage'] });
    const reopened = await browser.newPage(); await load(reopened, running.base, taskId, '');
    assert.equal(await reopened.$eval('#status', node => node.dataset.state), 'TERMINAL');
  } finally {
    if (browser) await browser.close().catch(() => {}); if (running) await running.stop().catch(() => {}); rmSync(root, { recursive: true, force: true });
  }
});
