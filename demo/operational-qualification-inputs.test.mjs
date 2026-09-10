import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  EXPECTED_OPERATIONAL_ARTIFACTS,
  buildCoherentSyntheticSubstitution,
  verifyCompleteOperationalInputSet,
} from './operational-qualification-inputs.mjs';

async function fixtureInputs() {
  return new Map(await Promise.all(EXPECTED_OPERATIONAL_ARTIFACTS.map(async ({ path }) => [
    path,
    new Uint8Array(await readFile(new URL(`./fixtures/operational-lifeline-v1/${path}`, import.meta.url))),
  ])));
}

test('all eighteen public and restricted artifacts are mandatory synthetic inputs', async () => {
  const complete = await fixtureInputs();
  assert.equal((await verifyCompleteOperationalInputSet(complete)).artifacts.length, 18);
  const restricted = EXPECTED_OPERATIONAL_ARTIFACTS.filter(({ path }) => path.startsWith('restricted/'));
  assert.equal(restricted.length, 12);
  for (const { path } of EXPECTED_OPERATIONAL_ARTIFACTS) {
    const omitted = new Map(complete);
    omitted.delete(path);
    await assert.rejects(verifyCompleteOperationalInputSet(omitted), {
      name: 'Error',
      message: 'synthetic probe requires the exact 18-artifact input set',
    });
  }
});

test('coherent 46-event substitution is bound to the verified complete input set', async () => {
  const complete = await fixtureInputs();
  const verified = await verifyCompleteOperationalInputSet(complete);
  const substitution = await buildCoherentSyntheticSubstitution(complete, verified);
  assert.equal(substitution.eventCount, 46);
  assert.match(substitution.inputSetDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(substitution.files.size, 18);
  const packageText = new TextDecoder().decode(substitution.files.get('package.jsonl'));
  const header = JSON.parse(packageText.split('\n')[0]);
  assert.equal(header.runId, `lifeline-substituted-${substitution.inputSetDigest.slice(7, 19)}`);
  const receipt = JSON.parse(new TextDecoder().decode(substitution.files.get('receipt.json')));
  assert.notEqual(receipt.outputDigest, JSON.parse(new TextDecoder().decode(complete.get('receipt.json'))).outputDigest);
});

test('extra synthetic input is rejected', async () => {
  const inputs = await fixtureInputs();
  inputs.set('restricted/attacker-extra.json', new Uint8Array([123, 125]));
  await assert.rejects(verifyCompleteOperationalInputSet(inputs), /exact 18-artifact input set/);
});

test('operational browser probe emits no passing evidence when any input is omitted', () => {
  for (const { path } of EXPECTED_OPERATIONAL_ARTIFACTS) {
    const profile = mkdtempSync(join(tmpdir(), 'smesh-node-browser-profile-'));
    const result = spawnSync(process.execPath, ['operational-qualification.mjs'], {
      cwd: new URL('.', import.meta.url),
      encoding: 'utf8',
      env: {
        ...process.env,
        SMESH_QUALIFICATION_BROWSER_PROFILE: profile,
        SMESH_QUALIFICATION_OMIT_ARTIFACT: path,
      },
      timeout: 60_000,
    });
    rmSync(profile, { recursive: true, force: true });
    assert.equal(result.error, undefined, path);
    assert.equal(result.status, 1, path);
    assert.equal(result.stdout, '', path);
    assert.match(result.stderr, /exact 18-artifact input set/, path);
  }
});
