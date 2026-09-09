import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  canonicalJson,
  createOperationalProjector,
  digestProjectedState,
  loadVerifiedOperationalPackage,
  protocolHash,
} from './operational-observatory.mjs';

const fixture = new URL('./fixtures/operational-observatory-v1/', import.meta.url);

async function fixtureInputs() {
  const [packageBytes, receiptBytes, actorBytes, editorialBytes, bootstrapBytes] = await Promise.all([
    readFile(new URL('package.jsonl', fixture)),
    readFile(new URL('receipt.json', fixture)),
    readFile(new URL('actors.json', fixture)),
    readFile(new URL('editorial.json', fixture)),
    readFile(new URL('browser-bootstrap.json', fixture)),
  ]);
  return { packageBytes, receiptBytes, actorBytes, editorialBytes, bootstrapBytes };
}

async function productionInputs() {
  const root = new URL('./fixtures/operational-lifeline-v1/', import.meta.url);
  const [packageBytes, receiptBytes, actorBytes, editorialBytes, bootstrapBytes] = await Promise.all([
    readFile(new URL('package.jsonl', root)), readFile(new URL('receipt.json', root)),
    readFile(new URL('actors.json', root)), readFile(new URL('editorial.json', root)),
    readFile(new URL('browser-bootstrap.json', root)),
  ]);
  return { packageBytes, receiptBytes, actorBytes, editorialBytes, bootstrapBytes };
}

async function reboundInputs(inputs, mutate) {
  const values = inputs.packageBytes.toString().trimEnd().split('\n').map(JSON.parse);
  await mutate(values);
  const packageBytes = Buffer.from(`${values.map(canonicalJson).join('\n')}\n`);
  const receipt = JSON.parse(inputs.receiptBytes);
  receipt.outputByteLength = String(packageBytes.byteLength);
  receipt.outputDigest = await protocolHash('operational-observatory-output', packageBytes);
  return { ...inputs, packageBytes, receiptBytes: Buffer.from(canonicalJson(receipt)) };
}

async function relabeledInputs(inputs, { bytes, domain, field, inputKey }) {
  const changed = { ...inputs, [inputKey]: bytes };
  return reboundInputs(changed, async (values) => { values[0][field] = await protocolHash(domain, bytes); });
}

test('complete verified operational package is accepted and tampering fails closed', async () => {
  const inputs = await fixtureInputs();
  const verified = await loadVerifiedOperationalPackage(inputs);
  assert.equal(verified.ready, true);
  assert.equal(verified.records.length, 2);
  assert.equal(verified.receipt.projectorId, 'smesh-operational-observatory');
  assert.equal(verified.authority.upstreamRunSealCryptographicallyReverified, false);
  assert.match(verified.authority.label, /projection receipt and input commitment verified/i);

  for (const [field, mutate] of [
    ['packageBytes', (bytes) => Buffer.concat([bytes.subarray(0, -1)])],
    ['packageBytes', (bytes) => Buffer.from(bytes.toString().replace('"mergeIndex":"1"', '"mergeIndex":"2"'))],
    ['packageBytes', (bytes) => Buffer.from(bytes.toString().replace('"kind":"a2aSend"', '"kind":"invented"'))],
    ['receiptBytes', (bytes) => { const value = JSON.parse(bytes); value.outputByteLength = String(BigInt(value.outputByteLength) + 1n); return Buffer.from(canonicalJson(value)); }],
    ['actorBytes', (bytes) => Buffer.from(bytes.toString().replace('"displayName":"Alpha"', '"displayName":"Tampered"'))],
    ['editorialBytes', (bytes) => Buffer.from(bytes.toString().replace('Captured send.', 'Tampered text.'))],
    ['bootstrapBytes', (bytes) => Buffer.from(bytes.toString().replace('4fd03225', '0fd03225'))],
  ]) {
    const changed = { ...inputs, [field]: mutate(inputs[field]) };
    await assert.rejects(loadVerifiedOperationalPackage(changed), /operational package rejected/i);
  }
});

test('semantic package, actor, overlay, gap, order, and reference tampering fails after receipt rebinding', async () => {
  const inputs = await fixtureInputs();
  const source = inputs.packageBytes.toString().trimEnd().split('\n').map(JSON.parse);
  const [firstEventId, secondEventId] = source.slice(1).map(({ eventId }) => eventId);
  const packageMutations = [
    (values) => { values[1].parent = { eventId: secondEventId, kind: 'event' }; },
    (values) => { values[1].parent = { eventId: `sha256:${'f'.repeat(64)}`, kind: 'event' }; },
    (values) => { values[1].unknown = true; },
    (values) => { values[2].mergeIndex = '2'; },
    (values) => { values[2].eventId = firstEventId; },
    (values) => { values[1].runRelativeNs = '2'; },
    (values) => { values[1].kind = 'invented'; },
    (values) => { values[1].parent = { expectedEventId: `sha256:${'d'.repeat(64)}`, kind: 'missing', reason: 'invented' }; },
    (values) => { values.splice(1, 0, { children: [firstEventId], expectedEventId: `sha256:${'d'.repeat(64)}`, reason: 'ordinaryAbsence', recordId: `sha256:${'e'.repeat(64)}`, recordType: 'gap' }); },
    // A rebound receipt cannot turn an existing root/event child into a gap child.
    (values) => { values.splice(1, 0, { children: [firstEventId], expectedEventId: `sha256:${'d'.repeat(64)}`, reason: 'unresolvedAtSeal', recordId: `sha256:${'e'.repeat(64)}`, recordType: 'gap' }); },
    // Every claimed child must name this gap's exact missing parent.
    (values) => {
      values[2].parent = { expectedEventId: `sha256:${'c'.repeat(64)}`, kind: 'missing', reason: 'producerRestart' };
      values.splice(1, 0, { children: [secondEventId], expectedEventId: `sha256:${'d'.repeat(64)}`, reason: 'unresolvedAtSeal', recordId: `sha256:${'e'.repeat(64)}`, recordType: 'gap' });
    },
    // A child may be claimed by exactly one gap, even under distinct missing IDs.
    (values) => {
      values[2].parent = { expectedEventId: `sha256:${'c'.repeat(64)}`, kind: 'missing', reason: 'producerRestart' };
      values.splice(1, 0,
        { children: [secondEventId], expectedEventId: `sha256:${'c'.repeat(64)}`, reason: 'unresolvedAtSeal', recordId: `sha256:${'d'.repeat(64)}`, recordType: 'gap' },
        { children: [secondEventId], expectedEventId: `sha256:${'e'.repeat(64)}`, reason: 'unresolvedAtSeal', recordId: `sha256:${'f'.repeat(64)}`, recordType: 'gap' });
    },
    // One missing expected event has exactly one gap record, not disjoint duplicate definitions.
    (values) => {
      const expectedEventId = `sha256:${'c'.repeat(64)}`;
      values[1].parent = { expectedEventId, kind: 'missing', reason: 'producerRestart' };
      values[2].parent = { expectedEventId, kind: 'missing', reason: 'producerRestart' };
      values.splice(1, 0,
        { children: [firstEventId], expectedEventId, reason: 'unresolvedAtSeal', recordId: `sha256:${'d'.repeat(64)}`, recordType: 'gap' },
        { children: [secondEventId], expectedEventId, reason: 'unresolvedAtSeal', recordId: `sha256:${'e'.repeat(64)}`, recordType: 'gap' });
    },
  ];
  for (const mutate of packageMutations) await assert.rejects(loadVerifiedOperationalPackage(await reboundInputs(inputs, mutate)), /operational package rejected/i);

  const manifest = JSON.parse(inputs.actorBytes); manifest.actors[1].actorId = manifest.actors[0].actorId;
  const actorBytes = Buffer.from(canonicalJson(manifest));
  await assert.rejects(loadVerifiedOperationalPackage(await relabeledInputs(inputs, { bytes: actorBytes, domain: 'operational-actor-manifest', field: 'actorManifestDigest', inputKey: 'actorBytes' })), /actors conflict/i);

  const overlay = JSON.parse(inputs.editorialBytes); overlay.entries[0].eventId = `sha256:${'0'.repeat(64)}`;
  const editorialBytes = Buffer.from(canonicalJson(overlay));
  await assert.rejects(loadVerifiedOperationalPackage(await relabeledInputs(inputs, { bytes: editorialBytes, domain: 'operational-editorial-overlay', field: 'editorialOverlayDigest', inputKey: 'editorialBytes' })), /editorial reference/i);
});

test('gap expectedEventId cannot name a present package event after receipt rebinding', async () => {
  const inputs = await fixtureInputs();
  const source = inputs.packageBytes.toString().trimEnd().split('\n').map(JSON.parse);
  const [firstEventId, secondEventId] = source.slice(1).map(({ eventId }) => eventId);
  const rebound = await reboundInputs(inputs, (values) => {
    values[2].parent = { expectedEventId: firstEventId, kind: 'missing', reason: 'producerRestart' };
    values.splice(1, 0, {
      children: [secondEventId],
      expectedEventId: firstEventId,
      reason: 'unresolvedAtSeal',
      recordId: `sha256:${'e'.repeat(64)}`,
      recordType: 'gap',
    });
  });

  await assert.rejects(loadVerifiedOperationalPackage(rebound), /operational package rejected/i);
});

test('source facts reject rebound unknown enums, digest conflicts, and duplicate restrictions', async () => {
  const inputs = await productionInputs();
  const mutateFacts = async (values, mutate) => {
    mutate(values);
    const entries = values.slice(1).map(({ sourceFacts }) => sourceFacts).filter(Boolean).sort((a, b) => a.eventId.localeCompare(b.eventId));
    values[0].sourceFactsDigest = await protocolHash('operational-source-facts', Buffer.from(canonicalJson({ entries, schemaVersion: 'operational-observatory-source-facts/1' })));
  };
  const mutations = [
    (values) => { values.find(({ sourceFacts }) => sourceFacts?.failureKind).sourceFacts.failureKind = 'invented'; },
    (values) => { values.find(({ sourceFacts }) => sourceFacts?.failureKind).sourceFacts.outcome = 'completed'; },
    (values) => { values.find(({ sourceFacts }) => sourceFacts?.failureKind).sourceFacts.sourceSchemaVersion = 'unknown-source/1'; },
    (values) => { values.find(({ sourceFacts }) => sourceFacts?.failureKind).sourceFacts.sourceContentDigest = `sha256:${'e'.repeat(64)}`; },
    (values) => { const record = values.find(({ sourceFacts }) => sourceFacts?.fieldRestrictions?.length); record.sourceFacts.fieldRestrictions.push(structuredClone(record.sourceFacts.fieldRestrictions[0])); },
  ];
  for (const mutate of mutations) {
    await assert.rejects(loadVerifiedOperationalPackage(await reboundInputs(inputs, (values) => mutateFacts(values, mutate))), /operational package rejected/i);
  }
});

test('restricted records reject sourceFacts even with rebound manifests and receipt', async () => {
  const inputs = await fixtureInputs();
  const manifest = JSON.parse(inputs.actorBytes);
  const restrictedActor = manifest.actors[0];
  restrictedActor.visibility = 'restricted';
  const actorBytes = Buffer.from(canonicalJson(manifest));
  const overlay = JSON.parse(inputs.editorialBytes);
  overlay.entries = overlay.entries.filter(({ eventId }) => {
    const record = inputs.packageBytes.toString().trimEnd().split('\n').map(JSON.parse).find((candidate) => candidate.eventId === eventId);
    return record?.actorId !== restrictedActor.actorId;
  });
  const editorialBytes = Buffer.from(canonicalJson(overlay));
  const changed = { ...inputs, actorBytes, editorialBytes };
  const rebound = await reboundInputs(changed, async (values) => {
    values[0].actorManifestDigest = await protocolHash('operational-actor-manifest', actorBytes);
    values[0].editorialOverlayDigest = await protocolHash('operational-editorial-overlay', editorialBytes);
    const record = values.find(({ actorId }) => actorId === restrictedActor.actorId);
    for (const key of ['content', 'contextId', 'editorial', 'interactionId', 'peerId', 'subjectId', 'taskId']) delete record[key];
    record.recordType = 'restricted';
    record.restrictionReason = 'actorManifest';
  });

  await assert.rejects(loadVerifiedOperationalPackage(rebound), /operational package rejected/i);
});

test('all modes and non-monotonic seeks share immutable source-linked state', async () => {
  const verified = await loadVerifiedOperationalPackage(await fixtureInputs());
  const first = createOperationalProjector(verified);
  const second = createOperationalProjector(verified);
  const atStart = first.projectStateAt({ timeNs: '0' });
  const atEnd = first.projectStateAt({ timeNs: '1000000000' });
  const rewound = first.projectStateAt({ timeNs: '0' });
  const fresh = second.projectStateAt({ timeNs: '0' });
  assert.deepEqual(rewound, atStart);
  assert.deepEqual(fresh, atStart);
  assert.notEqual(await digestProjectedState(atStart), await digestProjectedState(atEnd));
  assert.equal(await digestProjectedState(atStart), await digestProjectedState(rewound));
  assert.deepEqual(first.projectStateForFrame(30, 30), atEnd);
  assert.deepEqual(atStart.contributingEventIds, [verified.records[0].eventId]);
  assert.deepEqual(atEnd.contributingEventIds, verified.records.map(({ eventId }) => eventId));
  assert.ok(atEnd.visuals.every((visual) => visual.sourceEventIds.length > 0));
  assert.ok(atEnd.rows.every((row) => row.sourceEventIds.length === 1));
  assert.deepEqual(atStart.narration, {
    cue: 'focus',
    endNsExclusive: '1',
    sourceEventId: verified.records[0].eventId,
    startNsInclusive: '0',
    text: 'Captured send.',
  });
  const justBeforeEnd = first.projectStateAt({ timeNs: '999999999' });
  assert.equal(justBeforeEnd.narration.sourceEventId, verified.records[1].eventId);
  assert.equal(justBeforeEnd.narration.endNsExclusive, '1000000000');
  assert.equal(atEnd.narration, null);
  assert.deepEqual(first.projectStateAt({ timeNs: '0' }), atStart);
  assert.deepEqual(first.projectStateAt({ timeNs: '999999999' }), justBeforeEnd);
  assert.equal(first.projectStateAt({ timeNs: '1000000000' }).narration, null);
  assert.throws(() => first.projectStateAt({ timeNs: '1000000001' }), /time/i);
  assert.throws(() => first.projectStateForFrame(-1, 30), /frame/i);
  const times = Array.from({ length: 64 }, (_, index) => String(BigInt((index * 48271) % 1_000_000) * 1000n));
  const forward = new Map();
  for (const timeNs of times) forward.set(timeNs, await digestProjectedState(first.projectStateAt({ timeNs })));
  for (const timeNs of [...times].reverse()) assert.equal(await digestProjectedState(second.projectStateAt({ timeNs })), forward.get(timeNs));
});

test('restricted and gap state uses explicit non-success labels and source IDs', () => {
  const eventId = `sha256:${'a'.repeat(64)}`;
  const missingId = `sha256:${'b'.repeat(64)}`;
  const fixtureState = Object.freeze({
    ready: true,
    bootstrap: { finalDurationNs: 10n },
    gaps: [{ children: [eventId], expectedEventId: missingId, reason: 'unresolvedAtSeal', recordId: `sha256:${'c'.repeat(64)}`, recordType: 'gap' }],
    records: [{ actorId: 'anonymous-actor', channel: 'a2a', eventId, kind: 'a2aSend', mergeIndex: '0', parent: { expectedEventId: missingId, kind: 'missing', reason: 'producerRestart' }, producer: { id: 'unknown', instanceId: 'unknown', kind: 'a2a', sourceSequence: '0' }, recordType: 'restricted', restrictionReason: 'actorManifest', runRelativeNs: '0', siteId: 'anonymous-site', timeNs: 0n }],
  });
  const state = createOperationalProjector(fixtureState).projectStateAt({ timeNs: '0' });
  assert.equal(state.rows[0].statusLabel, 'RESTRICTED — CONTENT NOT AVAILABLE');
  assert.equal(state.rows[0].glyph, '◆');
  assert.equal(state.gaps[0].statusLabel, 'GAP — UNRESOLVED AT VERIFIED SEAL');
  assert.equal(state.gaps[0].glyph, '△');
  assert.deepEqual(state.gaps[0].sourceEventIds, [eventId]);
  assert.equal(state.rows[0].actorLabel, 'Anonymous actor [anonymous-actor]');
  assert.equal(state.rows[0].siteLabel, 'Anonymous site [anonymous-site]');
});
