import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const fixture = new URL('./fixtures/full-matrix-replay-v1/', import.meta.url);
const bytes = (value) => Buffer.from(value, 'utf8');
const digest = (buffer) => `sha256:${createHash('sha256').update(buffer).digest('hex')}`;
const rawDigest = (value) => Buffer.from(value.slice(7), 'hex');
const u64be = (value) => { const buffer = Buffer.alloc(8); buffer.writeBigUInt64BE(BigInt(value)); return buffer; };
const framedRaw = (label, parts) => createHash('sha256').update(Buffer.concat([
  Buffer.from(`SMESH-A2A\0${label}\0v1\0`, 'ascii'),
  ...parts.flatMap((part) => [u64be(part.length), part]),
])).digest();
const framed = (label, parts) => `sha256:${framedRaw(label, parts).toString('hex')}`;
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
const validDigest = (value) => /^sha256:[0-9a-f]{64}$/.test(value);
const validIdentifier = (value) => typeof value === 'string' && value.length > 0 && value.length <= 256 && /^[A-Za-z0-9_.:/-]+$/.test(value);

function assertWellFormed(value) {
  if (typeof value !== 'string') return;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('lone high surrogate');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('lone low surrogate');
  }
}
function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') { assertWellFormed(value); return JSON.stringify(value); }
  if (typeof value === 'number' || typeof value === 'bigint') throw new Error('JSON numbers are forbidden');
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value);
  keys.forEach(assertWellFormed);
  keys.sort(); // ECMAScript compares UTF-16 code units, as RFC 8785 requires.
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function parseDecimal(value) {
  assert.match(value, /^(0|[1-9][0-9]*)$/);
  const parsed = BigInt(value);
  assert.ok(parsed <= 0xffffffffffffffffn);
  return parsed;
}
function assertNoNumbers(value) {
  if (typeof value === 'number') throw new Error('number');
  if (typeof value === 'string') assertWellFormed(value);
  if (Array.isArray(value)) value.forEach(assertNoNumbers);
  else if (value && typeof value === 'object') {
    Object.keys(value).forEach(assertWellFormed);
    Object.values(value).forEach(assertNoNumbers);
  }
}
function producerHash(causal) {
  const core = { event: causal.event, hlc: causal.hlc, lamport: causal.lamport, recordedDecision: causal.recordedDecision };
  const previous = causal.producerPrevious === null ? Buffer.alloc(32) : rawDigest(causal.producerPrevious);
  return framed('producer-chain', [previous, bytes(canonical(core))]);
}
function captureEventId(runId, event) {
  const producerKinds = { a2a: 'A2a', smesh: 'Smesh', tool: 'Tool', artifact: 'Artifact', human: 'Human' };
  const eventKinds = {
    a2aSend: 'A2aSend', a2aReceive: 'A2aReceive',
    smeshSignalEmitted: 'SmeshSignalEmitted', smeshSignalSent: 'SmeshSignalSent',
    smeshSignalReinforced: 'SmeshSignalReinforced', smeshSignalReceived: 'SmeshSignalReceived',
    smeshSignalExpired: 'SmeshSignalExpired', smeshTickCompleted: 'SmeshTickCompleted',
    smeshPeerConnected: 'SmeshPeerConnected', smeshPeerDisconnected: 'SmeshPeerDisconnected',
    toolCall: 'ToolCall', toolResult: 'ToolResult', toolFailed: 'ToolFailed',
    artifactProduced: 'ArtifactProduced', artifactConsumed: 'ArtifactConsumed',
    humanPrompt: 'HumanPrompt', humanDecision: 'HumanDecision', humanFailed: 'HumanFailed',
  };
  const missingReasons = {
    externalBoundary: 'ExternalBoundary',
    captureStartedLate: 'CaptureStartedLate',
    producerRestart: 'ProducerRestart',
  };
  const producer = event.producer;
  const parent = event.parent.kind === 'root' ? 'root'
    : event.parent.kind === 'event' ? `event:${event.parent.eventId}`
      : `missing:${event.parent.expectedEventId}:${missingReasons[event.parent.reason]}`;
  const identity = `${producerKinds[producer.kind]}\0${producer.id}\0${producer.instanceId}`;
  const preimage = `full-matrix-event/v1\0${runId}\0${identity}\0${producer.sourceSequence}\0${eventKinds[event.kind]}\0${event.interactionId}\0${event.peerId}\0${event.taskId ?? ''}\0${event.contextId ?? ''}\0${event.subjectId ?? ''}\0${parent}\0${event.content.digest}\0${event.content.byteLength}`;
  return digest(bytes(preimage));
}
function merkle(lines) {
  let nodes = lines.map((line) => framedRaw('merkle-leaf', [line]));
  while (nodes.length > 1) {
    const next = [];
    for (let index = 0; index < nodes.length; index += 2) {
      next.push(index + 1 === nodes.length ? nodes[index] : framedRaw('merkle-node', [nodes[index], nodes[index + 1]]));
    }
    nodes = next;
  }
  return `sha256:${nodes[0].toString('hex')}`;
}
function parseSource(buffer) {
  assert.equal(buffer.at(-1), 0x0a);
  assert.ok(buffer.length <= 16 * 1024 * 1024);
  const lines = buffer.subarray(0, -1).toString('utf8').split('\n');
  const values = lines.map((line) => {
    const value = JSON.parse(line);
    assertNoNumbers(value);
    assert.equal(line, canonical(value));
    return value;
  });
  const complete = values.pop();
  exactKeys(complete, ['eventCount', 'recordType', 'runId', 'schemaVersion']);
  assert.equal(complete.recordType, 'complete');
  assert.equal(complete.schemaVersion, 'full-matrix-causal-source/1');
  assert.equal(parseDecimal(complete.eventCount), BigInt(values.length));
  for (const record of values) {
    exactKeys(record, ['event', 'recordType', 'runId', 'schemaVersion']);
    assert.equal(record.recordType, 'causalEvent');
    assert.equal(record.schemaVersion, 'full-matrix-causal-source/1');
    assert.equal(record.runId, complete.runId);
    const causal = record.event;
    exactKeys(causal, ['event', 'hlc', 'lamport', 'producerHash', 'producerPrevious', 'recordedDecision']);
    const event = causal.event;
    exactKeys(event, ['content', 'contextId', 'eventId', 'interactionId', 'kind', 'parent', 'peerId', 'producer', 'sourceSequence', 'subjectId', 'taskId']);
    exactKeys(event.content, ['byteLength', 'digest']);
    exactKeys(event.producer, ['id', 'instanceId', 'kind', 'sourceSequence']);
    assert.ok(validIdentifier(event.interactionId) && validIdentifier(event.peerId));
    assert.ok(validIdentifier(event.producer.id) && validIdentifier(event.producer.instanceId));
    assert.ok(validDigest(event.content.digest) && validDigest(event.eventId));
    parseDecimal(event.content.byteLength); parseDecimal(event.sourceSequence);
    parseDecimal(event.producer.sourceSequence); parseDecimal(causal.hlc.physicalNs);
    parseDecimal(causal.hlc.logical); parseDecimal(causal.lamport);
    assert.equal(event.eventId, captureEventId(record.runId, event));
    assert.equal(causal.producerHash, producerHash(causal));
  }
  return { runId: complete.runId, events: values.map((record) => record.event) };
}
function merge(sources) {
  const runId = sources[0].runId;
  assert.ok(sources.every((source) => source.runId === runId));
  const byId = new Map();
  for (const event of sources.flatMap((source) => source.events)) {
    const id = event.event.eventId;
    if (byId.has(id)) assert.equal(canonical(byId.get(id)), canonical(event));
    else byId.set(id, event);
  }
  const indegree = new Map([...byId.keys()].map((id) => [id, 0]));
  const outgoing = new Map();
  const slots = new Map();
  for (const [id, causal] of byId) {
    const producer = causal.event.producer;
    const group = `${producer.kind}\0${producer.id}\0${producer.instanceId}`;
    slots.set(`${group}\0${producer.sourceSequence}`, id);
  }
  const addEdge = (parent, child) => {
    const children = outgoing.get(parent) ?? new Set();
    if (!children.has(child)) { children.add(child); indegree.set(child, indegree.get(child) + 1); }
    outgoing.set(parent, children);
  };
  for (const [id, causal] of byId) {
    const producer = causal.event.producer;
    const sequence = parseDecimal(producer.sourceSequence);
    const group = `${producer.kind}\0${producer.id}\0${producer.instanceId}`;
    if (sequence > 0n) {
      const previousId = slots.get(`${group}\0${sequence - 1n}`); assert.ok(previousId);
      addEdge(previousId, id);
    }
    if (causal.event.parent.kind === 'event' && byId.has(causal.event.parent.eventId)) addEdge(causal.event.parent.eventId, id);
  }
  const key = (id) => {
    const causal = byId.get(id); const producer = causal.event.producer;
    return [parseDecimal(causal.hlc.physicalNs), parseDecimal(causal.hlc.logical), producer.kind, producer.id, producer.instanceId, parseDecimal(producer.sourceSequence), id];
  };
  const compare = (left, right) => {
    const a = key(left); const b = key(right);
    for (let index = 0; index < a.length; index += 1) if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
    return 0;
  };
  const ready = [...indegree].filter(([, degree]) => degree === 0).map(([id]) => id);
  const ordered = [];
  while (ready.length) {
    ready.sort(compare); const id = ready.shift(); ordered.push(id);
    for (const child of outgoing.get(id) ?? []) { indegree.set(child, indegree.get(child) - 1); if (indegree.get(child) === 0) ready.push(child); }
  }
  assert.equal(ordered.length, byId.size);
  return { runId, ordered: ordered.map((id) => byId.get(id)) };
}
function sealMerged({ runId, ordered }) {
  const records = ordered.map((causal, index) => ({ causal, mergeSequence: String(index), recordType: 'event' }));
  const lines = records.map((record) => bytes(canonical(record)));
  const merged = Buffer.concat(lines.flatMap((line) => [line, Buffer.from('\n')]));
  const mergedDigest = framed('merged-jsonl', [merged]);
  const decisions = records.filter((record) => record.causal.recordedDecision !== null).map((record) => ({
    decisionDigest: framed('recorded-decision', [bytes(canonical(record.causal.recordedDecision))]),
    eventId: record.causal.event.eventId,
  }));
  const groups = new Map();
  for (const causal of ordered) {
    const producer = causal.event.producer;
    const group = `${producer.kind}\0${producer.id}\0${producer.instanceId}`;
    const entries = groups.get(group) ?? []; entries.push(causal); groups.set(group, entries);
  }
  const producerHeads = [...groups.values()].map((entries) => {
    entries.sort((a, b) => Number(parseDecimal(a.event.producer.sourceSequence) - parseDecimal(b.event.producer.sourceSequence)));
    const producer = entries[0].event.producer;
    return { eventCount: String(entries.length), headHash: entries.at(-1).producerHash, producerId: producer.id, producerInstanceId: producer.instanceId, producerKind: producer.kind };
  }).sort((a, b) => {
    const left = [a.producerKind, a.producerId, a.producerInstanceId];
    const right = [b.producerKind, b.producerId, b.producerInstanceId];
    for (let index = 0; index < left.length; index += 1) {
      if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
    }
    return 0;
  });
  const decisionDigest = framed('decision-set', [bytes(canonical(decisions))]);
  const claims = {
    artifactManifestDigest: framed('artifact-manifest', [bytes('[]')]), canonicalization: 'RFC8785-JCS-restricted-no-numbers/1',
    eventCount: String(records.length), hashFraming: 'SMESH-A2A-length-prefixed-v1', mergedJsonlDigest: mergedDigest,
    merkleRoot: merkle(lines), missingParents: [], producerHeads, projections: [], recordCount: String(records.length),
    recordedDecisionSetDigest: decisionDigest, runId, schemaVersion: 'full-matrix-replay/1',
  };
  const runSeal = framed('run-seal', [bytes(canonical(claims))]);
  const bundle = Buffer.concat([merged, bytes(canonical({ claims, recordType: 'seal', sealDigest: runSeal })), Buffer.from('\n')]);
  const receipt = {
    decisionMode: 'recordedOnly', inputJsonlDigest: mergedDigest, merkleRoot: claims.merkleRoot,
    normalizedOutputDigest: framed('replay-output', [bundle]), projections: [], receiptDigest: '',
    recordedDecisionSetDigest: decisionDigest, replayedEventCount: String(records.length), runId, runSeal,
    schemaVersion: 'full-matrix-replay-receipt/1',
  };
  const unsigned = { ...receipt }; delete unsigned.receiptDigest;
  receipt.receiptDigest = framed('replay-receipt', [bytes(canonical(unsigned))]);
  return { bundle, receiptBytes: bytes(canonical(receipt)) };
}

test('Node independently validates sources, merges, and derives Rust bundle and receipt', async () => {
  const [sourceA, sourceB, expectedBundle, expectedReceipt] = await Promise.all([
    readFile(new URL('source-a.jsonl', fixture)), readFile(new URL('source-b.jsonl', fixture)),
    readFile(new URL('expected.bundle.jsonl', fixture)), readFile(new URL('expected.receipt.json', fixture)),
  ]);
  const actual = sealMerged(merge([parseSource(sourceB), parseSource(sourceA)]));
  assert.deepEqual(actual.bundle, expectedBundle);
  assert.deepEqual(actual.receiptBytes, expectedReceipt);
});

test('restricted JCS Unicode and u64 corpus is explicit', () => {
  assert.throws(() => canonical({ '\ud800': 'bad' }), /surrogate/);
  assert.throws(() => canonical('\udfff'), /surrogate/);
  assert.equal(canonical({ '\u{10000}': 'astral', '\ue000': 'bmp' }), '{"𐀀":"astral","":"bmp"}');
  assert.equal(canonical({ control: '\b\t\n\f\r\u0000', café: '雪😀' }), '{"café":"雪😀","control":"\\b\\t\\n\\f\\r\\u0000"}');
  assert.equal(parseDecimal('18446744073709551615'), 0xffffffffffffffffn);
  assert.throws(() => parseDecimal('18446744073709551616'));
  assert.throws(() => parseDecimal('01'));
});

test('event identity matches every Rust event kind and missing-parent reason', () => {
  const eventKinds = {
    a2aSend: 'A2aSend', a2aReceive: 'A2aReceive',
    smeshSignalEmitted: 'SmeshSignalEmitted', smeshSignalSent: 'SmeshSignalSent',
    smeshSignalReinforced: 'SmeshSignalReinforced', smeshSignalReceived: 'SmeshSignalReceived',
    smeshSignalExpired: 'SmeshSignalExpired', smeshTickCompleted: 'SmeshTickCompleted',
    smeshPeerConnected: 'SmeshPeerConnected', smeshPeerDisconnected: 'SmeshPeerDisconnected',
    toolCall: 'ToolCall', toolResult: 'ToolResult', toolFailed: 'ToolFailed',
    artifactProduced: 'ArtifactProduced', artifactConsumed: 'ArtifactConsumed',
    humanPrompt: 'HumanPrompt', humanDecision: 'HumanDecision', humanFailed: 'HumanFailed',
  };
  const missingReasons = {
    externalBoundary: 'ExternalBoundary',
    captureStartedLate: 'CaptureStartedLate',
    producerRestart: 'ProducerRestart',
  };
  const runId = 'run-kind-corpus';
  const expectedId = (event, rustKind, parent) => {
    const identity = `A2a\0producer\0instance`;
    const preimage = [
      'full-matrix-event/v1', runId, identity, '0', rustKind, 'interaction', 'peer',
      '', '', '', parent, `sha256:${'00'.repeat(32)}`, '0',
    ].join('\0');
    return digest(bytes(preimage));
  };
  const base = {
    content: { byteLength: '0', digest: `sha256:${'00'.repeat(32)}` },
    contextId: null, eventId: `sha256:${'00'.repeat(32)}`, interactionId: 'interaction',
    kind: 'a2aSend', parent: { kind: 'root' }, peerId: 'peer',
    producer: { id: 'producer', instanceId: 'instance', kind: 'a2a', sourceSequence: '0' },
    sourceSequence: '0', subjectId: null, taskId: null,
  };
  for (const [wireKind, rustKind] of Object.entries(eventKinds)) {
    const event = { ...base, kind: wireKind };
    assert.equal(captureEventId(runId, event), expectedId(event, rustKind, 'root'));
  }
  for (const [wireReason, rustReason] of Object.entries(missingReasons)) {
    const expected = `sha256:${'11'.repeat(32)}`;
    const event = {
      ...base,
      parent: { expectedEventId: expected, kind: 'missing', reason: wireReason },
    };
    assert.equal(
      captureEventId(runId, event),
      expectedId(event, 'A2aSend', `missing:${expected}:${rustReason}`),
    );
  }
});
