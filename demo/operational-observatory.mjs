const MAX_BYTES = 16 * 1024 * 1024;
const MAX_LINE_BYTES = 64 * 1024;
const MAX_EVENTS = 100_000;
const MAX_ACTORS = 1_024;
const MAX_TEXT_BYTES = 4_096;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9_.:/-]{1,256}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
const PRODUCER_KINDS = new Set(['a2a', 'smesh', 'tool', 'artifact', 'human']);
const CUES = new Set(['clear', 'focus', 'follow', 'hold']);
const GAP_REASONS = new Set(['externalBoundary', 'captureStartedLate', 'producerRestart']);
const FAILURE_KINDS = new Set(['sibling-submitted', 'primary-submitted', 'primary-outage-observed', 'primary-stream-failed', 'cancel-requested', 'late-output-fenced', 'internal-processor-stopped', 'cancel-confirmed', 'sibling-completed', 'fallback-selected', 'fallback-submitted', 'fallback-completed', 'review-completed', 'primary-final-reconciled', 'scenario-completed']);
const FAILURE_OUTCOMES = new Set(['submitted', 'unavailable', 'error', 'requested', 'fenced', 'cooperative-stop', 'canceled', 'completed', 'selected']);
const FAILURE_OUTCOME_BY_KIND = new Map([
  ['sibling-submitted', 'submitted'], ['primary-submitted', 'submitted'], ['fallback-submitted', 'submitted'],
  ['primary-outage-observed', 'unavailable'], ['primary-stream-failed', 'error'], ['cancel-requested', 'requested'],
  ['late-output-fenced', 'fenced'], ['internal-processor-stopped', 'cooperative-stop'], ['cancel-confirmed', 'canceled'],
  ['primary-final-reconciled', 'canceled'], ['sibling-completed', 'completed'], ['fallback-completed', 'completed'],
  ['review-completed', 'completed'], ['scenario-completed', 'completed'], ['fallback-selected', 'selected'],
]);
const KIND_CHANNEL = new Map([
  ['a2aSend', 'a2a'], ['a2aReceive', 'a2a'],
  ['smeshSignalEmitted', 'smesh'], ['smeshSignalSent', 'smesh'],
  ['smeshSignalReinforced', 'smesh'], ['smeshSignalReceived', 'smesh'],
  ['smeshSignalExpired', 'smesh'], ['smeshTickCompleted', 'smesh'],
  ['smeshPeerConnected', 'smesh'], ['smeshPeerDisconnected', 'smesh'],
  ['toolCall', 'tool'], ['toolResult', 'tool'], ['toolFailed', 'tool'],
  ['artifactProduced', 'artifact'], ['artifactConsumed', 'artifact'],
  ['humanPrompt', 'human'], ['humanDecision', 'human'], ['humanFailed', 'human'],
]);
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function fail(message) {
  throw new Error(`operational package rejected: ${String(message).slice(0, 240)}`);
}
function object(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}
function exact(value, keys, label) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has an unknown or missing field`);
}
function text(value, label) {
  if (typeof value !== 'string' || encoder.encode(value).length === 0 || encoder.encode(value).length > MAX_TEXT_BYTES || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) fail(`${label} is invalid`);
}
function digest(value, label) { if (typeof value !== 'string' || !DIGEST.test(value)) fail(`${label} is invalid`); }
function identifier(value, label) { if (typeof value !== 'string' || !IDENTIFIER.test(value)) fail(`${label} is invalid`); }
function decimal(value, label) { if (typeof value !== 'string' || !DECIMAL.test(value) || BigInt(value) > 18446744073709551615n) fail(`${label} is invalid`); return BigInt(value); }
function bytes(value, label, max = MAX_BYTES) {
  const result = value instanceof Uint8Array ? value : new Uint8Array(value);
  if (result.byteLength === 0 || result.byteLength > max) fail(`${label} exceeds bounds`);
  return result;
}
function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  return value;
}
export function canonicalJson(value) { return JSON.stringify(canonicalValue(value)); }
function parseCanonical(input, label, max = MAX_BYTES) {
  const raw = bytes(input, label, max);
  let value;
  try { value = JSON.parse(decoder.decode(raw)); } catch { fail(`${label} is malformed UTF-8 JSON`); }
  if (canonicalJson(value) !== decoder.decode(raw)) fail(`${label} is not canonical JSON`);
  return value;
}
function uint64(value) {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, BigInt(value));
  return result;
}
function concat(...parts) {
  const size = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(size); let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.byteLength; }
  return output;
}
function hex(value) { return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, '0')).join(''); }
export async function protocolHash(label, payload) {
  const body = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const framed = concat(encoder.encode('SMESH-A2A\0'), encoder.encode(label), encoder.encode('\0v1\0'), uint64(body.byteLength), body);
  return `sha256:${hex(await globalThis.crypto.subtle.digest('SHA-256', framed))}`;
}
function parsePackage(input) {
  const raw = bytes(input, 'package');
  if (raw.at(-1) !== 10) fail('package requires a terminal LF');
  const body = raw.subarray(0, -1);
  const rawLines = decoder.decode(body).split('\n');
  if (rawLines.length < 2 || rawLines.length > MAX_EVENTS + 1 || rawLines.some((line) => line.length === 0 || encoder.encode(line).length > MAX_LINE_BYTES)) fail('package line bounds are invalid');
  const values = rawLines.map((line, index) => {
    let value; try { value = JSON.parse(line); } catch { fail(`package line ${index + 1} is malformed`); }
    if (canonicalJson(value) !== line) fail(`package line ${index + 1} is not canonical`);
    return value;
  });
  return { raw, values };
}
function validateManifest(manifest) {
  exact(manifest, ['actors', 'schemaVersion', 'sites'], 'actor manifest');
  if (manifest.schemaVersion !== 'operational-observatory-actors/1') fail('actor manifest schema is unsupported');
  if (!Array.isArray(manifest.sites) || manifest.sites.length === 0 || manifest.sites.length > MAX_ACTORS) fail('sites exceed bounds');
  if (!Array.isArray(manifest.actors) || manifest.actors.length === 0 || manifest.actors.length > MAX_ACTORS) fail('actors exceed bounds');
  let priorSite = ''; const sites = new Map();
  for (const site of manifest.sites) {
    exact(site, ['displayName', 'siteId'], 'site'); identifier(site.siteId, 'siteId'); text(site.displayName, 'site displayName');
    if (site.siteId <= priorSite || sites.has(site.siteId)) fail('sites conflict or are not sorted');
    sites.set(site.siteId, site); priorSite = site.siteId;
  }
  let priorKey = ''; const actors = new Map(); const actorIds = new Set();
  for (const actor of manifest.actors) {
    exact(actor, ['actorId', 'displayName', 'producer', 'siteId', 'visibility'], 'actor');
    exact(actor.producer, ['id', 'instanceId', 'kind'], 'actor producer');
    identifier(actor.actorId, 'actorId'); identifier(actor.producer.id, 'producer id'); identifier(actor.producer.instanceId, 'producer instanceId'); text(actor.displayName, 'actor displayName');
    if (!PRODUCER_KINDS.has(actor.producer.kind) || !sites.has(actor.siteId) || !['visible', 'restricted'].includes(actor.visibility)) fail('actor reference or enum is invalid');
    const key = `${actor.producer.kind}\0${actor.producer.id}\0${actor.producer.instanceId}`;
    if (key <= priorKey || actors.has(key) || actorIds.has(actor.actorId)) fail('actors conflict or are not sorted');
    actors.set(key, actor); actorIds.add(actor.actorId); priorKey = key;
  }
  return { actors, sites };
}
function validateOverlay(overlay) {
  exact(overlay, ['entries', 'schemaVersion'], 'editorial overlay');
  if (overlay.schemaVersion !== 'operational-observatory-editorial/1' || !Array.isArray(overlay.entries) || overlay.entries.length > MAX_EVENTS) fail('editorial overlay schema or bounds are invalid');
  let prior = ''; const entries = new Map();
  for (const entry of overlay.entries) {
    exact(entry, ['cue', 'eventId', 'narration'], 'editorial entry'); digest(entry.eventId, 'editorial eventId'); text(entry.narration, 'narration');
    if (!CUES.has(entry.cue) || entry.eventId <= prior || entries.has(entry.eventId)) fail('editorial entries conflict or are not sorted');
    entries.set(entry.eventId, entry); prior = entry.eventId;
  }
  return entries;
}
function validateParent(parent) {
  object(parent, 'parent');
  if (parent.kind === 'root') exact(parent, ['kind'], 'root parent');
  else if (parent.kind === 'event') { exact(parent, ['eventId', 'kind'], 'event parent'); digest(parent.eventId, 'parent eventId'); }
  else if (parent.kind === 'missing') { exact(parent, ['expectedEventId', 'kind', 'reason'], 'missing parent'); digest(parent.expectedEventId, 'expected parent'); if (!GAP_REASONS.has(parent.reason)) fail('missing parent reason is invalid'); }
  else fail('parent kind is invalid');
}
function validateProducer(producer, channel) {
  exact(producer, ['id', 'instanceId', 'kind', 'sourceSequence'], 'producer'); identifier(producer.id, 'producer id'); identifier(producer.instanceId, 'producer instanceId'); decimal(producer.sourceSequence, 'sourceSequence');
  if (producer.kind !== channel || !PRODUCER_KINDS.has(producer.kind)) fail('producer kind conflicts with channel');
}
function validateSourceFacts(facts, record) {
  if (facts === null) return null;
  exact(facts, ['eventId', 'failureKind', 'fieldRestrictions', 'outcome', 'sourceContentDigest', 'sourceSchemaVersion'], 'source facts');
  digest(facts.eventId, 'source facts eventId'); digest(facts.sourceContentDigest, 'source content digest'); identifier(facts.sourceSchemaVersion, 'source schema version');
  if (facts.eventId !== record.eventId || facts.sourceContentDigest !== record.content?.digest) fail('source facts binding conflicts with event');
  if ((facts.failureKind === null) !== (facts.outcome === null)) fail('source failure facts are incomplete');
  if (facts.failureKind !== null && (!FAILURE_KINDS.has(facts.failureKind) || !FAILURE_OUTCOMES.has(facts.outcome) || FAILURE_OUTCOME_BY_KIND.get(facts.failureKind) !== facts.outcome)) fail('source failure facts enum is invalid');
  if (!Array.isArray(facts.fieldRestrictions) || (facts.failureKind === null && facts.fieldRestrictions.length === 0)) fail('source facts are empty');
  let prior = '';
  for (const restriction of facts.fieldRestrictions) {
    exact(restriction, ['field', 'reason'], 'field restriction');
    if (restriction.field !== 'subjectId' || restriction.reason !== 'sourceIdentifierUnavailable' || restriction.field <= prior || record.subjectId !== null) fail('field restriction is invalid');
    prior = restriction.field;
  }
  if ((facts.sourceSchemaVersion === 'lifeline-failure-scenario/1') !== (facts.failureKind !== null)
      || (facts.sourceSchemaVersion === 'lifeline-runtime-trace/1') !== (facts.fieldRestrictions.length === 1)
      || (facts.failureKind !== null && facts.fieldRestrictions.length !== 0)) fail('source schema does not match source facts');
  return facts;
}
function validateRecords(values, manifestIndex, overlayEntries) {
  const header = values[0];
  exact(header, ['actorManifestDigest', 'editorialOverlayDigest', 'inputReplayDigest', 'inputRunSeal', 'recordType', 'runId', 'schemaVersion', 'sourceFactsDigest'], 'package header');
  if (header.recordType !== 'package' || header.schemaVersion !== 'operational-observatory/1') fail('package header schema is unsupported');
  for (const key of ['actorManifestDigest', 'editorialOverlayDigest', 'inputReplayDigest', 'inputRunSeal', 'sourceFactsDigest']) digest(header[key], key);
  identifier(header.runId, 'runId');
  const records = []; const sourceFacts = []; const eventIds = new Set(); const orderedEventIds = new Set(); const usedActors = new Set(); const gaps = []; const gapClaimByChild = new Map(); const gapExpectedIds = new Set(); let sawEvent = false; let priorTime = 0n;
  for (const [offset, record] of values.slice(1).entries()) {
    object(record, `record ${offset}`);
    if (record.recordType === 'gap') {
      if (sawEvent) fail('gap records must precede events');
      exact(record, ['children', 'expectedEventId', 'reason', 'recordId', 'recordType'], 'gap');
      digest(record.expectedEventId, 'gap expectedEventId'); digest(record.recordId, 'gap recordId');
      if (gapExpectedIds.has(record.expectedEventId)) fail('gap expected event is defined more than once');
      gapExpectedIds.add(record.expectedEventId);
      if (record.reason !== 'unresolvedAtSeal' || !Array.isArray(record.children) || record.children.length === 0) fail('gap semantics are invalid');
      let prior = ''; for (const child of record.children) {
        digest(child, 'gap child');
        if (child <= prior) fail('gap children are not sorted');
        if (gapClaimByChild.has(child)) fail('gap child is claimed more than once');
        gapClaimByChild.set(child, record.expectedEventId); prior = child;
      }
      gaps.push(record); continue;
    }
    sawEvent = true; const restricted = record.recordType === 'restricted';
    const common = ['actorId', 'channel', 'eventId', 'kind', 'mergeIndex', 'parent', 'producer', 'recordType', 'runRelativeNs', 'siteId'];
    exact(record, restricted ? [...common, 'restrictionReason'] : [...common, 'content', 'contextId', 'editorial', 'interactionId', 'peerId', 'sourceFacts', 'subjectId', 'taskId'], 'event record');
    if (!restricted && record.recordType !== 'event') fail('record type is invalid');
    if (restricted && record.restrictionReason !== 'actorManifest') fail('restriction reason is invalid');
    digest(record.eventId, 'eventId'); if (eventIds.has(record.eventId)) fail('duplicate eventId'); eventIds.add(record.eventId);
    if (decimal(record.mergeIndex, 'mergeIndex') !== BigInt(offset - gaps.length)) fail('merge indices are not contiguous');
    const timeNs = decimal(record.runRelativeNs, 'runRelativeNs'); if (timeNs < priorTime) fail('recorded time is not monotonic'); priorTime = timeNs;
    identifier(record.actorId, 'actorId'); identifier(record.siteId, 'siteId');
    const channel = KIND_CHANNEL.get(record.kind); if (!channel || channel !== record.channel) fail('event kind conflicts with channel');
    validateParent(record.parent);
    if (record.parent.kind === 'event' && !orderedEventIds.has(record.parent.eventId)) fail('parent reference is missing or follows its child');
    validateProducer(record.producer, record.channel);
    const producerKey = `${record.producer.kind}\0${record.producer.id}\0${record.producer.instanceId}`;
    const actor = manifestIndex.actors.get(producerKey);
    if (!actor || actor.actorId !== record.actorId || actor.siteId !== record.siteId || (restricted ? actor.visibility !== 'restricted' : actor.visibility !== 'visible')) fail('event actor mapping conflicts with manifest');
    usedActors.add(producerKey);
    if (!restricted) {
      exact(record.content, ['byteLength', 'digest'], 'content'); decimal(record.content.byteLength, 'content byteLength'); digest(record.content.digest, 'content digest');
      for (const key of ['interactionId', 'peerId']) identifier(record[key], key);
      for (const key of ['contextId', 'subjectId', 'taskId']) if (record[key] !== null) identifier(record[key], key);
      const facts = validateSourceFacts(record.sourceFacts, record); if (facts) sourceFacts.push(facts);
      const expectedEditorial = overlayEntries.get(record.eventId);
      if (record.editorial === null) { if (expectedEditorial) fail('editorial reference is missing'); }
      else {
        exact(record.editorial, ['cue', 'narration'], 'embedded editorial');
        if (!expectedEditorial || record.editorial.cue !== expectedEditorial.cue || record.editorial.narration !== expectedEditorial.narration) fail('editorial reference conflicts');
      }
    } else if (overlayEntries.has(record.eventId)) fail('restricted event has editorial content');
    records.push({ ...record, timeNs });
    orderedEventIds.add(record.eventId);
  }
  if (records.length === 0 || usedActors.size !== manifestIndex.actors.size) fail('package is incomplete for actor manifest');
  for (const eventId of overlayEntries.keys()) if (!eventIds.has(eventId)) fail('editorial reference is missing');
  for (const record of records) {
    const claimedExpected = gapClaimByChild.get(record.eventId);
    if (record.parent.kind === 'missing') {
      if (claimedExpected !== record.parent.expectedEventId) fail('missing parent lacks its exact explicit gap');
    } else if (claimedExpected !== undefined) fail('gap child does not declare the claimed missing parent');
  }
  for (const child of gapClaimByChild.keys()) if (!eventIds.has(child)) fail('gap child reference is missing');
  for (const gap of gaps) if (eventIds.has(gap.expectedEventId)) fail('gap expected event is already present');
  sourceFacts.sort((a, b) => a.eventId.localeCompare(b.eventId));
  return { header, gaps, records, sourceFacts };
}
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child); }
  return value;
}

export async function loadVerifiedOperationalPackage(inputs) {
  try {
    const packageData = parsePackage(inputs.packageBytes);
    const receiptRaw = bytes(inputs.receiptBytes, 'projection receipt', MAX_LINE_BYTES);
    const actorRaw = bytes(inputs.actorBytes, 'actor manifest');
    const editorialRaw = bytes(inputs.editorialBytes, 'editorial overlay');
    const bootstrapRaw = bytes(inputs.bootstrapBytes, 'browser bootstrap', MAX_LINE_BYTES);
    const receipt = parseCanonical(receiptRaw, 'projection receipt', MAX_LINE_BYTES);
    const manifest = parseCanonical(actorRaw, 'actor manifest');
    const overlay = parseCanonical(editorialRaw, 'editorial overlay');
    const bootstrap = parseCanonical(bootstrapRaw, 'browser bootstrap', MAX_LINE_BYTES);
    exact(receipt, ['inputDigest', 'outputByteLength', 'outputDigest', 'projectorId', 'projectorVersion'], 'projection receipt');
    exact(bootstrap, ['expectedInputDigest', 'expectedRunSeal', 'finalDurationNs', 'schemaVersion'], 'browser bootstrap');
    for (const key of ['inputDigest', 'outputDigest']) digest(receipt[key], `receipt ${key}`);
    digest(bootstrap.expectedInputDigest, 'expected input digest'); digest(bootstrap.expectedRunSeal, 'expected run seal');
    const finalDurationNs = decimal(bootstrap.finalDurationNs, 'final duration');
    if (bootstrap.schemaVersion !== 'operational-observatory-browser-bootstrap/1' || receipt.projectorId !== 'smesh-operational-observatory' || receipt.projectorVersion !== '1') fail('projector or bootstrap identity is unsupported');
    if (receipt.inputDigest !== bootstrap.expectedInputDigest || decimal(receipt.outputByteLength, 'outputByteLength') !== BigInt(packageData.raw.byteLength)) fail('receipt input or byte length does not match');
    if (receipt.outputDigest !== await protocolHash('operational-observatory-output', packageData.raw)) fail('projection receipt output digest does not match');
    const manifestIndex = validateManifest(manifest); const overlayEntries = validateOverlay(overlay);
    const validated = validateRecords(packageData.values, manifestIndex, overlayEntries);
    if (validated.header.actorManifestDigest !== await protocolHash('operational-actor-manifest', actorRaw) || validated.header.editorialOverlayDigest !== await protocolHash('operational-editorial-overlay', editorialRaw)) fail('package label commitments do not match');
    const sourceFactsBytes = encoder.encode(canonicalJson({ entries: validated.sourceFacts, schemaVersion: 'operational-observatory-source-facts/1' }));
    if (validated.header.sourceFactsDigest !== await protocolHash('operational-source-facts', sourceFactsBytes)) fail('source facts commitment does not match');
    if (validated.header.inputRunSeal !== bootstrap.expectedRunSeal || finalDurationNs < validated.records.at(-1).timeNs) fail('run seal or final duration commitment does not match');
    return deepFreeze({
      ready: true, header: validated.header, records: validated.records, gaps: validated.gaps,
      manifest, overlay, receipt, bootstrap: { ...bootstrap, finalDurationNs },
      authority: { upstreamRunSealCryptographicallyReverified: false, label: 'Projection receipt and input commitment verified; upstream Rust run seal displayed but not cryptographically re-verified in this browser.' },
    });
  } catch (error) {
    if (String(error?.message).startsWith('operational package rejected:')) throw error;
    fail(error?.message || 'validation failed');
  }
}

function anonymousLabel(kind, id) {
  const prefix = kind === 'actor' ? 'Anonymous actor' : 'Anonymous site';
  return `${prefix} [${id}]`;
}
function timeFromRequest(request, duration) {
  const hasNs = request !== null && typeof request === 'object' && Object.hasOwn(request, 'timeNs');
  exact(request, hasNs ? ['timeNs'] : ['timeMs'], 'projection time');
  let time;
  if (hasNs) time = decimal(request.timeNs, 'timeNs');
  else {
    if (!Number.isFinite(request.timeMs) || request.timeMs < 0) throw new RangeError('projection time must be finite and non-negative');
    time = BigInt(Math.floor(request.timeMs * 1_000_000));
  }
  if (time > duration) throw new RangeError('projection time exceeds final duration');
  return time;
}

function operationalPresentation(record) {
  const restrictions = record.sourceFacts?.fieldRestrictions || [];
  if (restrictions.length > 0) return { glyph: '◆', state: 'restricted', statusLabel: 'RESTRICTED — SOURCE IDENTIFIER UNAVAILABLE' };
  const kind = record.sourceFacts?.failureKind;
  const outcome = record.sourceFacts?.outcome;
  if (!kind) return { glyph: '●', state: 'verified', statusLabel: 'VERIFIED CAPTURED EVENT' };
  const detail = `${kind.replaceAll('-', ' ').toUpperCase()} · ${outcome.replaceAll('-', ' ').toUpperCase()}`;
  if (['unavailable', 'error'].includes(outcome)) return { glyph: '✕', state: 'failure', statusLabel: `FAILURE — ${detail}` };
  if (['requested', 'fenced', 'canceled', 'cooperative-stop'].includes(outcome)) return { glyph: '◇', state: 'control', statusLabel: `CONTROL — ${detail}` };
  if (['selected', 'submitted'].includes(outcome)) return { glyph: '▸', state: 'transition', statusLabel: `TRANSITION — ${detail}` };
  return { glyph: '●', state: 'completed', statusLabel: `COMPLETED — ${detail}` };
}

export function createOperationalProjector(verified) {
  if (!verified?.ready || !Array.isArray(verified.records) || typeof verified.bootstrap?.finalDurationNs !== 'bigint') throw new TypeError('a complete verified operational package is required');
  const duration = verified.bootstrap.finalDurationNs;
  const actorLabels = new Map((verified.manifest?.actors || []).map((actor) => [actor.actorId, actor.displayName]));
  const siteLabels = new Map((verified.manifest?.sites || []).map((site) => [site.siteId, site.displayName]));
  const cueRecords = verified.records.filter((record) => record.recordType === 'event' && record.editorial !== null);
  const cues = cueRecords.map((record, index) => ({
    cue: record.editorial.cue,
    endNsExclusive: String(cueRecords[index + 1]?.timeNs ?? duration),
    sourceEventId: record.eventId,
    startNsInclusive: String(record.timeNs),
    text: record.editorial.narration,
  }));
  if (cues.some((cue, index) => BigInt(cue.endNsExclusive) <= BigInt(cue.startNsInclusive) || (index > 0 && BigInt(cue.startNsInclusive) < BigInt(cues[index - 1].startNsInclusive)))) throw new TypeError('narration cue intervals are invalid');

  function projectAt(time) {
    const visible = verified.records.filter((record) => record.timeNs <= time);
    const contributingEventIds = visible.map((record) => record.eventId);
    const rows = visible.map((record) => {
      const restricted = record.recordType === 'restricted';
      const presentation = restricted
        ? { glyph: '◆', state: 'restricted', statusLabel: 'RESTRICTED — CONTENT NOT AVAILABLE' }
        : operationalPresentation(record);
      return {
        actorLabel: actorLabels.get(record.actorId) || anonymousLabel('actor', record.actorId),
        channel: record.channel,
        eventId: record.eventId,
        glyph: presentation.glyph,
        kind: record.kind,
        operationalState: presentation.state,
        siteLabel: siteLabels.get(record.siteId) || anonymousLabel('site', record.siteId),
        sourceEventIds: [record.eventId],
        statusLabel: presentation.statusLabel,
        timeNs: record.runRelativeNs,
      };
    });
    const visuals = rows.map((row) => ({
      actorLabel: row.actorLabel,
      channel: row.channel,
      glyph: row.glyph,
      kind: row.kind,
      operationalState: row.operationalState,
      sourceEventIds: row.sourceEventIds,
      statusLabel: row.statusLabel,
    }));
    const gaps = verified.gaps.map((gap) => ({
      expectedEventId: gap.expectedEventId,
      glyph: '△',
      reason: gap.reason,
      sourceEventIds: [...gap.children],
      statusLabel: 'GAP — UNRESOLVED AT VERIFIED SEAL',
    }));
    let narration = null;
    for (const cue of cues) if (BigInt(cue.startNsInclusive) <= time && time < BigInt(cue.endNsExclusive)) narration = cue;
    return deepFreeze({
      contributingEventIds,
      gaps,
      narration,
      rows,
      schemaVersion: 'operational-observatory-browser-state/1',
      timeNs: String(time),
      visuals,
    });
  }
  return Object.freeze({
    finalDurationNs: String(duration),
    projectStateAt(request) { return projectAt(timeFromRequest(request, duration)); },
    projectStateForFrame(frame, fps) {
      if (!Number.isSafeInteger(frame) || frame < 0) throw new RangeError('frame must be a non-negative safe integer');
      if (!Number.isSafeInteger(fps) || fps < 1 || fps > 240) throw new RangeError('fps must be an integer from 1 through 240');
      const time = BigInt(frame) * 1_000_000_000n / BigInt(fps);
      if (time > duration) throw new RangeError('frame exceeds final duration');
      return projectAt(time);
    },
  });
}

export async function digestProjectedState(state) {
  if (state?.schemaVersion !== 'operational-observatory-browser-state/1') throw new TypeError('projected operational state is required');
  return protocolHash('operational-observatory-browser-state', encoder.encode(canonicalJson(state)));
}
