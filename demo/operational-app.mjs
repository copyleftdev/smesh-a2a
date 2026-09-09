import * as THREE from './vendor/three.module.min.js';
import { createOperationalProjector, digestProjectedState, loadVerifiedOperationalPackage } from './operational-observatory.mjs';

const PACKAGE_ROOT = './fixtures/operational-lifeline-v1/';
const PRODUCTION_FIXTURE = Object.freeze({
  expectedInputDigest: 'sha256:12c21884869189a56e196bbd31a21ccc482bcc8dde0dea65d70ad11f7b743061',
  expectedRunSeal: 'sha256:9490f15c83f39fc923ef221155fa7ba5da79a38a92b571375defef6e943532ad',
  finalDurationNs: '46000000000',
  inputReplayDigest: 'sha256:3fda26ac58e9707b57f56be368ced9c1b25e7170cd31bb08535e8a9e83d0ed50',
  outputByteLength: '43300',
  outputDigest: 'sha256:191b058da6c715f068287d3f065a798331c6339f22c158f24bb545d395553d17',
  recordCount: 46,
  runId: 'lifeline-operational-0047',
  sites: Object.freeze(['atlas-fallback', 'atlas-primary', 'harbor', 'helix', 'meridian', 'sentinel']),
  sourceFactsDigest: 'sha256:cd1bf0a8e3ea2be13d4fce2853e7e798e0c1432aa6a861bd6e523f33f51d649c',
});
const ASSETS = Object.freeze({
  packageBytes: `${PACKAGE_ROOT}package.jsonl`, receiptBytes: `${PACKAGE_ROOT}receipt.json`,
  actorBytes: `${PACKAGE_ROOT}actors.json`, editorialBytes: `${PACKAGE_ROOT}editorial.json`,
  bootstrapBytes: `${PACKAGE_ROOT}browser-bootstrap.json`,
});
const STATE_STYLES = Object.freeze({
  completed: Object.freeze({ color: '#87d5a0', shape: 'icosahedron' }),
  control: Object.freeze({ color: '#65c7ff', shape: 'octahedron' }),
  failure: Object.freeze({ color: '#ff4f64', shape: 'octahedron' }),
  gap: Object.freeze({ color: '#ffd45d', shape: 'triangle' }),
  restricted: Object.freeze({ color: '#ff7654', shape: 'square' }),
  transition: Object.freeze({ color: '#c6a7ff', shape: 'tetrahedron' }),
  verified: Object.freeze({ color: '#87d5a0', shape: 'icosahedron' }),
});
const canvas = document.querySelector('#observatory');
const controls = [...document.querySelectorAll('#controls button, #controls input')];
const scrub = document.querySelector('#scrub');
const play = document.querySelector('#play');
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
let verified; let projector; let state; let playing = false; let animation; let lastReal = 0; let renderGeneration = 0; let failed = false;
let renderer; let rendererMetadata; let scene; let camera; let raycaster; let sceneObjects = []; let renderCount = 0;
window.__operationalReady = false;
document.body.dataset.validation = 'validating';
document.body.dataset.motion = reducedMotion ? 'reduced' : 'full';
document.body.dataset.accessibility = 'canvas-log-controls';
window.__operationalVisualObjects = Object.freeze([]);
window.__operationalSceneObjects = Object.freeze([]);
window.__operationalRendererMetadata = null;
window.__operationalReducedMotion = reducedMotion;

async function localAsset(path) {
  const url = new URL(path, location.href);
  if (url.origin !== location.origin || !Object.values(ASSETS).some((allowed) => url.href === new URL(allowed, location.href).href)) throw new Error('request is not on the operational asset allowlist');
  const response = await fetch(url, { cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  if (!response.ok) throw new Error(`required local asset unavailable (${response.status})`);
  return new Uint8Array(await response.arrayBuffer());
}
function inspectEvent(eventId) {
  const record = verified.records.find((candidate) => candidate.eventId === eventId);
  document.querySelector('#inspector').textContent = record ? JSON.stringify(record, (_, value) => typeof value === 'bigint' ? String(value) : value, 2) : `Source event not available: ${eventId}`;
}
function setupRenderer() {
  renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false, preserveDrawingBuffer: true });
  renderer.setPixelRatio(1);
  renderer.setSize(canvas.width, canvas.height, false);
  renderer.setClearColor(0x0d1210, 1);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  scene = new THREE.Scene();
  camera = new THREE.OrthographicCamera(-6, 6, 2.8, -2.8, 0.1, 30);
  camera.position.set(0, 0, 10);
  camera.lookAt(0, 0, 0);
  raycaster = new THREE.Raycaster();
  const metadata = {};
  Object.defineProperties(metadata, {
    engine: { enumerable: true, value: 'Three.js' },
    revision: { enumerable: true, value: THREE.REVISION },
    vendorPath: { enumerable: true, value: '/vendor/three.module.min.js' },
    webgl: { enumerable: true, value: Boolean(renderer.getContext()) },
    renderCount: { enumerable: true, get: () => renderCount },
    resourceCounts: { enumerable: true, get: () => Object.freeze({ geometries: renderer.info.memory.geometries, textures: renderer.info.memory.textures }) },
    stateStyles: { enumerable: true, value: STATE_STYLES },
  });
  rendererMetadata = Object.freeze(metadata);
}
function disposeSceneObjects() {
  for (const object of sceneObjects) {
    scene.remove(object);
    object.geometry?.dispose();
    if (Array.isArray(object.material)) object.material.forEach((material) => material.dispose());
    else object.material?.dispose();
  }
  sceneObjects = [];
  window.__operationalSceneObjects = Object.freeze([]);
}
function sourceData({ eventId, sourceEventIds, state: visualState }) {
  return Object.freeze({ eventId, sourceEventIds: Object.freeze([...sourceEventIds]), state: visualState });
}
function createSceneObject({ eventId, sourceEventIds, visualState, index, count }) {
  const columns = 9;
  const rows = Math.max(1, Math.ceil(count / columns));
  const column = index % columns;
  const row = Math.floor(index / columns);
  const x = columns === 1 ? 0 : -4.8 + column * 1.2;
  const y = rows === 1 ? 0 : 1.8 - row * (3.6 / Math.max(1, rows - 1));
  let geometry; let color;
  if (visualState === 'restricted') { geometry = new THREE.BoxGeometry(0.42, 0.42, 0.42); color = 0xff7654; }
  else if (visualState === 'gap') { geometry = new THREE.ConeGeometry(0.28, 0.52, 3); color = 0xffd45d; }
  else if (visualState === 'failure') { geometry = new THREE.OctahedronGeometry(0.34); color = 0xff4f64; }
  else if (visualState === 'control') { geometry = new THREE.OctahedronGeometry(0.3); color = 0x65c7ff; }
  else if (visualState === 'transition') { geometry = new THREE.TetrahedronGeometry(0.34); color = 0xc6a7ff; }
  else { geometry = new THREE.IcosahedronGeometry(0.25, 1); color = 0x87d5a0; }
  let material;
  try {
    material = new THREE.MeshBasicMaterial({ color, wireframe: visualState !== 'verified' });
    const object = new THREE.Mesh(geometry, material);
    object.position.set(x, y, 0);
    object.userData = sourceData({ eventId, sourceEventIds, state: visualState });
    return object;
  } catch (error) {
    geometry?.dispose(); material?.dispose();
    throw error;
  }
}
function disposeObjects(objects) {
  for (const object of objects) {
    object.geometry?.dispose();
    if (Array.isArray(object.material)) object.material.forEach((material) => material.dispose());
    else object.material?.dispose();
  }
}
function prepareDraw(projected) {
  const entries = [
    ...projected.visuals.map((visual) => ({ eventId: visual.sourceEventIds[0], sourceEventIds: visual.sourceEventIds, visualState: visual.operationalState })),
    ...projected.gaps.map((gap) => ({ eventId: gap.sourceEventIds[0], sourceEventIds: gap.sourceEventIds, visualState: 'gap' })),
  ];
  const objects = [];
  let visuals;
  try {
    visuals = entries.map((entry, index) => {
      const object = createSceneObject({ ...entry, index, count: entries.length });
      objects.push(object);
      const point = object.position.clone().project(camera);
      const size = entry.visualState === 'verified' ? 52 : 60;
      return Object.freeze({
        eventId: entry.eventId,
        sourceEventIds: object.userData.sourceEventIds,
        state: entry.visualState,
        bounds: Object.freeze({ x: (point.x + 1) * canvas.width / 2 - size / 2, y: (1 - point.y) * canvas.height / 2 - size / 2, width: size, height: size }),
      });
    });
  } catch (error) {
    disposeObjects(objects);
    throw error;
  }
  return { objects, visuals: Object.freeze(visuals), sourceEventIds: JSON.stringify(projected.contributingEventIds) };
}
function prepareRows(projected) {
  const fragment = document.createDocumentFragment();
  for (const row of projected.rows) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'event-row';
    button.dataset.eventId = row.eventId; button.dataset.sourceEventIds = JSON.stringify(row.sourceEventIds); button.dataset.status = row.operationalState;
    const status = document.createElement('span'); status.className = 'status'; status.textContent = `${row.glyph} ${row.statusLabel}`;
    const detail = document.createElement('span'); detail.className = 'meta'; detail.textContent = `${row.kind} · ${row.actorLabel} · ${row.siteLabel} · ${row.eventId}`;
    button.append(status, detail); button.addEventListener('click', () => inspectEvent(row.eventId)); fragment.append(button);
  }
  return fragment;
}
function prepareGaps(projected) {
  const fragment = document.createDocumentFragment();
  for (const gap of projected.gaps) {
    const item = document.createElement('div'); item.className = 'gap'; item.dataset.sourceEventIds = JSON.stringify(gap.sourceEventIds);
    item.textContent = `${gap.glyph} ${gap.statusLabel} · expected ${gap.expectedEventId} · affected ${gap.sourceEventIds.join(', ')}`; fragment.append(item);
  }
  return fragment;
}
async function applyState(projected) {
  if (failed) throw new Error('operational package is not ready');
  const generation = ++renderGeneration;
  maybeInject('digest');
  const stateDigest = await digestProjectedState(projected);
  if (generation !== renderGeneration || failed) return null;
  let preparedDraw;
  let rows;
  let gaps;
  try {
    preparedDraw = prepareDraw(projected);
    maybeInject('prepare');
    rows = prepareRows(projected);
    gaps = prepareGaps(projected);
  } catch (error) {
    if (preparedDraw) disposeObjects(preparedDraw.objects);
    throw error;
  }
  const cue = projected.narration;
  const narration = cue?.text || 'No cue at this time.';
  const narrationSource = cue ? `SOURCE ${cue.sourceEventId} · [${cue.startNsInclusive}, ${cue.endNsExclusive}) ns · ${cue.cue.toUpperCase()}` : '';
  const duration = BigInt(projector.finalDurationNs); const time = BigInt(projected.timeNs);
  const scrubValue = String(duration === 0n ? 0n : time * 1_000_000n / duration);

  try {
    disposeSceneObjects();
    for (const object of preparedDraw.objects) {
      scene.add(object);
      maybeInject('commit');
    }
    sceneObjects = preparedDraw.objects;
    window.__operationalSceneObjects = Object.freeze([...sceneObjects]);
    window.__operationalVisualObjects = preparedDraw.visuals;
    canvas.dataset.sourceEventIds = preparedDraw.sourceEventIds;
    renderer.render(scene, camera); renderCount += 1;
    document.querySelector('#event-log').replaceChildren(rows);
    document.querySelector('#gap-list').replaceChildren(gaps);
    document.querySelector('#narration-text').textContent = narration;
    document.querySelector('#narration-source').textContent = narrationSource;
    scrub.value = scrubValue;
    scrub.setAttribute('aria-valuetext', `${projected.timeNs} ns`);
    document.querySelector('#time-readout').textContent = `${projected.timeNs} ns`;
    document.body.dataset.stateDigest = stateDigest;
    state = projected;
  } catch (error) {
    for (const object of preparedDraw.objects) scene.remove(object);
    disposeObjects(preparedDraw.objects);
    sceneObjects = [];
    window.__operationalSceneObjects = Object.freeze([]);
    window.__operationalVisualObjects = Object.freeze([]);
    canvas.removeAttribute('data-source-event-ids');
    throw error;
  }
  return Object.freeze({ contributingEventIds: projected.contributingEventIds, stateDigest, timeNs: projected.timeNs });
}
function maybeInject(stage) {
  const hook = window.__operationalTestHooks;
  if (hook?.failAt !== stage || !(hook.remaining > 0)) return;
  hook.remaining -= 1;
  throw new Error(`injected ${stage} failure`);
}
function stop() { playing = false; play.textContent = reducedMotion ? 'MOTION OFF' : 'PLAY'; play.setAttribute('aria-pressed', 'false'); if (animation) cancelAnimationFrame(animation); animation = undefined; }
function transitionToFailure(error) {
  if (failed) return;
  failed = true;
  renderGeneration += 1;
  stop();
  window.__operationalReady = false;
  document.body.dataset.validation = 'failed';
  delete document.body.dataset.stateDigest;
  for (const control of controls) control.disabled = true;
  if (scene) {
    disposeSceneObjects();
    try { renderer.render(scene, camera); renderCount += 1; } catch {}
  }
  window.__operationalVisualObjects = Object.freeze([]);
  window.__operationalSceneObjects = Object.freeze([]);
  window.__operationalRendererMetadata = null;
  canvas.removeAttribute('data-source-event-ids');
  document.querySelector('#event-log').replaceChildren();
  document.querySelector('#gap-list').replaceChildren();
  document.querySelector('#narration-text').textContent = '';
  document.querySelector('#narration-source').textContent = '';
  document.querySelector('#inspector').textContent = '';
  document.querySelector('#time-readout').textContent = '';
  scrub.value = '0'; scrub.removeAttribute('aria-valuetext');
  document.querySelector('#mode-status').textContent = 'OPERATIONAL PACKAGE NOT READY';
  document.querySelector('#authority').textContent = 'Validation failed. No partial operational state is displayed.';
  const message = `OPERATIONAL PACKAGE NOT READY — ${String(error?.message || error).slice(0, 300)}`;
  const panel = document.querySelector('#load-error'); panel.textContent = message; panel.hidden = false;
  window.__operationalError = message;
  window.OPERATIONAL_PROJECT_STATE_AT = () => { throw new Error('operational package is not ready'); };
  window.OPERATIONAL_RENDER_FRAME = async () => { throw new Error('operational package is not ready'); };
  state = undefined; projector = undefined; verified = undefined;
}
async function requestState(factory, propagate = false) {
  try {
    return await applyState(factory());
  } catch (error) {
    transitionToFailure(error);
    if (propagate) throw error;
    return null;
  }
}
async function tick(now) {
  if (!playing) return;
  const elapsedNs = BigInt(Math.max(0, Math.floor((now - lastReal) * 1_000_000))); lastReal = now;
  const next = BigInt(state.timeNs) + elapsedNs; const end = BigInt(projector.finalDurationNs);
  const applied = await requestState(() => projector.projectStateAt({ timeNs: String(next > end ? end : next) }));
  if (!applied || next >= end) stop(); else animation = requestAnimationFrame(tick);
}
function setPlaying(next) {
  if (failed || reducedMotion) { stop(); return; }
  playing = next; play.textContent = playing ? 'PAUSE' : 'PLAY'; play.setAttribute('aria-pressed', String(playing));
  if (playing) { lastReal = performance.now(); animation = requestAnimationFrame(tick); } else stop();
}
play.addEventListener('click', () => setPlaying(!playing));
document.querySelector('#restart').addEventListener('click', () => { stop(); void requestState(() => projector.projectStateAt({ timeNs: '0' })); });
scrub.addEventListener('input', () => { stop(); void requestState(() => { const time = BigInt(projector.finalDurationNs) * BigInt(scrub.value) / 1_000_000n; return projector.projectStateAt({ timeNs: String(time) }); }); });
document.querySelector('#debug-toggle').addEventListener('click', (event) => { if (failed) return; const shown = document.body.classList.toggle('debug'); event.currentTarget.setAttribute('aria-pressed', String(shown)); });
canvas.addEventListener('click', (event) => {
  if (!raycaster || sceneObjects.length === 0) return;
  const box = canvas.getBoundingClientRect();
  raycaster.setFromCamera({ x: (event.clientX - box.left) / box.width * 2 - 1, y: -((event.clientY - box.top) / box.height) * 2 + 1 }, camera);
  const selected = raycaster.intersectObjects(sceneObjects, false)[0]?.object;
  if (selected) inspectEvent(selected.userData.eventId);
});
canvas.addEventListener('keydown', (event) => { if ((event.key === 'Enter' || event.key === ' ') && sceneObjects[0]) { event.preventDefault(); inspectEvent(sceneObjects[0].userData.eventId); } });

async function initialize() {
  const loaded = Object.fromEntries(await Promise.all(Object.entries(ASSETS).map(async ([key, path]) => [key, await localAsset(path)])));
  verified = await loadVerifiedOperationalPackage(loaded);
  const sites = verified.manifest.sites.map(({ siteId }) => siteId).sort();
  if (verified.header.runId !== PRODUCTION_FIXTURE.runId
      || verified.records.length !== PRODUCTION_FIXTURE.recordCount
      || verified.receipt.inputDigest !== PRODUCTION_FIXTURE.expectedInputDigest
      || verified.bootstrap.expectedInputDigest !== PRODUCTION_FIXTURE.expectedInputDigest
      || verified.header.inputReplayDigest !== PRODUCTION_FIXTURE.inputReplayDigest
      || verified.header.inputRunSeal !== PRODUCTION_FIXTURE.expectedRunSeal
      || verified.bootstrap.expectedRunSeal !== PRODUCTION_FIXTURE.expectedRunSeal
      || String(verified.bootstrap.finalDurationNs) !== PRODUCTION_FIXTURE.finalDurationNs
      || verified.receipt.outputByteLength !== PRODUCTION_FIXTURE.outputByteLength
      || verified.receipt.outputDigest !== PRODUCTION_FIXTURE.outputDigest
      || verified.header.sourceFactsDigest !== PRODUCTION_FIXTURE.sourceFactsDigest
      || JSON.stringify(sites) !== JSON.stringify(PRODUCTION_FIXTURE.sites)) throw new Error('production fixture commitment is not the complete six-gateway LIFELINE capture');
  projector = createOperationalProjector(verified);
  setupRenderer();
  const frame = new URLSearchParams(location.search).get('frame');
  const initial = frame === null ? projector.projectStateAt({ timeNs: '0' }) : projector.projectStateForFrame(Number(frame), 30);
  await applyState(initial);
  window.__operationalRendererMetadata = rendererMetadata;
  document.querySelector('#authority').textContent = verified.authority.label;
  document.querySelector('#mode-status').textContent = `VERIFIED OPERATIONAL LIFELINE · ${verified.records.length} CAPTURED EVENTS · SIX GATEWAYS · FIVE PROVIDERS`;
  for (const control of controls) control.disabled = false;
  if (reducedMotion) { play.disabled = true; play.textContent = 'MOTION OFF'; play.setAttribute('aria-label', 'Automatic playback disabled by reduced motion preference'); }
  window.OPERATIONAL_PROJECT_STATE_AT = (timeNs) => {
    if (failed) throw new Error('operational package is not ready');
    return projector.projectStateAt({ timeNs: String(timeNs) });
  };
  window.OPERATIONAL_RENDER_FRAME = (frameNumber, fps = 30) => requestState(() => projector.projectStateForFrame(frameNumber, fps), true);
  document.body.dataset.validation = 'verified'; window.__operationalReady = true;
}
initialize().catch(transitionToFailure);
