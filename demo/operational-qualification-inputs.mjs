import { createHash } from 'node:crypto';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const EXPECTED_INPUT_SET_DIGEST = 'sha256:4c91721207fcb756251b3f19b2bdbe576e7499e234fd023672455ce043feb826';

export const EXPECTED_OPERATIONAL_ARTIFACTS = Object.freeze([
  { byteLength: '5173', digest: 'sha256:75278b0cec2b705ca37eb6122caa5c5ad75a713948d890cb056185b82bf458cf', path: 'actors.json' },
  { byteLength: '283', digest: 'sha256:45a65b751a6231acfc50f75f9c153354cf519dd3b63e012b5c22055298700d22', path: 'browser-bootstrap.json' },
  { byteLength: '1435', digest: 'sha256:d0917240c21235378bc5ea470a5fa8570c42375bc51bd83a5e3f6e955549196a', path: 'editorial.json' },
  { byteLength: '43300', digest: 'sha256:ed0877c47e6c3ad132d0650cbdf4b20887d1b72bb61c73439824c7bc2ee51f8c', path: 'package.jsonl' },
  { byteLength: '36666', digest: 'sha256:8729ea79f461bc35b736efa742e4046d40d87a3cd431cb0e5ec556a4dc011957', path: 'public-manifest.json' },
  { byteLength: '274', digest: 'sha256:8186f1be5bc8e7432a8123cf37ae186435dce577f5632acdbc3aa9b2eb815e75', path: 'receipt.json' },
  { byteLength: '32028', digest: 'sha256:a73dd0d1d0621bd630c59473eb578848466e87d74d008fdc4cc15fb29b4ab491', path: 'restricted/canonical-capture.jsonl' },
  { byteLength: '48913', digest: 'sha256:34ffb3a504af6bedaff2b5555029b3c37d6aaf2e6d375881102227c349990481', path: 'restricted/causal-source.jsonl' },
  { byteLength: '9460', digest: 'sha256:9ff74d41c9abba4120d0377f579329407a8efd2075f92965638eecc82ede7b07', path: 'restricted/criteria-evidence.json' },
  { byteLength: '7199', digest: 'sha256:46c52ea5d8f0e9b4bd4d2de94161c21c79779fa18cf0e577e60d5464afcc6cda', path: 'restricted/decision-receipt.json' },
  { byteLength: '6839', digest: 'sha256:ec02b9d746a49be29e02d8d7c89ac892b132478a42cc274f6b7245f8c6558b16', path: 'restricted/evidence-manifest.json' },
  { byteLength: '72699', digest: 'sha256:1f1c675642e8b0ee68a1bc37c6e40afa11f1d86c7a0b7d0e31f993744c48c851', path: 'restricted/privacy-manifest.json' },
  { byteLength: '105084', digest: 'sha256:89af598ddbc6368000abae62866cbae5d8708054013c6ac94b0d245791c51c43', path: 'restricted/redaction-log.json' },
  { byteLength: '712', digest: 'sha256:706a646a3cf6d8b01d86906c893dc54bcf02d2f9775de7e7d4c9e0cdff067924', path: 'restricted/replay-receipt.json' },
  { byteLength: '7355', digest: 'sha256:3b2ef658c34aa8026b37832717b9b18c4b5d7606d418243e33899f51594fe566', path: 'restricted/review-packet.json' },
  { byteLength: '7087', digest: 'sha256:84090c4868fd3ad8ada3e3ba3beb95a9d34ee449b37c2d63305b71330a0aad68', path: 'restricted/review-receipt.json' },
  { byteLength: '51053', digest: 'sha256:896dc3dcd9368cd5978c2ec54fb1e8f0648a996da4c813ebd1507e5b8361ef90', path: 'restricted/sealed-replay.jsonl' },
  { byteLength: '7783', digest: 'sha256:f596aa28982b08e6ea9491ec4ef7cf42f47616e4205a6a431669c627857825e4', path: 'restricted/source-facts.json' },
].map(Object.freeze));

function protocolDigest(label, body) {
  const bytes = body instanceof Uint8Array ? body : new Uint8Array(body);
  const labelBytes = Buffer.from(`SMESH-A2A\0${label}\0v1\0`);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.byteLength));
  return `sha256:${createHash('sha256').update(labelBytes).update(length).update(bytes).digest('hex')}`;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  return value;
}

export async function verifyCompleteOperationalInputSet(files) {
  if (!(files instanceof Map)) throw new TypeError('synthetic probe requires the exact 18-artifact input set');
  const names = [...files.keys()].sort();
  const expectedNames = EXPECTED_OPERATIONAL_ARTIFACTS.map(({ path }) => path).sort();
  if (names.length !== expectedNames.length || names.some((name, index) => name !== expectedNames[index])) throw new Error('synthetic probe requires the exact 18-artifact input set');
  const artifacts = [];
  for (const expected of EXPECTED_OPERATIONAL_ARTIFACTS) {
    const bytes = files.get(expected.path);
    if (!(bytes instanceof Uint8Array)
        || String(bytes.byteLength) !== expected.byteLength
        || protocolDigest('operational-lifeline-acceptance-artifact', bytes) !== expected.digest) {
      throw new Error(`synthetic probe artifact does not match expected bytes: ${expected.path}`);
    }
    artifacts.push({ ...expected });
  }
  const inputSetBytes = encoder.encode(JSON.stringify(canonicalValue(artifacts)));
  const inputSetDigest = protocolDigest('operational-lifeline-acceptance-input-set', inputSetBytes);
  if (inputSetDigest !== EXPECTED_INPUT_SET_DIGEST) throw new Error('synthetic probe input-set relationship is invalid');
  return Object.freeze({ artifacts: Object.freeze(artifacts.map(Object.freeze)), inputSetDigest });
}

export async function buildCoherentSyntheticSubstitution(files, verifiedInputSet) {
  const verified = await verifyCompleteOperationalInputSet(files);
  if (verifiedInputSet?.inputSetDigest !== verified.inputSetDigest) throw new Error('synthetic probe input-set verification was not preserved');
  const records = decoder.decode(files.get('package.jsonl')).trimEnd().split('\n').map((line) => JSON.parse(line));
  const eventCount = records.slice(1).filter((record) => ['event', 'restricted'].includes(record.recordType)).length;
  if (records.length !== 47 || eventCount !== 46) throw new Error('synthetic package is not a coherent 46-event substitution');
  records[0].runId = `lifeline-substituted-${verified.inputSetDigest.slice(7, 19)}`;
  const syntheticPackage = encoder.encode(`${records.map((record) => JSON.stringify(canonicalValue(record))).join('\n')}\n`);
  const syntheticReceipt = JSON.parse(decoder.decode(files.get('receipt.json')));
  syntheticReceipt.outputByteLength = String(syntheticPackage.byteLength);
  syntheticReceipt.outputDigest = protocolDigest('operational-observatory-output', syntheticPackage);
  const syntheticFiles = new Map(files);
  syntheticFiles.set('package.jsonl', syntheticPackage);
  syntheticFiles.set('receipt.json', encoder.encode(JSON.stringify(canonicalValue(syntheticReceipt))));
  return Object.freeze({ eventCount, files: syntheticFiles, inputSetDigest: verified.inputSetDigest });
}
