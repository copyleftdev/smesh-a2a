#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

export const MAX_DENIAL_BYTES = 16 * 1024;
const SAFE_VALUE = /^[A-Za-z0-9_./:+,@=()& -]{1,512}$/;
const SELECTED_FIELDS = [
  'apparmor',
  'operation',
  'class',
  'profile',
  'comm',
  'family',
  'sock_type',
  'protocol',
  'requested_mask',
  'denied_mask',
];

function field(line, name) {
  const match = line.match(new RegExp(`(?:^|\\s)${name}=(?:"([^"]*)"|([^\\s]+))`));
  const value = match?.[1] ?? match?.[2];
  return value && SAFE_VALUE.test(value) ? value : undefined;
}

export function parseBrowserAuthority(input) {
  const pattern = /browser_pid=([1-9][0-9]*) browser_apparmor_label=("(?:\\.|[^"\\])*")/g;
  let selected;
  for (const match of input.matchAll(pattern)) {
    const browserPid = Number(match[1]);
    const browserAppArmorLabel = JSON.parse(match[2]);
    if (!Number.isSafeInteger(browserPid) || browserPid <= 0) continue;
    if (typeof browserAppArmorLabel !== 'string' || Buffer.byteLength(browserAppArmorLabel) > 1024 || !SAFE_VALUE.test(browserAppArmorLabel)) continue;
    selected = { browserPid, browserAppArmorLabel };
  }
  if (!selected) throw new Error('valid browser authority record unavailable');
  return selected;
}

export function filterAppArmorDenials(input, browserPid, browserAppArmorLabel, maxBytes = MAX_DENIAL_BYTES) {
  if (!Number.isSafeInteger(browserPid) || browserPid <= 0) throw new Error('browser PID must be a positive integer');
  if (typeof browserAppArmorLabel !== 'string' || Buffer.byteLength(browserAppArmorLabel) > 1024 || !SAFE_VALUE.test(browserAppArmorLabel)) {
    throw new Error('browser AppArmor label is invalid');
  }
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_DENIAL_BYTES) {
    throw new Error(`denial evidence cap must be between 1 and ${MAX_DENIAL_BYTES} bytes`);
  }
  const expectedProfile = browserAppArmorLabel.replace(/ \((?:enforce|complain|kill|mixed)\)$/, '');

  const selected = [];
  let used = 0;
  for (const line of input.split('\n')) {
    if (!line.includes('apparmor="DENIED"') || !line.includes('class="net"')) continue;
    const auditPid = Number(line.match(/(?:^|\s)pid=([1-9][0-9]*)(?:\s|$)/)?.[1]);
    const auditProfile = field(line, 'profile');
    if (!Number.isSafeInteger(auditPid) || auditPid <= 0) continue;
    if (auditPid !== browserPid && auditProfile !== expectedProfile) continue;

    const audit = line.match(/audit\(([0-9.:]+)\)/)?.[1];
    if (!audit) continue;
    const record = { audit };
    for (const name of SELECTED_FIELDS) {
      const value = field(line, name);
      if (value !== undefined) record[name] = value;
    }
    if (record.apparmor !== 'DENIED' || record.class !== 'net') continue;
    record.pid = auditPid;

    const bytes = Buffer.byteLength(`${JSON.stringify(record)}\n`);
    if (used + bytes > maxBytes) break;
    selected.push(record);
    used += bytes;
  }
  return selected;
}

async function main() {
  if (process.argv[2] === '--authority') {
    const input = await readFile(process.argv[3], 'utf8');
    if (Buffer.byteLength(input) > 32 * 1024) throw new Error('browser readiness log exceeds authority parsing cap');
    const { browserPid, browserAppArmorLabel } = parseBrowserAuthority(input);
    process.stdout.write(`${browserPid}\n${browserAppArmorLabel}\n`);
    return;
  }
  const browserPid = Number(process.argv[2]);
  const browserAppArmorLabel = process.argv[3];
  let input = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > 2 * 1024 * 1024) input = input.slice(-1024 * 1024);
  }
  for (const record of filterAppArmorDenials(input, browserPid, browserAppArmorLabel)) {
    process.stdout.write(`[CANARY-FREE browser readiness diagnostic] APPARMOR_DENIAL ${JSON.stringify(record)}\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`[CANARY-FREE browser readiness diagnostic] AppArmor denial filter failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
