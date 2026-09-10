import assert from 'node:assert/strict';
import test from 'node:test';

import { filterAppArmorDenials, parseBrowserAuthority } from './filter-apparmor-denials.mjs';

test('browser authority parser preserves the exact stacked AppArmor label', () => {
  const log = '[CANARY-FREE browser readiness diagnostic] AUTHORITY browser_pid=3301 browser_apparmor_label="bwrap//&chrome//&unpriv_bwrap (mixed)"\n';
  assert.deepEqual(parseBrowserAuthority(log), {
    browserPid: 3301,
    browserAppArmorLabel: 'bwrap//&chrome//&unpriv_bwrap (mixed)',
  });
});

test('AppArmor evidence selects only denied browser network records and safe fields', () => {
  const input = [
    'kernel: audit: type=1400 audit(1.001:7): apparmor="DENIED" operation="connect" class="net" profile="bwrap//&chrome" pid=4242 comm="chrome" family="inet" sock_type="stream" protocol=6 requested_mask="send" denied_mask="send"',
    'kernel: audit: type=1400 audit(1.002:8): apparmor="ALLOWED" operation="connect" class="net" profile="bwrap//&chrome" pid=4242 comm="chrome" family="inet"',
    'kernel: audit: type=1400 audit(1.003:9): apparmor="DENIED" operation="open" class="file" profile="bwrap//&chrome" pid=4242 comm="chrome" name="/private/fixture"',
    'kernel: audit: type=1400 audit(1.004:10): apparmor="DENIED" operation="connect" class="net" profile="other" pid=777 comm="secret-name" family="inet"',
    'kernel: audit: type=1400 audit(1.004:12): apparmor="DENIED" operation="connect" class="net" profile="bwrap//&chrome" pid=not-a-pid comm="chrome" family="inet"',
    'kernel: audit: type=1400 audit(1.005:11): apparmor="DENIED" operation="connect" class="net" profile="bwrap//&chrome" pid=4243 comm="chrome" family="inet6" sock_type="stream" protocol=6 requested_mask="send" denied_mask="send"',
  ].join('\n');

  assert.deepEqual(filterAppArmorDenials(input, 4242, 'bwrap//&chrome (mixed)'), [{
    audit: '1.001:7',
    apparmor: 'DENIED',
    operation: 'connect',
    class: 'net',
    profile: 'bwrap//&chrome',
    pid: 4242,
    comm: 'chrome',
    family: 'inet',
    sock_type: 'stream',
    protocol: '6',
    requested_mask: 'send',
    denied_mask: 'send',
  }, {
    audit: '1.005:11',
    apparmor: 'DENIED',
    operation: 'connect',
    class: 'net',
    profile: 'bwrap//&chrome',
    pid: 4243,
    comm: 'chrome',
    family: 'inet6',
    sock_type: 'stream',
    protocol: '6',
    requested_mask: 'send',
    denied_mask: 'send',
  }]);
});

test('AppArmor evidence is byte capped without partial or unallowlisted output', () => {
  const records = Array.from({ length: 100 }, (_, index) =>
    `audit: type=1400 audit(2.${index}:1): apparmor="DENIED" operation="connect" class="net" profile="chrome" pid=99 comm="chrome" family="inet" sock_type="stream" protocol=6 arbitrary="credential-${index}"`,
  ).join('\n');
  const output = filterAppArmorDenials(records, 99, 'chrome (enforce)', 512);
  const encoded = `${output.map((record) => JSON.stringify(record)).join('\n')}\n`;

  assert.ok(Buffer.byteLength(encoded) <= 512);
  assert.ok(output.length > 0 && output.length < 100);
  assert.doesNotMatch(encoded, /credential-/);
});