import assert from 'node:assert/strict';
import test from 'node:test';

import { waitForMainFrame } from './frame-readiness.mjs';

test('main-frame readiness retries only the transient Puppeteer assertion', async () => {
  let attempts = 0;
  const frame = {};
  const page = {
    mainFrame() {
      attempts += 1;
      if (attempts < 3) throw new Error('Requesting main frame too early!');
      return frame;
    },
  };

  assert.equal(await waitForMainFrame(page, { timeoutMs: 50, pollMs: 1 }), frame);
  assert.equal(attempts, 3);
});

test('main-frame readiness does not retry other failures', async () => {
  let attempts = 0;
  const failure = new Error('CDP session closed');
  const page = {
    mainFrame() {
      attempts += 1;
      throw failure;
    },
  };

  await assert.rejects(
    waitForMainFrame(page, { timeoutMs: 50, pollMs: 1 }),
    (error) => error === failure,
  );
  assert.equal(attempts, 1);
});

test('main-frame readiness has a tight bounded timeout', async () => {
  let now = 0;
  let attempts = 0;
  const page = {
    mainFrame() {
      attempts += 1;
      throw new Error('Requesting main frame too early!');
    },
  };

  await assert.rejects(
    waitForMainFrame(page, {
      timeoutMs: 20,
      pollMs: 5,
      now: () => now,
      sleep: async (delay) => { now += delay; },
    }),
    /main frame was not ready within 20ms/,
  );
  assert.equal(attempts, 4);
});

test('main-frame readiness times out after a late wake without another attempt', async () => {
  let now = 0;
  let attempts = 0;
  const transient = new Error('Requesting main frame too early!');
  const page = {
    mainFrame() {
      attempts += 1;
      if (attempts === 1) throw transient;
      return {};
    },
  };

  await assert.rejects(
    waitForMainFrame(page, {
      timeoutMs: 500,
      pollMs: 10,
      now: () => now,
      sleep: async () => { now = 501; },
    }),
    (error) => {
      assert.match(error.message, /main frame was not ready within 500ms/);
      assert.equal(error.cause, transient);
      return true;
    },
  );
  assert.equal(attempts, 1);
});