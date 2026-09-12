const TRANSIENT_MAIN_FRAME_ERROR = 'Requesting main frame too early!';

const defaultSleep = (delay) => new Promise((resolve) => setTimeout(resolve, delay));

export async function waitForMainFrame(page, {
  timeoutMs = 500,
  pollMs = 10,
  now = () => performance.now(),
  sleep = defaultSleep,
} = {}) {
  const deadline = now() + timeoutMs;
  let firstAttempt = true;
  let lastTransientError;
  while (true) {
    if (!firstAttempt && now() >= deadline) {
      throw new Error(`Puppeteer main frame was not ready within ${timeoutMs}ms`, {
        cause: lastTransientError,
      });
    }
    firstAttempt = false;
    try {
      return page.mainFrame();
    } catch (error) {
      if (String(error?.message ?? error) !== TRANSIENT_MAIN_FRAME_ERROR) throw error;
      lastTransientError = error;
      if (now() >= deadline) {
        throw new Error(`Puppeteer main frame was not ready within ${timeoutMs}ms`, {
          cause: error,
        });
      }
      await sleep(Math.min(pollMs, Math.max(0, deadline - now())));
    }
  }
}