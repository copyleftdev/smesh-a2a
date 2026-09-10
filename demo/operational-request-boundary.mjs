import { closeServer as closeNodeServer } from './export-utils.mjs';

const INTERCEPTION_FAILURE = 'browser request interception failed';
const CLEANUP_FAILURE = 'qualification cleanup failed';

export function createRequestSettlement(page, handleRequest) {
  const pending = new Set();
  const failures = [];
  let accepting = true;
  let settlement;

  const listener = (request) => {
    if (!accepting) return;
    const operation = Promise.resolve()
      .then(() => handleRequest(request))
      .catch(async () => {
        failures.push(INTERCEPTION_FAILURE);
        if (!request.isInterceptResolutionHandled()) {
          try {
            await request.abort('failed');
          } catch {
            failures.push(INTERCEPTION_FAILURE);
          }
        }
      });
    pending.add(operation);
    void operation.then(() => pending.delete(operation));
  };
  page.on('request', listener);

  return {
    settle() {
      if (!settlement) {
        accepting = false;
        page.off('request', listener);
        settlement = (async () => {
          while (pending.size !== 0) await Promise.all([...pending]);
          if (failures.length !== 0) throw new Error(INTERCEPTION_FAILURE);
        })();
      }
      return settlement;
    },
  };
}

export async function cleanupQualification({
  browser,
  requestSettlements = [],
  server,
  closeServer = closeNodeServer,
}) {
  const attempts = [];
  for (const boundary of requestSettlements) {
    try {
      attempts.push(Promise.resolve(boundary.settle()));
    } catch (error) {
      attempts.push(Promise.reject(error));
    }
  }
  if (browser) attempts.push(Promise.resolve().then(() => browser.close()));
  attempts.push(Promise.resolve().then(() => closeServer(server)));
  const results = await Promise.allSettled(attempts);
  if (results.some(({ status }) => status === 'rejected') || server?.listening) {
    throw new Error(CLEANUP_FAILURE);
  }
}
