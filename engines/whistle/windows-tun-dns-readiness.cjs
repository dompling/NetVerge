'use strict';

const { setTimeout: sleep } = require('node:timers/promises');
const { performance } = require('node:perf_hooks');

// Only a local DNS listener's transient startup errors are retryable.
// Never retry invalid answers, certificate failures, routing assertions or
// application requests: those remain hard failures in the TUN acceptance.
async function resolveReady(resolve, host, {
  timeoutMs = 15000, wait = sleep, now = () => performance.now(), onRetry = () => {},
} = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Invalid DNS readiness timeout');
  const started = now();
  const deadline = started + timeoutMs;
  let attempt = 0;
  let lastError;
  while (now() < deadline || attempt === 0) {
    attempt++;
    try {
      return await resolve(host);
    } catch (error) {
      if (!['ECONNREFUSED', 'ETIMEOUT'].includes(error.code)) throw error;
      lastError = error;
      const remaining = deadline - now();
      if (remaining <= 0) break;
      onRetry(error.code, attempt);
      await wait(Math.min(250, remaining));
    }
  }
  throw new Error('Local DNS listener not ready for ' + host + ' after ' +
    attempt + ' attempts in ' + Math.round(now() - started) + 'ms: ' +
    lastError.code, { cause: lastError });
}

module.exports = { resolveReady };
