'use strict';

const { setTimeout: sleep } = require('node:timers/promises');

// Only a local DNS listener's transient startup errors are retryable.
// Never retry invalid answers, certificate failures, routing assertions or
// application requests: those remain hard failures in the TUN acceptance.
async function resolveReady(resolve, host, { attempts = 16, wait = sleep, onRetry = () => {} } = {}) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await resolve(host);
    } catch (error) {
      if (!['ECONNREFUSED', 'ETIMEOUT'].includes(error.code)) throw error;
      if (attempt === attempts) {
        throw new Error('Local DNS listener not ready for ' + host + ' after ' + attempts +
          ' attempts: ' + error.code, { cause: error });
      }
      onRetry(error.code, attempt);
      await wait(250);
    }
  }
  throw new Error('Invalid DNS readiness attempt count');
}

module.exports = { resolveReady };
