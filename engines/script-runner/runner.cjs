'use strict';

// Stage 8.7a: a disposable process for each invocation. No HTTP worker hookup
// until the Windows isolation/approval gates are complete.
const { spawn } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const path = require('node:path');

const MAX_BODY = 256 * 1024;
const MAX_SOURCE = 64 * 1024;
const MAX_WIRE = 512 * 1024;
const MAX_CONCURRENT = 4;
const WINDOWS_JOB = path.join(__dirname, 'netverge-script-job.exe');
let active = 0;

const fail = error => ({ ok: false, error });
const record = value => value !== null && typeof value === 'object' &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const fields = (value, allowed) => record(value) &&
  Object.keys(value).every(key => allowed.includes(key));
const bounded = (value, bytes) => typeof value === 'string' && Buffer.byteLength(value) <= bytes;
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function validHeaders(headers) {
  return record(headers) && Object.keys(headers).length <= 64 &&
    Object.entries(headers).every(([key, value]) =>
      /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/.test(key) && bounded(value, 4096));
}

function validInvocation(input) {
  if (!fields(input, ['source', 'phase', 'request', 'response', 'argument', 'timeoutMs']) ||
      !bounded(input.source, MAX_SOURCE) || !input.source.length ||
      !['http-request', 'http-response'].includes(input.phase) ||
      !Number.isInteger(input.timeoutMs) || input.timeoutMs < 50 || input.timeoutMs > 5000 ||
      (own(input, 'argument') && !bounded(input.argument, 4096))) return false;
  const request = input.request;
  if (!fields(request, ['url', 'method', 'headers', 'body']) ||
      !bounded(request.url, 4096) || !/^https:\/\/[^/\s]+(?:\/[^\s]*)?$/.test(request.url) ||
      typeof request.method !== 'string' || !/^[A-Z]{1,16}$/.test(request.method) ||
      !validHeaders(request.headers) ||
      (own(request, 'body') && !bounded(request.body, MAX_BODY))) return false;
  if (input.phase === 'http-request') return !own(input, 'response');
  const response = input.response;
  return fields(response, ['status', 'headers', 'body']) &&
    Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 &&
    validHeaders(response.headers) &&
    (!own(response, 'body') || bounded(response.body, MAX_BODY));
}

function bodyAllowed(input) {
  return own(input.phase === 'http-request' ? input.request : input.response, 'body');
}

function validResult(result, input) {
  return fields(result, ['body']) &&
    (!own(result, 'body') || (bodyAllowed(input) && bounded(result.body, MAX_BODY)));
}

// This function is serialized into QuickJS, not called in Node. It exposes no
// host callbacks. The completion value is a bounded, primitive JSON string;
// even later mutations to guest intrinsics cannot forge the call counter.
function guestBootstrap(snapshot) {
  function freeze(value) {
    if (value !== null && typeof value === 'object') {
      for (const child of Object.values(value)) freeze(child);
      Object.freeze(value);
    }
    return value;
  }
  const stringify = JSON.stringify;
  const ownKeys = Reflect.ownKeys;
  const descriptor = Object.getOwnPropertyDescriptor;
  const isArray = Array.isArray;
  const allowBody = snapshot.allowBody;
  let calls = 0;
  let valid = true;
  let result = '{}';
  function done(value) {
    calls++;
    if (calls !== 1) { valid = false; return; }
    if (value === undefined) return;
    try {
      if (value === null || typeof value !== 'object' || isArray(value)) {
        valid = false; return;
      }
      const names = ownKeys(value);
      if (names.length === 0) return;
      if (names.length !== 1 || names[0] !== 'body' || !allowBody) {
        valid = false; return;
      }
      const property = descriptor(value, 'body');
      if (!property || typeof property.value !== 'string' || property.value.length > 262144) {
        valid = false; return;
      }
      result = '{"body":' + stringify(property.value) + '}';
    } catch {
      valid = false;
    }
  }
  const globals = {
    $request: { value: freeze(snapshot.request) },
    $argument: { value: snapshot.argument },
    $done: { value: done },
    // Deliberately drop script logs until a sanitized logging broker exists.
    console: { value: freeze({ log() {} }) },
  };
  if (snapshot.response !== undefined) globals.$response = { value: freeze(snapshot.response) };
  Object.defineProperties(globalThis, globals);
  return () => calls === 1 && valid ? result : '';
}

async function evaluate(input) {
  const { getQuickJS } = require('quickjs-emscripten');
  const QuickJS = await getQuickJS();
  const runtime = QuickJS.newRuntime();
  let context;
  let finish;
  let timedOut = false;
  const deadline = performance.now() + input.timeoutMs;
  try {
    runtime.setMemoryLimit(16 * 1024 * 1024);
    runtime.setMaxStackSize(512 * 1024);
    runtime.setInterruptHandler(() => {
      if (performance.now() >= deadline) timedOut = true;
      return timedOut;
    });
    context = runtime.newContext();
    const snapshot = {
      request: input.request,
      response: input.response,
      argument: input.argument ?? '',
      allowBody: bodyAllowed(input),
    };
    // Encode data as a string literal; never interpolate it as executable code.
    const init = context.evalCode(
      '(' + guestBootstrap.toString() + ')(JSON.parse(' +
      JSON.stringify(JSON.stringify(snapshot)) + '))', 'bootstrap.js', { type: 'global' });
    if (init.error) { init.error.dispose(); return fail(timedOut ? 'timeout' : 'runner-failure'); }
    finish = init.value;
    const execution = context.evalCode(input.source, 'module-script.js', { type: 'global' });
    if (execution.error) {
      execution.error.dispose();
      return fail(timedOut ? 'timeout' : 'script-error');
    }
    execution.value.dispose();
    // No timers, promises/jobs, module loader, network or persistent state in v1.
    if (runtime.hasPendingJob()) return fail('async-unsupported');
    const completed = context.callFunction(finish, context.undefined);
    if (completed.error) {
      completed.error.dispose();
      return fail(timedOut ? 'timeout' : 'script-error');
    }
    let encoded;
    try { encoded = context.getString(completed.value); }
    finally { completed.value.dispose(); }
    if (timedOut || performance.now() >= deadline) return fail('timeout');
    if (!encoded || !bounded(encoded, MAX_WIRE)) return fail('invalid-completion');
    const result = JSON.parse(encoded);
    return validResult(result, input) ? { ok: true, result } : fail('invalid-completion');
  } finally {
    if (finish) finish.dispose();
    if (context) context.dispose();
    runtime.dispose();
  }
}

async function childMain() {
  const chunks = [];
  let length = 0;
  try {
    for await (const chunk of process.stdin) {
      length += chunk.length;
      if (length > MAX_WIRE) { process.stdout.write(JSON.stringify(fail('invalid-input'))); return; }
      chunks.push(chunk);
    }
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const answer = validInvocation(input) ? await evaluate(input) : fail('invalid-input');
    const output = JSON.stringify(answer);
    process.stdout.write(bounded(output, MAX_WIRE) ? output : JSON.stringify(fail('invalid-completion')));
  } catch {
    // No script text, user data, exception strings or stack traces leave the process.
    process.stdout.write(JSON.stringify(fail('runner-failure')));
  }
}

function runScript(input) {
  let wire;
  let snapshot;
  try {
    wire = JSON.stringify(input);
    if (!bounded(wire, MAX_WIRE)) return Promise.resolve(fail('invalid-input'));
    snapshot = JSON.parse(wire);
    if (!validInvocation(snapshot)) return Promise.resolve(fail('invalid-input'));
  } catch {
    return Promise.resolve(fail('invalid-input'));
  }
  if (active >= MAX_CONCURRENT) return Promise.resolve(fail('busy'));
  active++;
  return new Promise(resolve => {
    let child;
    let timer;
    let reason;
    let size = 0;
    const chunks = [];
    function finish(answer) {
      clearTimeout(timer);
      active--;
      resolve(answer);
    }
    function stop(error) {
      reason ||= error;
      if (child && !child.killed) child.kill();
    }
    try {
      // Do not inherit NODE_OPTIONS, proxy settings, secrets or application IPC.
      const env = {};
      if (process.platform === 'win32') {
        for (const key of ['SystemRoot', 'WINDIR']) {
          if (process.env[key]) env[key] = process.env[key];
        }
      }
      // Windows never falls back to an uncontained child. The trusted launcher
      // joins a kill-on-close Job Object before it starts Node.
      const windows = process.platform === 'win32';
      const executable = windows ? WINDOWS_JOB : process.execPath;
      const args = windows
        ? [process.execPath, __filename, String(snapshot.timeoutMs + 1500)]
        : ['--max-old-space-size=64', __filename];
      child = spawn(executable, args, {
        cwd: __dirname, env, windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'],
      });
    } catch {
      finish(fail('runner-failure'));
      return;
    }
    // Startup allowance is separate from the guest's execution deadline.
    timer = setTimeout(() => stop('timeout'), snapshot.timeoutMs + 1500);
    child.on('error', () => stop('runner-failure'));
    child.stdin.on('error', () => stop('runner-failure'));
    child.stdout.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_WIRE) { stop('invalid-completion'); return; }
      if (!reason) chunks.push(chunk);
    });
    child.once('close', (code, signal) => {
      if (reason || code !== 0 || signal) { finish(fail(reason || (process.platform === 'win32' && code === 124 ? 'timeout' : 'runner-failure'))); return; }
      try {
        const response = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (fields(response, ['ok', 'result']) && response.ok === true && validResult(response.result, snapshot)) {
          finish({ ok: true, result: response.result }); return;
        }
        const errors = ['invalid-input', 'runner-failure', 'timeout', 'script-error', 'async-unsupported', 'invalid-completion'];
        if (fields(response, ['ok', 'error']) && response.ok === false && errors.includes(response.error)) {
          finish(fail(response.error)); return;
        }
      } catch { /* malformed child output */ }
      finish(fail('runner-failure'));
    });
    child.stdin.end(wire);
  });
}

if (require.main === module) childMain();
module.exports = { runScript };
