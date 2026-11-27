'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
// CI only: exercise the actual extracted artifact with the same assertions.
const runnerDir = process.env.NETVERGE_TEST_RUNNER_DIR || __dirname;
const { runScript } = require(path.join(path.resolve(runnerDir), 'runner.cjs'));

function fixture(source, overrides = {}) {
  return {
    source, phase: 'http-response', timeoutMs: 1000, argument: 'approved',
    request: { method: 'GET', url: 'https://api.example.test/demo', headers: { 'X-Custom-Input': 'yes' } },
    response: { status: 200, headers: { 'Content-Type': 'application/json' }, body: '{"ok":false}' },
    ...overrides,
  };
}

test('unchanged and phase-specific response body mutations', async () => {
  assert.deepEqual(await runScript(fixture('$done()')), { ok: true, result: {} });
  assert.deepEqual(await runScript(fixture(
    'const value = JSON.parse($response.body); value.ok = $argument === "approved" && $request.method === "GET"; $done({body: JSON.stringify(value)});'
  )), { ok: true, result: { body: '{"ok":true}' } });
  const request = { method: 'POST', url: 'https://api.example.test/demo', headers: {}, body: 'old' };
  const input = { source: '$done({body: $request.body + "!"})', phase: 'http-request', timeoutMs: 1000, request };
  assert.deepEqual(await runScript(input), { ok: true, result: { body: 'old!' } });
});

test('guest globals are immutable snapshots, no host bindings or cross-call state', async () => {
  assert.deepEqual(await runScript(fixture(
    '"use strict"; if ([typeof process, typeof require, typeof fetch, typeof WebSocket, typeof $httpClient, typeof $persistentStore, typeof setTimeout].some(x => x !== "undefined")) throw 1; try {$request.headers["X-Custom-Input"] = "bad"} catch {} if ($request.headers["X-Custom-Input"] !== "yes") throw 1; globalThis.marker = 1; console.log($response.body); $done();'
  )), { ok: true, result: {} });
  assert.deepEqual(await runScript(fixture('if (typeof marker !== "undefined") throw 1; $done()')), { ok: true, result: {} });
});

test('completion is synchronous, exactly once, and cannot change after $done', async () => {
  for (const source of [
    '0', '$done(); $done();', '$done({url:"https://other.test/"})',
    '$done({body:"ok", status:undefined})', '$done({body:123})',
    '$done({get body(){return "bad"}})', '$done(null)',
    'Object.prototype.toJSON = () => ({body:"forged"});',
  ]) {
    assert.deepEqual(await runScript(fixture(source)), { ok: false, error: 'invalid-completion' }, source);
  }
  assert.deepEqual(await runScript(fixture('const r={body:"first"}; $done(r); r.body="second"')), { ok: true, result: { body: 'first' } });
  assert.equal((await runScript(fixture('$done(); throw new Error("private body")'))).error, 'script-error');
  assert.equal((await runScript(fixture('Promise.resolve().then(() => $done())'))).error, 'async-unsupported');
});

test('reject invalid input and oversize body/source; body-less scripts cannot create bodies', async () => {
  assert.equal((await runScript(fixture('$done()', { timeoutMs: 5001 }))).error, 'invalid-input');
  assert.equal((await runScript(fixture('x'.repeat(65537)))).error, 'invalid-input');
  assert.equal((await runScript(fixture('$done({body:"é".repeat(200000)})'))).error, 'invalid-completion');
  const response = { status: 200, headers: {} };
  assert.equal((await runScript(fixture('$done({body:"new"})', { response }))).error, 'invalid-completion');
});

test('infinite loop times out; failure discards even a prior completion; next invocation survives', async () => {
  const begin = Date.now();
  assert.deepEqual(await runScript(fixture('$done({body:"partial"}); while(true){}', { timeoutMs: 100 })), { ok: false, error: 'timeout' });
  assert.ok(Date.now() - begin < 5000);
  assert.deepEqual(await runScript(fixture('$done()')), { ok: true, result: {} });
});

test('memory pressure fails closed without disabling the next process', async () => {
  const response = await runScript(fixture('const a=[]; while(true) a.push(new Array(100000).fill(1));'));
  assert.equal(response.ok, false);
  assert.ok(['script-error', 'timeout', 'runner-failure'].includes(response.error));
  assert.deepEqual(await runScript(fixture('$done()')), { ok: true, result: {} });
});

test('limit concurrent invocations to four', async () => {
  const jobs = Array.from({ length: 4 }, () => runScript(fixture('$done()', { timeoutMs: 5000 })));
  assert.deepEqual(await runScript(fixture('$done()')), { ok: false, error: 'busy' });
  for (const job of await Promise.all(jobs)) assert.deepEqual(job, { ok: true, result: {} });
});
