'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { resolveReady } = require('./windows-tun-dns-readiness.cjs');

function failure(code) { return Object.assign(new Error(code), { code }); }

test('waits for a transient local DNS refusal and timeout, then returns the actual answer', async () => {
  const observed = [];
  let calls = 0;
  const result = await resolveReady(async host => {
    assert.equal(host, 'api.example.test');
    calls++;
    if (calls === 1) throw failure('ECONNREFUSED');
    if (calls === 2) throw failure('ETIMEOUT');
    return ['198.18.17.4'];
  }, 'api.example.test', {
    wait: async ms => assert.equal(ms, 250),
    onRetry: (code, attempt) => observed.push([code, attempt]),
  });
  assert.deepEqual(result, ['198.18.17.4']);
  assert.deepEqual(observed, [['ECONNREFUSED', 1], ['ETIMEOUT', 2]]);
});

test('immediate refusals cannot exhaust the readiness window early', async () => {
  let elapsed = 0;
  let calls = 0;
  const result = await resolveReady(async () => {
    calls++;
    if (elapsed < 5000) throw failure('ECONNREFUSED');
    return ['198.18.17.4'];
  }, 'api.example.test', {
    now: () => elapsed, wait: async ms => { elapsed += ms; },
  });
  assert.deepEqual(result, ['198.18.17.4']);
  assert.equal(calls, 21);
  assert.equal(elapsed, 5000);
});

test('persistent refusal fails at the elapsed deadline without a new attempt after it', async () => {
  let elapsed = 0;
  let calls = 0;
  const waits = [];
  await assert.rejects(resolveReady(async () => {
    calls++;
    throw failure('ECONNREFUSED');
  }, 'api.example.test', {
    timeoutMs: 625, now: () => elapsed,
    wait: async ms => { waits.push(ms); elapsed += ms; },
  }), /after 3 attempts in 625ms: ECONNREFUSED/);
  assert.equal(calls, 3);
  assert.deepEqual(waits, [250, 250, 125]);
});

test('DNS resolution time also consumes the readiness budget', async () => {
  let elapsed = 0;
  let calls = 0;
  await assert.rejects(resolveReady(async () => {
    calls++;
    elapsed += 900;
    throw failure('ETIMEOUT');
  }, 'api.example.test', {
    timeoutMs: 1000, now: () => elapsed, wait: async ms => { elapsed += ms; },
  }), /after 1 attempts in 1000ms: ETIMEOUT/);
  assert.equal(calls, 1);
});

test('negative DNS replies and other errors fail immediately', async () => {
  for (const code of ['ENOTFOUND', 'ENODATA', 'ESERVFAIL', 'EREFUSED', 'EBADRESP']) {
    let calls = 0;
    const error = failure(code);
    await assert.rejects(resolveReady(async () => {
      calls++;
      throw error;
    }, 'api.example.test', { wait: async () => assert.fail('unexpected retry') }),
    e => e === error);
    assert.equal(calls, 1);
  }
});
