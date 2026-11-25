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

test('persistent refusal fails at the bounded attempt count', async () => {
  let calls = 0;
  let waits = 0;
  await assert.rejects(resolveReady(async () => {
    calls++;
    throw failure('ECONNREFUSED');
  }, 'api.example.test', {
    attempts: 3, wait: async () => { waits++; },
  }), /after 3 attempts: ECONNREFUSED/);
  assert.equal(calls, 3);
  assert.equal(waits, 2);
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
