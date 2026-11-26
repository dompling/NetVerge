'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { planRequest } = require('./rewrite-rules.cjs');

const host = 'api.example.test';
const authority = host + ':443';
const scope = new Set([host]);
const rule = (id, path = '/v1', extra = {}) => ({ id, host, path, ...extra });
const lists = {
  request: [rule('first'), rule('target', '/v2'), rule('last')],
  response: [rule('response'), rule('other-host', '/v1', { host: 'other.example.test' })],
  body: [rule('body')],
  path: [rule('first-path', '/v1', { target: '/v2' }), rule('second-path', '/v1', { target: '/v3' })],
};
const ids = rules => rules.map(r => r.id);

test('one original-path plan retains list order and chooses only the first URL rule', () => {
  const p = planRequest(scope, lists, '/v1?a=%2f&b=1&b=2', authority);
  assert.deepEqual(ids(p.request), ['first', 'last']);
  assert.deepEqual(ids(p.response), ['response']);
  assert.deepEqual(ids(p.body), ['body']);
  assert.equal(p.pathTarget, '/v2?a=%2f&b=1&b=2');
  assert.equal(planRequest(scope, lists, '/v1?', authority).pathTarget, '/v2?');
  assert.equal(planRequest(scope, lists, 'https://api.example.test/v1?x=%2F', authority).pathTarget,
    'https://api.example.test/v2?x=%2F');
});

test('a target path never causes a second match within the original plan', () => {
  const p = planRequest(scope, lists, '/v1', authority);
  assert.ok(!ids(p.request).includes('target'));
  lists.request.push(rule('new', '/v1'));
  try { assert.deepEqual(ids(p.request), ['first', 'last']); }
  finally { lists.request.pop(); }
});

test('non-admitted scope, wrong port, userinfo and cross-host URLs cannot match', () => {
  const empty = { request: [], response: [], body: [], pathTarget: null };
  for (const [url, a] of [
    ['/v1', 'other.example.test:443'], ['/v1', host + ':8443'],
    ['https://other.example.test/v1', authority], ['//other.example.test/v1', authority],
    ['https://user@api.example.test/v1', authority], ['http://api.example.test/v1', authority],
    ['https://api.example.test/v1#fragment', authority], ['https://[invalid', authority],
    ['/v1/extra', authority],
  ]) assert.deepEqual(planRequest(scope, lists, url, a), empty);
});

test('no authority can match if the allowed MITM scope is empty', () => {
  assert.deepEqual(planRequest(new Set(), lists, '/v1', authority),
    { request: [], response: [], body: [], pathTarget: null });
});
