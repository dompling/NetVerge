'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { planRequest, parseRuleFile } = require('./rewrite-rules.cjs');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

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

test('method conditions share original host/path matching and preserve order', () => {
  const common = [rule('any'), rule('get', '/v1', { method: 'GET' }), rule('post', '/v1', { method: 'POST' })];
  const byMethod = {
    request: common, response: common, body: common,
    path: [rule('post-path', '/v1', { method: 'POST', target: '/post' }),
      rule('get-path', '/v1', { method: 'GET', target: '/get' })],
  };
  for (const [method, expected, target] of [
    ['GET', ['any', 'get'], '/get?q=%2f'],
    ['POST', ['any', 'post'], '/post?q=%2f'],
    ['PUT', ['any'], null],
    [undefined, ['any'], null],
  ]) {
    const p = planRequest(scope, byMethod, '/v1?q=%2f', authority, method);
    for (const phase of ['request', 'response', 'body']) assert.deepEqual(ids(p[phase]), expected);
    assert.equal(p.pathTarget, target);
  }
});

test('legacy and v2 files normalize optional methods without broadening invalid rules', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-method-rule-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'rule.json');
  const action = { enabled: true, host, path: '/v1', header: 'X-Test', value: '1' };
  const validate = item => {
    assert.deepEqual(item, action);
    return item;
  };
  for (const method of [undefined, null, 'GET', 'POST']) {
    fs.writeFileSync(file, JSON.stringify({ version: 2, rules: [{ ...action, method }] }));
    assert.deepEqual(parseRuleFile(file, validate), [method == null ? action : { ...action, method }]);
  }
  fs.writeFileSync(file, JSON.stringify(action));
  assert.deepEqual(parseRuleFile(file, validate), [action]);
  for (const method of ['get', '', '*', 'CONNECT', 'TRACE', 42, ['GET']]) {
    fs.writeFileSync(file, JSON.stringify({ version: 2, rules: [{ ...action, method }] }));
    assert.throws(() => parseRuleFile(file, validate));
  }
});
