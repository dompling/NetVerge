'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { planRequest, parseRuleFile, compileUrlRegex } = require('./rewrite-rules.cjs');
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

test('bounded URL regex matches original admitted URL without widening scope or recursing', () => {
  const bothHosts = new Set([host, 'other.example.test']);
  const regexLists = {
    request: [
      rule('omitted-path-regex', '', { regex: '^https://api\\.example\\.test/v[12]/items/[0-9]+(?:\\?.*)?$' }),
      rule('anded-query-regex', '/v1/items/42', { method: 'GET', regex: '\\?(?:.*?&)?flag=1(?:&|$)' }),
      rule('post-rewrite-target', '', { regex: '/rewritten(?:\\?|$)' }),
      rule('empty-without-regex', ''),
      rule('invalid-regex-closed', '', { regex: '(?=items)' }),
    ],
    response: [rule('resp-regex', '', { regex: '/items/[0-9]{1,4}(?:\\?|$)' })],
    body: [rule('body-regex', '', { regex: '^https://api\\.example\\.test/v1/items/\\d+\\?' })],
    path: [rule('regex-path', '', { regex: '^https://api\\.example\\.test/v1/items/[0-9]+(?:\\?|$)', target: '/rewritten' })],
  };

  const hit = planRequest(bothHosts, regexLists, '/v1/items/42?a=%2f&flag=1', authority, 'GET');
  assert.deepEqual(ids(hit.request), ['omitted-path-regex', 'anded-query-regex']);
  assert.deepEqual(ids(hit.response), ['resp-regex']);
  assert.deepEqual(ids(hit.body), ['body-regex']);
  assert.equal(hit.pathTarget, '/rewritten?a=%2f&flag=1');

  const noFlag = planRequest(bothHosts, regexLists, 'https://api.example.test/v1/items/42?flag=0', authority, 'GET');
  assert.deepEqual(ids(noFlag.request), ['omitted-path-regex']);
  assert.equal(noFlag.pathTarget, 'https://api.example.test/rewritten?flag=0');

  // Even when another hostname is in allowedHosts, a rule's exact host boundary prevents cross-host regex hits.
  assert.deepEqual(planRequest(bothHosts, regexLists, '/v1/items/42?flag=1', 'other.example.test:443', 'GET'),
    { request: [], response: [], body: [], pathTarget: null });
  // Overlong URLs (>2048 bytes) fail closed for regex matching while preserving exact non-regex behavior.
  const hugeQuery = '/v1/items/42?flag=1&pad=' + 'x'.repeat(2100);
  assert.deepEqual(ids(planRequest(bothHosts, regexLists, hugeQuery, authority, 'GET').request), []);
});

test('compileUrlRegex enforces RE2-subset syntax, state bounds and linear-time execution', t => {
  const match = compileUrlRegex('^https://api\\.example\\.test/(?:users|teams)/[a-zA-Z0-9._-]{1,8}(?:\\?[^#]*)?$');
  assert.equal(match('https://api.example.test/users/alice_1?tab=2'), true);
  assert.equal(match('https://api.example.test/users/too_long_identifier'), false);
  assert.equal(match('https://other.example.test/users/alice_1'), false);

  // Classic catastrophic backtracking input completes in linear time on the Thompson NFA.
  const redos = compileUrlRegex('^https://api\\.example\\.test/(a+)+$');
  const start = Date.now();
  assert.equal(redos('https://api.example.test/' + 'a'.repeat(1800) + 'b'), false);
  assert.equal(redos('https://api.example.test/' + 'a'.repeat(1800)), true);
  assert.ok(Date.now() - start < 200);

  for (const invalid of [
    '', 42, '(a)\\1', '\\k<id>', '(?=demo)', '(?!demo)', '(?<=demo)', '(?<!demo)',
    '(?i)demo', '(?<name>demo)', '\\bdemo\\b', '\\p{L}', 'a++', '()', '(?:)',
    'demo|', '|demo', 'a||b', '(a*)+', '(a?)+', '(^)+', '^*', '$?',
    '[]', '[^]', '[z-a]', '[\\d-z]', '[abc', '(abc', 'abc)', '{1,2}',
    'a{0}', 'a{0,0}', 'a{3,2}', 'a{17}', 'a}b', '(((((((((a)))))))))',
    'a'.repeat(257), '(abcdefghij){13}', 'https://api.example.test/\n',
  ]) {
    assert.throws(() => compileUrlRegex(invalid), `expected rejection for ${invalid}`);
  }

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nv-regex-rule-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'rule.json');
  const validate = item => {
    if (!/^\/[^?#\s]*$/.test(item.path)) throw new Error();
    return item;
  };
  const base = { enabled: true, host, path: '', header: 'X-Test', value: '1' };
  fs.writeFileSync(file, JSON.stringify({ version: 2, rules: [{ ...base, regex: '^https://api\\.example\\.test/v1$' }] }));
  assert.deepEqual(parseRuleFile(file, validate), [{ ...base, regex: '^https://api\\.example\\.test/v1$' }]);
  fs.writeFileSync(file, JSON.stringify({ version: 2, rules: [base] }));
  assert.throws(() => parseRuleFile(file, validate));
  fs.writeFileSync(file, JSON.stringify({ version: 2, rules: [{ ...base, regex: '(?=v1)' }] }));
  assert.throws(() => parseRuleFile(file, validate));
});
