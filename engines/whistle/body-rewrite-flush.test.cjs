'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { gzipSync } = require('node:zlib');
const test = require('node:test');
const { installBodyRewrite, createResponsePreview } = require('./body-rewrite.cjs');

const limit = 256 * 1024;
const plainText = 'text/plain';
const cases = [
  ['application/json', '{"marker":"original"}', '{"marker":"new"}'],
  ['text/plain; charset=utf-8', '原文 original', '原文 new'],
  ['text/html', '<p>original</p>', '<p>new</p>'],
  ['text/event-stream', 'data: original\n\n'],
  ['application/octet-stream', 'original'],
  [plainText, 'x'.repeat(limit / 4), '🌳'.repeat(limit / 4), [{ search: 'x', value: '🌳' }], 'exact UTF-8 limit'],
  [plainText, 'x'.repeat(limit / 4) + '!', undefined, [
    { search: 'x', value: 'y' }, { search: 'y', value: '🌳' },
  ], 'second rule exceeds limit by one byte'],
  [plainText, 'original', '$&', [{ search: 'original', value: '$&' }], 'literal replacement'],
  [plainText, 'original', 'new', [{ search: 'original', value: 'new', match_whole: true }], 'whole body match'],
  [plainText, 'original\n', undefined, [{ search: 'original', value: 'new', match_whole: true }], 'whole body mismatch'],

];

for (const [contentType, original, rewritten, rules = [{ search: 'original', value: 'new' }], label = contentType] of cases) {
  test(`flushing a streamed gzip response with ${label}`, async t => {
    const compressed = gzipSync(original);
    let hits = 0;
    const server = http.createServer((req, res) => {
      installBodyRewrite(req, res, rules, () => { hits++; });
      res.writeHead(200, undefined, {
        'Content-Type': contentType,
        'Content-Encoding': 'gzip',
        'Content-Length': compressed.length,
        'ETag': '"original"',
      });
      res.flushHeaders();
      res.write(compressed.subarray(0, 5));
      res.end(compressed.subarray(5));
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));
    const request = http.get({ host: '127.0.0.1', port: server.address().port, agent: false, signal: AbortSignal.timeout(5000) });
    const [response] = await once(request, 'response');
    const chunks = [];
    for await (const chunk of response) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    if (rewritten === undefined) {
      assert.equal(body.length, compressed.length);
      assert.deepEqual(body, compressed);
      assert.equal(response.headers['content-encoding'], 'gzip');
      assert.equal(response.headers.etag, '"original"');
      assert.equal(hits, 0);
      return;
    }
    assert.equal(body.toString(), rewritten);
    assert.equal(response.headers['content-length'], String(body.length));
    assert.equal(response.headers['content-encoding'], undefined);
    assert.equal(response.headers.etag, undefined);
    assert.equal(hits, 1);
  });
}

test('one-shot JSON preview observes final bytes, redacts keys and never changes forwarding', async t => {
  const preview = createResponsePreview(key => /token|password/i.test(key));
  const entries = [];
  const server = http.createServer((req, res) => {
    const entry = {};
    entries.push(entry);
    preview.attach(req, res, entry);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write('{"marker":"ok",');
    res.end('"accessToken":"secret","nested":{"password":"hidden"}}');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { preview.cancel(); return new Promise(resolve => server.close(resolve)); });
  const read = async () => {
    const [response] = await once(http.get({ host: '127.0.0.1', port: server.address().port, agent: false, signal: AbortSignal.timeout(5000) }), 'response');
    const chunks = [];
    for await (const chunk of response) chunks.push(chunk);
    assert.equal(Buffer.concat(chunks).toString(), '{"marker":"ok","accessToken":"secret","nested":{"password":"hidden"}}');
  };
  await read();
  assert.deepEqual(entries[0], {});
  preview.arm();
  await read();
  assert.equal(entries[1].responsePreview, '{"marker":"ok","accessToken":"[redacted]","nested":{"password":"[redacted]"}}');
  await read();
  assert.deepEqual(entries[2], {});
  preview.arm();
  preview.cancel();
  await read();
  assert.deepEqual(entries[3], {});
});

test('preview skips invalid, compressed, oversized and non-JSON responses; rewritten JSON is observed', async t => {
  const preview = createResponsePreview(() => false);
  const entries = [];
  const cases = [
    ['application/json', Buffer.from('{"a":'), undefined, false],
    ['application/json', gzipSync('{"a":1}'), 'gzip', false],
    ['application/json', Buffer.from(JSON.stringify({ a: 'x'.repeat(2048) })), undefined, false],
    ['text/plain', Buffer.from('{"a":1}'), undefined, false],
    ['application/json', gzipSync('{"a":"original"}'), 'gzip', true],
  ];
  const server = http.createServer((req, res) => {
    const entry = {};
    const [ct, bytes, encoding, rewrite] = cases[entries.length];
    entries.push(entry);
    preview.attach(req, res, entry);
    if (rewrite) installBodyRewrite(req, res, [{ search: 'original', value: 'new' }], () => {});
    res.writeHead(200, { 'Content-Type': ct, ...(encoding ? { 'Content-Encoding': encoding } : {}) });
    res.end(bytes);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { preview.cancel(); return new Promise(resolve => server.close(resolve)); });
  for (const [ct, bytes, encoding, rewrite] of cases) {
    preview.arm();
    const [response] = await once(http.get({ host: '127.0.0.1', port: server.address().port, agent: false, signal: AbortSignal.timeout(5000) }), 'response');
    const chunks = [];
    for await (const chunk of response) chunks.push(chunk);
    assert.deepEqual(Buffer.concat(chunks), rewrite ? Buffer.from('{"a":"new"}') : bytes);
    assert.equal(entries.at(-1).responsePreview, rewrite ? '{"a":"new"}' : undefined);
  }
});
