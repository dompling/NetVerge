'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { gzipSync } = require('node:zlib');
const test = require('node:test');
const { installBodyRewrite } = require('./body-rewrite.cjs');

test('flushing headers before a streamed gzip response preserves the rewritten body', async t => {
  const compressed = gzipSync('{"marker":"original"}');
  let hits = 0;
  const server = http.createServer((req, res) => {
    installBodyRewrite(req, res, [{ search: 'original', value: 'new' }], () => { hits++; });
    res.writeHead(200, undefined, {
      'Content-Type': 'application/json',
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
  assert.equal(body.toString(), '{"marker":"new"}');
  assert.equal(response.headers['content-length'], String(body.length));
  assert.equal(response.headers['content-encoding'], undefined);
  assert.equal(response.headers.etag, undefined);
  assert.equal(hits, 1);
});
