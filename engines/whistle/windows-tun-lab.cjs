'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const zlib = require('node:zlib');
const { X509Certificate } = require('node:crypto');
const { Resolver } = require('node:dns/promises');
const { resolveReady } = require('./windows-tun-dns-readiness.cjs');
const { execFileSync } = require('node:child_process');
const { makeCertificates, startLabDns, listen, dialTun } = require('./mitm-lab.cjs');

const selected = 'api.example.test';
const bypass = 'bypass.example.test';
const hosts = [selected, bypass];
const body = 'netverge-windows-tun-origin';

async function serve(dir) {
  const certs = makeCertificates(hosts);
  fs.writeFileSync(path.join(dir, 'origin-ca.pem'), certs.ca);
  fs.writeFileSync(path.join(dir, 'origin-leaf.pem'), certs.cert);
  fs.writeFileSync(path.join(dir, 'exit-observations'), '');
  const dns = await startLabDns(hosts);
  dns.on('error', err => { throw err; });
  const origin = https.createServer({ key: certs.key, cert: certs.cert }, (req, res) => {
    const [pathname, rawQuery = ''] = req.url.split('?');
    if (!['/netverge-proof', '/demo', '/demo/other', '/changed'].includes(pathname) || req.headers['proxy-authorization'] || req.headers['x-whistle-tunnel-data']) {
      res.writeHead(400).end();
      return;
    }
    res.setHeader('X-Observed-Path', req.url);
    res.setHeader('X-NetVerge-Test', 'origin');
    res.setHeader('X-NetVerge-Observed-Request', req.headers['x-custom-netverge-test'] ?? 'missing');
    res.setHeader('Set-Cookie', 'nv_session=origin-sensitive-secret; HttpOnly');
    if (rawQuery === 'oversize=1') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.write(body + ':');
      const block = Buffer.alloc(60000, 'x');
      for (let i = 0; i < 5; i++) res.write(block);
      res.end(block);
      return;
    }
    if (rawQuery === 'binary=1') {
      res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
      res.end(Buffer.from(body, 'utf8'));
      return;
    }
    if (req.headers['x-netverge-body-probe'] === 'gzip') {
      const gz = zlib.gzipSync(Buffer.from(JSON.stringify({ marker: body, path: pathname }), 'utf8'));
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Encoding': 'gzip',
        'ETag': '"origin-etag"',
        'Content-Length': String(gz.length),
      });
      res.end(gz);
      return;
    }
    res.end(body);
  });
  const originPort = await listen(origin);
  const exit = http.createServer((_, res) => res.writeHead(403).end());
  exit.on('connect', (req, socket, head) => {
    if (!hosts.some(host => req.url === host + ':443')) {
      socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }
    fs.appendFileSync(path.join(dir, 'exit-observations'), req.url + '\n');
    const source = net.connect(originPort, '127.0.0.1');
    source.once('connect', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) source.write(head);
      socket.pipe(source).pipe(socket);
    });
    source.on('error', () => socket.destroy());
    socket.on('error', () => source.destroy());
    socket.once('close', () => source.destroy());
    source.once('close', () => socket.destroy());
  });
  const exitPort = await listen(exit);
  console.log(JSON.stringify({ exitPort, upstreamDnsPort: dns.address().port }));
}

async function fakeAddress(port, host) {
  // Local link health can be published before the new DNS listener binds.
  // Allow retries for 15 seconds of elapsed time, plus at most the final
  // resolver attempt (configured below); immediate refusals cannot exhaust it early.
  // Each attempt uses a fresh resolver rather than a previous core's socket.
  const [ip] = await resolveReady(name => {
    const resolver = new Resolver({ timeout: 900, tries: 1 });
    resolver.setServers(['127.0.0.1:' + port]);
    return resolver.resolve4(name);
  }, host, {
    onRetry: (code, attempt) => console.log('Waiting for local DNS listener: ' + host + ' (' + code + ', attempt ' + attempt + ')'),
  });
  assert.match(ip, /^198\.18\.17\.(?:[4-9]|[1-9][0-9]{1,2})$/);
  const route = execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command',
    `$ErrorActionPreference='Stop'
     $deadline = [Diagnostics.Stopwatch]::StartNew()
     do {
       $route = Find-NetRoute -RemoteIPAddress '${ip}' | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | ForEach-Object { $_.InterfaceAlias + ' ' + $_.DestinationPrefix }
       if ($route -eq 'NV-MITM-CI 198.18.17.0/24') { break }
       Start-Sleep -Milliseconds 250
     } while ($deadline.Elapsed.TotalSeconds -lt 10)
     $route`,
  ], { encoding: 'utf8', timeout: 15000, windowsHide: true }).trim();
  assert.equal(route, 'NV-MITM-CI 198.18.17.0/24', 'Windows must route the resolved fake IP through the CI TUN');
  return ip;
}

function decodeHttpResponse(raw) {
  const sep = raw.indexOf('\r\n\r\n');
  assert.ok(sep > 0, 'missing HTTP header delimiter');
  const head = raw.subarray(0, sep).toString('utf8');
  let payload = raw.subarray(sep + 4);
  if (/^transfer-encoding:\s*chunked\b/im.test(head)) {
    const out = [];
    let offset = 0;
    while (offset < payload.length) {
      const lineEnd = payload.indexOf('\r\n', offset);
      assert.ok(lineEnd > offset, 'invalid chunk header');
      const size = Number.parseInt(payload.subarray(offset, lineEnd).toString('ascii').split(';')[0], 16);
      offset = lineEnd + 2;
      if (size === 0) break;
      out.push(payload.subarray(offset, offset + size));
      offset += size + 2;
    }
    return { head, body: Buffer.concat(out), chunked: true };
  }
  const clMatch = head.match(/^content-length:\s*(\d+)\s*$/im);
  if (clMatch) assert.equal(payload.length, Number(clMatch[1]), 'Content-Length mismatch on wire');
  return { head, body: payload, chunked: false };
}

async function probe(dir, port, mode, rewrite) {
  const log = path.join(dir, 'exit-observations');
  const originCA = fs.readFileSync(path.join(dir, 'origin-ca.pem'));
  const originLeaf = new X509Certificate(fs.readFileSync(path.join(dir, 'origin-leaf.pem')));
  const bodyRewrite = rewrite === 'body-on' || rewrite === 'body-off';
  const cases = bodyRewrite
    ? [[selected, '/demo'], [selected, '/demo/other'], [selected, '/demo?oversize=1'], [selected, '/demo?binary=1'], [bypass, '/demo']]
    : rewrite ? [[selected, '/demo'], [selected, '/demo/other'], [bypass, '/demo']]
    : hosts.map(host => [host, '/netverge-proof']);
  for (const [host, requestPath] of cases) {
    const ip = await fakeAddress(port, host);
    const before = fs.readFileSync(log, 'utf8');
    if (mode === 'pending') {
      await assert.rejects(dialTun(ip, host, 443, originCA, 2200),
        /TUN\/TLS timeout|ECONNRESET|socket disconnected before secure TLS connection|TUN closed without response/);
      assert.equal(fs.readFileSync(log, 'utf8'), before, 'a fenced connection reached the original exit');
      continue;
    }
    const intercepted = mode === 'enabled' && host === selected;
    const ca = intercepted
      ? new X509Certificate(fs.readFileSync(path.join(dir, 'whistle.der'))).toString()
      : originCA;
    const activeDemo = intercepted && requestPath === '/demo';
    const removeHeaders = rewrite === 'module-remove';
    const requestRewrite = removeHeaders || rewrite === 'request-on' || rewrite === 'request-off';
    const pathRewrite = rewrite === 'path-on' || rewrite === 'path-off';
    const queryProbe = removeHeaders || rewrite === 'module-pending';
    const keptQuery = '?id=7&id=8&raw=a%2Fb+%2f&Debug=keep';
    const query = queryProbe ? keptQuery + '&debug=1&%64ebug=2&debug' :
      pathRewrite ? '?id=7&id=8&raw=a%2Fb' : '';
    const extraHeaders = bodyRewrite && !requestPath.includes('?') ? 'X-NetVerge-Body-Probe: gzip\r\n' : '';
    const result = await dialTun(ip, host, 443, ca, 15000, requestPath + query, requestRewrite, extraHeaders);
    assert.match(result.response, /^HTTP\/1\.[01] 200 /);
    if (bodyRewrite) {
      const decoded = decodeHttpResponse(result.raw);
      if (requestPath === '/demo?oversize=1') {
        assert.equal(decoded.body.length, body.length + 1 + 360000, 'oversized stream truncated');
        assert.equal(decoded.body.subarray(0, body.length + 1).toString('utf8'), body + ':', 'oversized stream must bypass body rewrite');
      } else if (requestPath === '/demo?binary=1') {
        assert.equal(decoded.body.toString('utf8'), body, 'binary MIME must bypass body rewrite');
      } else if (rewrite === 'body-on' && intercepted && requestPath === '/demo') {
        assert.ok(!/^content-encoding:/im.test(decoded.head), 'rewritten body must clear Content-Encoding');
        assert.ok(!/^etag:/im.test(decoded.head), 'rewritten body must clear stale ETag');
        assert.ok(decoded.body.length > 0, 'rewritten body was empty: ' + JSON.stringify(decoded.head));
        assert.deepEqual(JSON.parse(decoded.body.toString('utf8')), { marker: 'netverge-body-rewritten', path: '/demo' });
      } else {
        assert.match(decoded.head, /^content-encoding:\s*gzip\s*$/im, 'untouched gzip response must retain encoding');
        assert.equal(JSON.parse(zlib.gunzipSync(decoded.body).toString('utf8')).marker, body);
      }
    } else {
      assert.ok(result.response.includes(body), 'missing controlled origin response');
    }
    if (rewrite && !bodyRewrite) {
      const expected = activeDemo && (rewrite === 'on' || rewrite === 'multi-both' || rewrite === 'module-pending') ? '1' :
        activeDemo && rewrite === 'multi-override' ? 'override' : 'origin';
      const rawHeaders = result.response.split('\r\n\r\n')[0].split('\r\n');
      const fields = rawHeaders.filter(line => /^x-netverge-test:/i.test(line));
      assert.deepEqual(fields.map(line => line.slice(line.indexOf(':') + 1).trim()), activeDemo && removeHeaders ? [] : [expected], host + requestPath);
      const extras = rawHeaders.filter(line => /^x-netverge-extra:/i.test(line)).map(line => line.slice(line.indexOf(':') + 1).trim());
      assert.deepEqual(extras, activeDemo && rewrite === 'multi-both' ? ['second'] : [], 'extra response header: ' + host + requestPath);
    }
    if (pathRewrite || queryProbe) {
      const expected = rewrite === 'path-on' && intercepted && requestPath === '/demo' ? '/changed' : requestPath;
      const observed = result.response.split('\r\n\r\n')[0].match(/^x-observed-path: ([^\r\n]+)/im);
      assert.equal(observed?.[1], expected + (activeDemo && removeHeaders ? keptQuery : query), 'target at origin');
    }
    if (requestRewrite) {
      const expected = activeDemo && removeHeaders ? 'missing' : activeDemo && rewrite === 'request-on' ? 'rewritten' : 'client, duplicate';
      const fields = result.response.split('\r\n\r\n')[0].split('\r\n').filter(line => /^x-netverge-observed-request:/i.test(line));
      assert.deepEqual(fields.map(line => line.slice(line.indexOf(':') + 1).trim()), [expected], 'upstream request header: ' + host + requestPath);
    }
    if (intercepted) assert.notEqual(result.fingerprint, originLeaf.fingerprint256);
    else assert.equal(result.fingerprint, originLeaf.fingerprint256);
    assert.equal(fs.readFileSync(log, 'utf8'), before + host + ':443\n', 'flow must use the original HTTP exit once');
  }
  console.log('PASS: Windows TUN ' + mode + ' traffic and original exit verified');
}

async function main() {
  const [action, dir, port, mode, rewrite] = process.argv.slice(2);
  if (action === 'serve') await serve(dir);
  else if (action === 'probe' && ['pending', 'enabled', 'disabled'].includes(mode)) await probe(dir, port, mode, rewrite);
  else throw new Error('expected serve or probe with a valid TUN phase');
}

main().catch(err => { console.error(err.message); process.exitCode = 1; });
