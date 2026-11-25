'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
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
    if (!['/netverge-proof', '/demo', '/demo/other'].includes(req.url) || req.headers['proxy-authorization'] || req.headers['x-whistle-tunnel-data']) {
      res.writeHead(400).end();
      return;
    }
    res.setHeader('X-NetVerge-Test', 'origin');
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
  // Give only this lookup a bounded readiness window (~18 seconds worst case).
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
    `$ErrorActionPreference='Stop'; Find-NetRoute -RemoteIPAddress '${ip}' | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | ForEach-Object { $_.InterfaceAlias + ' ' + $_.DestinationPrefix }`,
  ], { encoding: 'utf8', timeout: 12000, windowsHide: true }).trim();
  assert.equal(route, 'NV-MITM-CI 198.18.17.0/24', 'Windows must route the resolved fake IP through the CI TUN');
  return ip;
}

async function probe(dir, port, mode, rewrite) {
  const log = path.join(dir, 'exit-observations');
  const originCA = fs.readFileSync(path.join(dir, 'origin-ca.pem'));
  const originLeaf = new X509Certificate(fs.readFileSync(path.join(dir, 'origin-leaf.pem')));
  const cases = rewrite ? [[selected, '/demo'], [selected, '/demo/other'], [bypass, '/demo']] :
    hosts.map(host => [host, '/netverge-proof']);
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
    const result = await dialTun(ip, host, 443, ca, 15000, requestPath);
    assert.match(result.response, /^HTTP\/1\.[01] 200 /);
    assert.ok(result.response.includes(body), 'missing controlled origin response');
    if (rewrite) {
      const expected = rewrite === 'on' && intercepted && requestPath === '/demo' ? '1' : 'origin';
      const fields = result.response.split('\r\n\r\n')[0].split('\r\n').filter(line => /^x-netverge-test:/i.test(line));
      assert.deepEqual(fields.map(line => line.slice(line.indexOf(':') + 1).trim()), [expected], host + requestPath);
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
