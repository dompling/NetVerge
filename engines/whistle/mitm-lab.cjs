'use strict';

// Isolated experiment. TUN mode is Linux network-namespace-only; no host proxy or trust changes.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const dgram = require('node:dgram');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const { X509Certificate, randomBytes, createHash } = require('node:crypto');
const { fork, spawn, execFileSync } = require('node:child_process');
const { Resolver } = require('node:dns/promises');
const { once } = require('node:events');
const forge = require('node-forge');

const TARGET = 'mitm.netverge.test';
const BYPASS = 'bypass.netverge.test';
const pki = forge.pki;
const TUN = process.argv.includes('--tun');
const TUN_DEVICE = 'nvmitm0';
const FAKE_RANGE = '198.18.0.0/16';

function makeCertificates() {
  const caKeys = pki.rsa.generateKeyPair(2048);
  const leafKeys = pki.rsa.generateKeyPair(2048);
  function cert(keys, serial, cn) {
    const c = pki.createCertificate();
    c.publicKey = keys.publicKey;
    c.serialNumber = serial;
    c.validity.notBefore = new Date(Date.now() - 60000);
    c.validity.notAfter = new Date(Date.now() + 86400000);
    c.setSubject([{ name: 'commonName', value: cn }]);
    return c;
  }
  const ca = cert(caKeys, '01', 'NetVerge isolated origin CA');
  ca.setIssuer(ca.subject.attributes);
  ca.setExtensions([{ name: 'basicConstraints', cA: true, critical: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());
  const leaf = cert(leafKeys, '02', TARGET);
  leaf.setIssuer(ca.subject.attributes);
  leaf.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [TARGET, BYPASS].map(value => ({ type: 2, value })) },
  ]);
  leaf.sign(caKeys.privateKey, forge.md.sha256.create());
  return { ca: pki.certificateToPem(ca), cert: pki.certificateToPem(leaf), key: pki.privateKeyToPem(leafKeys.privateKey) };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

// Answer only the two lab names; never forward DNS to an external resolver.
async function startLabDns() {
  const server = dgram.createSocket('udp4');
  server.on('message', (query, peer) => {
    if (query.length < 17 || query.readUInt16BE(4) !== 1) return;
    let offset = 12;
    const labels = [];
    while (offset < query.length && query[offset]) {
      const size = query[offset++];
      if (size > 63 || offset + size >= query.length) return;
      labels.push(query.toString('ascii', offset, offset + size));
      offset += size;
    }
    if (offset + 5 > query.length) return;
    offset++;
    const type = query.readUInt16BE(offset);
    const qclass = query.readUInt16BE(offset + 2);
    const name = labels.join('.').toLowerCase();
    const known = [TARGET, BYPASS].includes(name);
    const hasAnswer = known && type === 1 && qclass === 1;
    const header = Buffer.alloc(12);
    query.copy(header, 0, 0, 2);
    header.writeUInt16BE(known ? 0x8180 : 0x8183, 2);
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(hasAnswer ? 1 : 0, 6);
    const answer = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
    const response = Buffer.concat([header, query.subarray(12, offset + 4), ...(hasAnswer ? [answer] : [])]);
    server.send(response, peer.port, peer.address);
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.bind(0, '127.0.0.1', resolve);
  });
  return server;
}

async function reservePorts(count) {
  const servers = Array.from({ length: count }, () => net.createServer());
  try { return await Promise.all(servers.map(listen)); }
  finally { await Promise.all(servers.map(s => new Promise(r => s.close(r)))); }
}

function timeout(promise, ms, label) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ' timed out')), ms);
  })]).finally(() => clearTimeout(timer));
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const closed = once(child, 'exit');
  child.kill();
  await timeout(closed, 5000, 'child exit').catch(() => child.kill('SIGKILL'));
}

function rawIngressStatus(port, host, originPort, headers = {}) {
  return new Promise((resolve, reject) => {
    const authority = host + ':' + originPort;
    const request = http.request({
      host: '127.0.0.1', port, path: 'https://' + authority + '/netverge-proof',
      headers: { Host: authority, ...headers }, agent: false,
    }, res => { res.resume(); res.once('end', () => resolve(res.statusCode)); });
    request.setTimeout(3000, () => request.destroy(new Error('Raw ingress check timed out')));
    request.once('error', reject);
    request.end();
  });
}

function dial(port, host, originPort, ca, password = '') {
  return new Promise((resolve, reject) => {
    const authority = host + ':' + originPort;
    const req = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: authority, headers: { Host: authority, ...(password ? { 'Proxy-Authorization': 'Basic ' + Buffer.from('netverge:' + password).toString('base64') } : {}) }, agent: false });
    let socket;
    const timer = setTimeout(() => {
      req.destroy();
      socket?.destroy();
      reject(new Error('CONNECT/TLS timeout: ' + host));
    }, 12000);
    const fail = e => { clearTimeout(timer); socket?.destroy(); reject(e); };
    req.once('error', fail);
    req.once('connect', (res, raw, head) => {
      socket = raw;
      if (res.statusCode !== 200) return fail(new Error('CONNECT status ' + res.statusCode));
      if (head.length) raw.unshift(head);
      const secured = tls.connect({ socket: raw, servername: host, ca, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] });
      socket = secured;
      secured.once('error', fail);
      secured.once('secureConnect', () => {
        const fingerprint = secured.getPeerCertificate().fingerprint256;
        let response = '';
        secured.setEncoding('utf8');
        secured.on('data', chunk => { response += chunk; });
        secured.once('end', () => { clearTimeout(timer); resolve({ fingerprint, response }); });
        secured.once('close', () => { if (!response) fail(new Error('Connection closed without response')); });
        secured.write('GET /netverge-proof HTTP/1.1\r\nHost: ' + authority + '\r\nConnection: close\r\n\r\n');
      });
    });
    req.end();
  });
}

async function waitPort(child, port) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error('Mihomo exited before ready');
    const ok = await new Promise(resolve => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => resolve(false));
      s.setTimeout(500, () => { s.destroy(); resolve(false); });
    });
    if (ok) return;
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('Mihomo listener not ready');
}

async function prepareTun(child) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error('Mihomo exited before TUN ready');
    try {
      const link = execFileSync('ip', ['-o', 'link', 'show', 'dev', TUN_DEVICE], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      if (link.includes('UP')) {
        execFileSync('ip', ['route', 'replace', FAKE_RANGE, 'dev', TUN_DEVICE]);
        console.log('TUN ready:', link.trim());
        return;
      }
    } catch {}
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error('Mihomo TUN interface not ready');
}

async function fakeAddress(port, host) {
  const resolver = new Resolver({ timeout: 1000, tries: 5 });
  resolver.setServers(['127.0.0.1:' + port]);
  const [ip] = await resolver.resolve4(host);
  assert.match(ip, /^198\.18\./, 'DNS must return a lab fake IP');
  const route = execFileSync('ip', ['route', 'get', ip], { encoding: 'utf8' });
  assert.ok(route.includes('dev ' + TUN_DEVICE), 'fake IP route must use the TUN device: ' + route);
  console.log('TUN DNS:', host, ip, route.trim());
  return ip;
}

function dialTun(ip, host, originPort, ca) {
  return new Promise((resolve, reject) => {
    // Native TLS socket to the fake IP; no HTTP proxy or CONNECT at the client.
    const secured = tls.connect({ host: ip, port: originPort, servername: host, ca, rejectUnauthorized: true, ALPNProtocols: ['http/1.1'] });
    const timer = setTimeout(() => {
      secured.destroy();
      reject(new Error('TUN/TLS timeout: ' + host));
    }, 15000);
    const fail = err => { clearTimeout(timer); secured.destroy(); reject(err); };
    secured.once('error', fail);
    secured.once('secureConnect', () => {
      const fingerprint = secured.getPeerCertificate().fingerprint256;
      let response = '';
      secured.setEncoding('utf8');
      secured.on('data', chunk => { response += chunk; });
      secured.once('end', () => { clearTimeout(timer); resolve({ fingerprint, response }); });
      secured.once('close', () => { if (!response) fail(new Error('TUN closed without response')); });
      secured.write('GET /netverge-proof HTTP/1.1\r\nHost: ' + host + ':' + originPort + '\r\nConnection: close\r\n\r\n');
    });
  });
}

async function main() {
  if (TUN) {
    assert.equal(process.platform, 'linux', 'TUN lab requires Linux');
    const hostNs = process.env.NETVERGE_TUN_LAB_HOST_NS;
    assert.ok(hostNs && /^net:\[\d+\]$/.test(hostNs), 'Start TUN lab through the namespace wrapper');
    assert.notEqual(await fs.readlink('/proc/self/ns/net'), hostNs, 'Refusing to touch routes in the host network namespace');
    assert.equal(execFileSync('ip', ['route', 'show', 'default'], { encoding: 'utf8' }).trim(), '', 'TUN lab requires no default route');
    await fs.access('/dev/net/tun');
  }
  const binary = process.env.NETVERGE_MIHOMO_BIN;
  if (!binary || !path.isAbsolute(binary)) throw new Error('Set NETVERGE_MIHOMO_BIN to an absolute path to a trusted Mihomo executable');
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'netverge-mitm-'));
  let origin, mihomo, worker, dns;
  try {
    const certs = makeCertificates();
    const originCa = path.join(dir, 'origin-ca.pem');
    await fs.writeFile(originCa, certs.ca);
    const fingerprint = new X509Certificate(certs.cert).fingerprint256;
    const received = [];
    origin = https.createServer({ key: certs.key, cert: certs.cert }, (req, res) => {
      received.push({ host: req.headers.host, url: req.url, internalData: req.headers['x-whistle-tunnel-data'], proxyAuth: req.headers['proxy-authorization'] });
      res.end('netverge-origin-proof');
    });
    const originPort = await listen(origin);
    const [entry, back, proxy, dnsListen] = await reservePorts(4);
    dns = await startLabDns();
    const dnsServer = '127.0.0.1:' + dns.address().port;
    const password = randomBytes(24).toString('base64url');
    const forwardPassword = randomBytes(24).toString('base64url');
    const healthSecret = randomBytes(24).toString('base64url');
    const config = {
      'mixed-port': entry,
      'allow-lan': false,
      'bind-address': '127.0.0.1',
      'mode': 'rule',
      'log-level': 'info',
      'find-process-mode': 'off',
      'ipv6': false,
      'dns': { enable: true, 'enhanced-mode': TUN ? 'fake-ip' : 'redir-host', 'use-hosts': false, 'use-system-hosts': false, nameserver: [dnsServer], 'default-nameserver': [dnsServer], ...(TUN ? { listen: '127.0.0.1:' + dnsListen, 'fake-ip-range': '198.18.0.1/16', 'fake-ip-filter': [] } : {}) },
      ...(TUN ? { tun: { enable: true, device: TUN_DEVICE, stack: 'gvisor', 'auto-route': false, 'auto-detect-interface': false, 'auto-redirect': false, 'dns-hijack': [], 'strict-route': false } } : {}),
      'listeners': [{ name: 'netverge-return', type: 'http', listen: '127.0.0.1', port: back, users: [{ username: 'netverge', password }] }],
      'proxies': [{ name: 'NETVERGE-MITM', type: 'http', server: '127.0.0.1', port: proxy, username: 'netverge', password: forwardPassword }],
      'rules': [
        'AND,((IN-NAME,netverge-return),(DOMAIN,' + TARGET + '),(NETWORK,TCP),(DST-PORT,' + originPort + ')),DIRECT',
        'AND,((IN-NAME,netverge-return),(IP-CIDR,127.0.0.1/32),(NETWORK,TCP),(DST-PORT,' + proxy + ')),DIRECT',
        'IN-NAME,netverge-return,REJECT',
        TUN ? 'AND,((IN-TYPE,TUN),(DOMAIN,' + TARGET + '),(NETWORK,TCP),(DST-PORT,' + originPort + ')),NETVERGE-MITM' : 'DOMAIN,' + TARGET + ',NETVERGE-MITM',
        'DOMAIN,' + BYPASS + ',DIRECT',
        'MATCH,REJECT',
      ],
    };
    const configPath = path.join(dir, 'mihomo.json');
    await fs.writeFile(configPath, JSON.stringify(config)); // JSON is valid YAML.
    mihomo = spawn(binary, ['-d', dir, '-f', configPath], { stdio: ['ignore', 'inherit', 'inherit'], windowsHide: true });
    mihomo.on('error', err => console.error('Mihomo process error:', err.message));
    await waitPort(mihomo, entry);
    await waitPort(mihomo, back);
    if (TUN) await prepareTun(mihomo);

    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(WHISTLE_|PFORK_|NODE_OPTIONS$|NODE_PATH$|NODE_TLS_REJECT_UNAUTHORIZED$|(?:HTTP|HTTPS|ALL|NO)_PROXY$)/i.test(k)));
    Object.assign(env, { HOME: dir, USERPROFILE: dir, NODE_EXTRA_CA_CERTS: originCa, NETVERGE_LAB_RETURN_PASSWORD: password, NETVERGE_LAB_FORWARD_PASSWORD: forwardPassword, NETVERGE_LAB_HEALTH_SECRET: healthSecret, NETVERGE_LAB_TARGET_PORT: String(originPort) });
    const observations = [];
    const tunnels = [];
    async function launchWorker() {
      worker = fork(path.join(__dirname, 'mitm-worker.cjs'), [dir, String(proxy), String(back)], { env, execArgv: [], stdio: ['ignore', 'inherit', 'inherit', 'ipc'], windowsHide: true });
      return timeout(new Promise((resolve, reject) => {
        worker.on('message', m => {
          if (m.event === 'ready') resolve(m);
          if (m.event === 'observed') observations.push(m);
          if (m.event === 'tunnel') { tunnels.push(m.url); console.log('Whistle CONNECT:', m.url); }
        });
        worker.once('error', reject);
        worker.once('exit', code => reject(new Error('Whistle exited: ' + code)));
      }), 20000, 'Whistle readiness');
    }
    const ready = await launchWorker();
    const whistleCa = await fs.readFile(ready.caPath, 'utf8');

    const proof = (kind, nonce) => createHash('sha256').update('netverge-health-v1:' + kind + ':' + nonce + ':' + healthSecret).digest('hex');
    function healthRequest(kind, nonce, headers = {}) {
      return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port: proxy, path: '/__netverge_health' + (kind === 'return' ? '_return' : '') + '/' + nonce,
          headers: { Host: '127.0.0.1:' + proxy, ...headers }, agent: false }, res => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', chunk => { body += chunk; });
          res.once('end', () => resolve({ status: res.statusCode, body }));
        });
        req.setTimeout(3000, () => req.destroy(new Error('health request timed out')));
        req.once('error', reject);
        req.end();
      });
    }
    async function verifyHealth() {
      const nonce = randomBytes(24).toString('base64url');
      const auth = 'Basic ' + Buffer.from('netverge:' + forwardPassword).toString('base64');
      assert.equal((await healthRequest('forward', nonce)).status, 403);
      assert.equal((await healthRequest('forward', nonce, { 'Proxy-Authorization': auth })).status, 403);
      assert.equal((await healthRequest('return', nonce, { 'X-NetVerge-Proof': 'forged' })).status, 403);
      const result = await healthRequest('forward', nonce, { 'Proxy-Authorization': auth, 'X-NetVerge-Proof': proof('forward-request', nonce) });
      assert.equal(result.status, 200);
      assert.equal(result.body, proof('forward-response', nonce));
      console.log('PASS: authenticated local round trip through Mihomo return listener; forged diagnostics rejected');
    }
    await verifyHealth();
    assert.notEqual(new X509Certificate(whistleCa).fingerprint256, new X509Certificate(certs.ca).fingerprint256);

    // Exercise the actual public worker listener, not a simulated auth check.
    await assert.rejects(dial(proxy, TARGET, originPort, whistleCa), /CONNECT status 407/);
    await assert.rejects(dial(proxy, BYPASS, originPort, certs.ca, forwardPassword), /CONNECT status 403/);
    await assert.rejects(dial(back, TARGET, originPort, certs.ca), /CONNECT status (407|403)/);
    assert.equal(await rawIngressStatus(proxy, TARGET, originPort), 403);
    assert.equal(await rawIngressStatus(proxy, TARGET, originPort, { 'x-whistle-tunnel-data': 'forged' }), 403);
    assert.equal(await rawIngressStatus(proxy, TARGET, originPort, { 'Proxy-Authorization': 'Basic ' + Buffer.from('netverge:' + forwardPassword).toString('base64') }), 403);
    console.log('PASS: unauthorized ingress and return denied; authenticated non-target ingress and direct HTTP denied');

    // Verify the real Mihomo return path before the MITM route.
    const direct = await dial(back, TARGET, originPort, certs.ca, password);
    assert.equal(direct.fingerprint, fingerprint);
    assert.match(direct.response, /netverge-origin-proof/);

    // Non-target traffic must keep the original TLS peer.
    const bypass = TUN
      ? await dialTun(await fakeAddress(dnsListen, BYPASS), BYPASS, originPort, certs.ca)
      : await dial(entry, BYPASS, originPort, certs.ca);
    assert.equal(bypass.fingerprint, fingerprint);
    assert.match(bypass.response, /netverge-origin-proof/);

    // The authorized target must present the Whistle-issued leaf and still reach the origin.
    const intercepted = TUN
      ? await dialTun(await fakeAddress(dnsListen, TARGET), TARGET, originPort, whistleCa)
      : await dial(entry, TARGET, originPort, whistleCa);
    assert.notEqual(intercepted.fingerprint, fingerprint);
    assert.match(intercepted.response, /^HTTP\/1\.[01] 200 /);
    assert.match(intercepted.response, /netverge-origin-proof/);
    assert.ok(received.some(r => r.host === TARGET + ':' + originPort && r.url === '/netverge-proof'));
    assert.ok(received.every(r => !r.internalData && !r.proxyAuth), 'internal authentication data reached origin');
    const expectedUrl = 'https://' + TARGET + ':' + originPort + '/netverge-proof';
    const deadline = Date.now() + 3000;
    while (!observations.some(x => x.url === expectedUrl && x.method === 'GET') && Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 25));
    }
    assert.ok(observations.some(x => x.url === expectedUrl && x.method === 'GET'), 'Whistle did not observe decrypted URL');
    assert.ok(!observations.some(x => x.url.includes(BYPASS)), 'Unexpected bypass observation');
    assert.ok(tunnels.includes('tunnel://' + TARGET + ':' + originPort), 'CONNECT authority lost its hostname');
    assert.ok(!tunnels.some(x => x.includes(BYPASS)), 'Bypass unexpectedly entered Whistle');
    console.log('PASS: real Mihomo ' + (TUN ? 'TUN' : 'CONNECT') + ' -> selective Whistle MITM -> named Mihomo return; original TLS for bypass');

    // Simulate abrupt worker loss while the same Mihomo runtime stays loaded.
    // Trust both CAs for the down-state probe: direct fallback must not be
    // accidentally concealed by a certificate verification error.
    const exited = once(worker, 'exit');
    assert.ok(worker.kill('SIGKILL'), 'could not terminate Whistle');
    await timeout(exited, 5000, 'Whistle forced exit');
    const beforeLoss = received.length;
    const selected = async ca => TUN
      ? dialTun(await fakeAddress(dnsListen, TARGET), TARGET, originPort, ca)
      : dial(entry, TARGET, originPort, ca);
    await assert.rejects(selected([certs.ca, whistleCa]));
    assert.equal(received.length, beforeLoss, 'selected request reached origin while MITM was down');
    const unaffected = TUN
      ? await dialTun(await fakeAddress(dnsListen, BYPASS), BYPASS, originPort, certs.ca)
      : await dial(entry, BYPASS, originPort, certs.ca);
    assert.equal(unaffected.fingerprint, fingerprint);
    assert.match(unaffected.response, /netverge-origin-proof/);
    console.log('PASS: worker loss fails selected traffic without bypass; ordinary traffic survives');

    const recovered = await launchWorker();
    const recoveredCa = await fs.readFile(recovered.caPath, 'utf8');
    await verifyHealth();
    assert.equal(new X509Certificate(recoveredCa).fingerprint256, new X509Certificate(whistleCa).fingerprint256, 'worker restart changed the session CA');
    await assert.rejects(dial(proxy, TARGET, originPort, whistleCa), /CONNECT status 407/);
    const recoveredResponse = await selected(whistleCa);
    assert.notEqual(recoveredResponse.fingerprint, fingerprint);
    assert.match(recoveredResponse.response, /^HTTP\/1\.[01] 200 /);
    assert.match(recoveredResponse.response, /netverge-origin-proof/);
    assert.ok(received.every(r => !r.internalData && !r.proxyAuth), 'internal authentication data reached origin after restart');
    console.log('PASS: Whistle restarted with unchanged CA and credentials; selected traffic recovered without core reload');
  } finally {
    await stop(worker);
    await stop(mihomo);
    if (dns) await new Promise(r => dns.close(r));
    if (origin) {
      origin.closeAllConnections();
      await new Promise(r => origin.close(r));
    }
    await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

main().catch(err => { console.error(err); process.exitCode = 1; });
