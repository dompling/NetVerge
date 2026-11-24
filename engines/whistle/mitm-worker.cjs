'use strict';

const path = require('node:path');
const http = require('node:http');
const { timingSafeEqual, randomBytes, createHash } = require('node:crypto');
const { readVerifiedCa } = require('./ca-integrity.cjs');
if (process.platform !== 'win32') process.umask(0o077);
const whistle = require('whistle');
const [legacyDataDir, portText, returnPortText] = process.argv.slice(2);
const desktop = !process.send;
const settings = desktop ? JSON.parse(process.env.NETVERGE_MITM_WORKER_CONFIG || '{}') : {
  dataDir: legacyDataDir, port: Number(portText), returnPort: Number(returnPortText),
  hosts: ['mitm.netverge.test'], password: process.env.NETVERGE_LAB_RETURN_PASSWORD || '',
  healthSecret: process.env.NETVERGE_LAB_HEALTH_SECRET,
  forwardPassword: process.env.NETVERGE_LAB_FORWARD_PASSWORD, targetPort: Number(process.env.NETVERGE_LAB_TARGET_PORT),
};
const { dataDir, port, returnPort, hosts, password, forwardPassword, targetPort, healthSecret } = settings;
const validHost = host => typeof host === 'string' && host.length <= 253 &&
  host.includes('.') && host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
if (!dataDir || !path.isAbsolute(dataDir) || ![port, returnPort].every(p => Number.isInteger(p) && p > 0 && p < 65536) || port === returnPort ||
    !Array.isArray(hosts) || !hosts.length || !hosts.every(validHost) || typeof password !== 'string' ||
    !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535 ||
    !/^[A-Za-z0-9_-]{32}$/.test(forwardPassword || '') || !/^[A-Za-z0-9_-]{32}$/.test(password) || forwardPassword === password || !/^[A-Za-z0-9_-]{32}$/.test(healthSecret || '') || healthSecret === password || healthSecret === forwardPassword) {
  throw new Error('Invalid MITM worker configuration');
}
if (desktop) {
  // The parent keeps the pipe open; exit if the desktop process exits or crashes.
  process.stdin.on('end', () => process.exit(0));
  process.stdin.on('error', () => process.exit(0));
  process.stdin.resume();
} else {
  process.on('disconnect', () => process.exit(0));
}
delete process.env.NETVERGE_MITM_WORKER_CONFIG;
delete process.env.NETVERGE_LAB_FORWARD_PASSWORD;
delete process.env.NETVERGE_LAB_RETURN_PASSWORD;
delete process.env.NETVERGE_LAB_HEALTH_SECRET;
const auth = password ? 'netverge:' + password + '@' : '';
// Whistle carries tunnel data from the authenticated CONNECT socket to its
// internal HTTPS-to-HTTP bridge. A per-tunnel capability binds that bridge
// to the admitted authority; socket identity alone does not survive it.
const TUNNEL_DATA = 'x-whistle-tunnel-data';
const server = http.createServer();
const capabilities = new Map();
const allowed = new Set(hosts.map(host => host + ':' + targetPort));
const expected = Buffer.from('Basic ' + Buffer.from('netverge:' + forwardPassword).toString('base64'));
let ready = false;
function stripHeader(req, name) {
  delete req.headers[name];
  if (!Array.isArray(req.rawHeaders)) return;
  for (let i = req.rawHeaders.length - 2; i >= 0; i -= 2) {
    if (req.rawHeaders[i].toLowerCase() === name) req.rawHeaders.splice(i, 2);
  }
}
function matchesAuthority(req, authority) {
  if (!authority || typeof req.headers.host !== 'string') return false;
  try {
    const expectedUrl = new URL('https://' + authority);
    const hostUrl = new URL('https://' + req.headers.host);
    const target = new URL(req.url, expectedUrl);
    return hostUrl.origin === expectedUrl.origin &&
      target.origin === expectedUrl.origin &&
      !hostUrl.username && !hostUrl.password && hostUrl.pathname === '/' &&
      !target.username && !target.password;
  } catch {
    return false;
  }
}
// The diagnostic route is fixed to this listener and the named authenticated
// Mihomo return inbound. No user hostname, external URL or TLS bypass is involved.
const HEALTH_PREFIX = '/__netverge_health/';
const RETURN_PREFIX = '/__netverge_health_return/';
const healthAuthority = '127.0.0.1:' + port;
const healthProof = (kind, nonce) => createHash('sha256')
  .update('netverge-health-v1:' + kind + ':' + nonce + ':' + healthSecret).digest('hex');
function constantEqual(value, expectedValue) {
  const a = Buffer.from(typeof value === 'string' ? value : '');
  const b = Buffer.from(expectedValue);
  return a.length === b.length && timingSafeEqual(a, b);
}
function writeHealth(res, status, body = '') {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, { Connection: 'close', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function checkReturn(nonce) {
  return new Promise(resolve => {
    let socket;
    let settled = false;
    let received = '';
    const finish = ok => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.destroy();
      socket?.destroy();
      resolve(ok);
    };
    const request = http.request({
      host: '127.0.0.1', port: returnPort, method: 'CONNECT', path: healthAuthority,
      headers: { Host: healthAuthority, 'Proxy-Authorization': 'Basic ' + Buffer.from('netverge:' + password).toString('base64') },
      agent: false,
    });
    const timer = setTimeout(() => finish(false), 1200);
    request.once('error', () => finish(false));
    request.once('connect', (res, raw, head) => {
      socket = raw;
      socket.once('error', () => finish(false));
      if (res.statusCode !== 200 || head.length) return finish(false);
      socket.setEncoding('utf8');
      socket.on('data', chunk => {
        received += chunk;
        if (received.length > 1024) finish(false);
      });
      socket.once('end', () => {
        const boundary = received.indexOf('\r\n\r\n');
        finish(boundary >= 0 && /^HTTP\/1\.[01] 200 /.test(received) &&
          constantEqual(received.slice(boundary + 4), healthProof('return-response', nonce)));
      });
      socket.once('close', () => finish(false));
      socket.write('GET ' + RETURN_PREFIX + nonce + ' HTTP/1.1\r\nHost: ' + healthAuthority +
        '\r\nX-NetVerge-Proof: ' + healthProof('return-request', nonce) + '\r\nConnection: close\r\n\r\n');
    });
    request.end();
  });
}
let healthBusy = false;
function handleHealth(req, res) {
  if (req.headers.host !== healthAuthority) return false;
  const prefix = req.url.startsWith(HEALTH_PREFIX) ? HEALTH_PREFIX :
    req.url.startsWith(RETURN_PREFIX) ? RETURN_PREFIX : null;
  if (!prefix) return false;
  const nonce = req.url.slice(prefix.length);
  if (!ready || req.method !== 'GET' ||
      !/^[A-Za-z0-9_-]{32}$/.test(nonce)) {
    writeHealth(res, 403);
    return true;
  }
  if (prefix === RETURN_PREFIX) {
    const valid = constantEqual(req.headers['x-netverge-proof'], healthProof('return-request', nonce));
    writeHealth(res, valid ? 200 : 403, valid ? healthProof('return-response', nonce) : '');
    return true;
  }
  const header = Buffer.from(req.headers['proxy-authorization'] || '');
  if (header.length !== expected.length || !timingSafeEqual(header, expected) ||
      !constantEqual(req.headers['x-netverge-proof'], healthProof('forward-request', nonce))) {
    writeHealth(res, 403);
    return true;
  }
  if (healthBusy) {
    writeHealth(res, 503);
    return true;
  }
  healthBusy = true;
  checkReturn(nonce).then(ok => {
    writeHealth(res, ok ? 200 : 503, ok ? healthProof('forward-response', nonce) : '');
  }).catch(() => writeHealth(res, 503)).finally(() => { healthBusy = false; });
  return true;
}
const originalEmit = server.emit;
server.emit = function(event, ...args) {
  if (event === 'connect') {
    const [req, socket] = args;
    const header = Buffer.from(req.headers['proxy-authorization'] || '');
    const authenticated = header.length === expected.length && timingSafeEqual(header, expected);
    if (!ready || !authenticated || !allowed.has(req.url)) {
      socket.end('HTTP/1.1 ' + (authenticated ? '403 Forbidden' : '407 Proxy Authentication Required') +
        '\r\nConnection: close\r\nContent-Length: 0\r\nProxy-Authenticate: Basic realm="NetVerge"\r\n\r\n');
      return true;
    }
    if (capabilities.size >= 4096) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return true;
    }
    stripHeader(req, 'proxy-authorization');
    stripHeader(req, TUNNEL_DATA);
    const capability = randomBytes(32).toString('hex');
    capabilities.set(capability, req.url);
    socket.once('close', () => capabilities.delete(capability));
    req.headers[TUNNEL_DATA] = capability;
  }
  if (event === 'request') {
    const [req, res] = args;
    if (handleHealth(req, res)) return true;
    const capability = req.headers[TUNNEL_DATA];
    const authority = capabilities.get(capability);
    stripHeader(req, TUNNEL_DATA);
    stripHeader(req, 'proxy-authorization');
    if (!ready || !matchesAuthority(req, authority)) {
      res.writeHead(403, { Connection: 'close', 'Content-Length': '0' });
      res.end();
      return true;
    }
  }
  if (event === 'upgrade') {
    args[1].end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return true;
  }
  return originalEmit.call(this, event, ...args);
};
server.on('error', err => { console.error('MITM listener failed:', err.code); process.exit(1); });
server.listen(port, '127.0.0.1', () => whistle({
  server,
  host: '127.0.0.1',
  port,
  baseDir: dataDir,
  rcPath: 'none',
  mode: 'safe|disableCapture|disableHttp2|shadowRulesOnly|disableUpdateTips|disableCustomCerts',
  noGlobalPlugins: true,
  disableAllPlugins: true,
  shadowRules: [
    ...hosts.map(host => host + ' enable://capture'),
    '/.*/ proxy://' + auth + '127.0.0.1:' + returnPort,
  ].join('\n'),
}, (proxy) => {
  // Only export the canonical public certificate of this isolated worker.
  // Never return arbitrary paths or file contents to the parent.
  let caPath, caDer;
  try {
    ({ caPath, caDer } = readVerifiedCa(dataDir, proxy.httpsUtil.getRootCAFile()));
  } catch {
    console.error('MITM root certificate validation failed');
    process.exit(1);
  }
  ready = true;
  if (desktop) {
    process.stdout.write('NETVERGE_MITM_READY ' + caDer + '\n');
    return;
  }
  proxy.on('_request', url => {
    if (typeof url === 'string' && url.startsWith('tunnel://')) process.send({ event: 'tunnel', url });
  });
  proxy.on('request', (emitter, data) => {
    if (data.url && ['https://mitm.netverge.test:', 'https://bypass.netverge.test:'].some(prefix => data.url.startsWith(prefix))) {
      process.send({ event: 'observed', url: data.url, method: data.req.method });
    }
  });
  process.send({ event: 'ready', caPath, caDer });
}));
