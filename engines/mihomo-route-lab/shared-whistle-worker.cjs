'use strict';

// Test-only adapter. Never packaged or called by the desktop app.
// The pinned worker API is reused; this probes a private Whistle 2.10.15
// hook before committing to a maintained upstream integration.
const path = require('node:path');
const http = require('node:http');
const { createRequire } = require('node:module');
const { randomBytes, timingSafeEqual } = require('node:crypto');
const actualWorker = path.resolve(process.env.NETVERGE_ROUTE_LAB_WORKER || '');
const load = createRequire(actualWorker);
const { readVerifiedCa } = load('./ca-integrity.cjs');
if (process.platform !== 'win32') process.umask(0o077);
const settings = JSON.parse(process.env.NETVERGE_MITM_WORKER_CONFIG || '{}');
delete process.env.NETVERGE_MITM_WORKER_CONFIG;
const { dataDir, port, routes, hosts, targetPort } = settings;
if (!path.isAbsolute(dataDir || '') || !Number.isInteger(port) || port < 1024 || port > 65535 ||
    targetPort !== 443 || JSON.stringify(hosts) !== '["route.netverge.test"]' ||
    !Array.isArray(routes) || routes.length < 2 || routes.length > 8) {
  throw new Error('Invalid shared route lab settings');
}
const authority = 'route.netverge.test:443';
const credentials = new Set();
const ports = new Set([port]);
const validSecret = v => typeof v === 'string' && /^[A-Za-z0-9_-]{32}$/.test(v);
for (const route of routes) {
  if (!validSecret(route.ingress) || !validSecret(route.password) ||
      credentials.has(route.ingress) || credentials.has(route.password) ||
      route.ingress === route.password || !Number.isInteger(route.port) ||
      route.port < 1024 || route.port > 65535 || ports.has(route.port)) {
    throw new Error('Invalid or duplicate route capability');
  }
  credentials.add(route.ingress); credentials.add(route.password); ports.add(route.port);
  route.auth = Buffer.from('Basic ' + Buffer.from('netverge:' + route.ingress).toString('base64'));
  route.claimed = false;
}
process.stdin.on('end', () => process.exit(0));
process.stdin.on('error', () => process.exit(0));
process.stdin.resume();

const whistle = load('whistle');
if (load('whistle/package.json').version !== '2.10.15') throw new Error('Whistle version mismatch');
const rules = load('whistle/lib/rules');
const config = load('whistle/lib/config');
const TUNNEL = 'x-whistle-tunnel-data';
const server = http.createServer();
const denied = http.createServer((req, res) => { res.writeHead(403, {Connection:'close'}); res.end(); });
denied.on('connect', (req, socket) => socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'));
denied.on('upgrade', (req, socket) => socket.destroy());
const capabilities = new Map();
const admissions = new WeakMap();
const agents = new WeakMap();
let ready = false;

function strip(req, name) {
  delete req.headers[name];
  if (Array.isArray(req.rawHeaders)) {
    for (let i = req.rawHeaders.length - 2; i >= 0; i -= 2) {
      if (req.rawHeaders[i].toLowerCase() === name) req.rawHeaders.splice(i, 2);
    }
  }
}
function sameAuthority(req, url = req.url) {
  try {
    const expected = new URL('https://' + authority);
    const host = new URL('https://' + req.headers.host);
    const target = new URL(url, expected);
    return host.origin === expected.origin && host.pathname === '/' &&
      !host.username && !host.password && target.origin === expected.origin &&
      !target.username && !target.password;
  } catch { return false; }
}

const emit = server.emit;
server.emit = function(event, ...args) {
  if (event === 'connect') {
    const [req, socket] = args;
    const auth = Buffer.from(req.headers['proxy-authorization'] || '');
    const route = routes.find(r => auth.length === r.auth.length && timingSafeEqual(auth, r.auth));
    if (!ready || !route || req.url !== authority || req.headers.host !== authority || route.claimed) {
      const code = route ? '403 Forbidden' : '407 Proxy Authentication Required';
      socket.end('HTTP/1.1 ' + code + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return true;
    }
    route.claimed = true; // One original connection, one admitted downstream tunnel.
    strip(req, 'proxy-authorization');
    strip(req, TUNNEL);
    const token = randomBytes(32).toString('hex');
    const admission = { route, active: true, requestClaimed: false };
    capabilities.set(token, admission);
    socket.once('close', () => { admission.active = false; capabilities.delete(token); });
    req.headers[TUNNEL] = token;
  }
  if (event === 'request') {
    const [req, res] = args;
    const admission = capabilities.get(req.headers[TUNNEL]);
    strip(req, TUNNEL);
    strip(req, 'proxy-authorization');
    if (!ready || !admission?.active || admission.requestClaimed || !sameAuthority(req)) {
      res.writeHead(403, {Connection:'close', 'Content-Length':'0'}); res.end();
      return true;
    }
    admission.requestClaimed = true;
    // After the internal TLS bridge, do not trust any user-supplied route
    // header; route identity lives only on the admitted request object.
    admissions.set(req, admission);
  }
  if (event === 'upgrade') { args[1].destroy(); return true; }
  return emit.call(this, event, ...args);
};

// Reuse Whistle's normal proxy resolution for a fail-closed loopback
// fallback, then replace only the verified request's resolved proxy.
// No shared global route rule is rewritten at request time.
const originalGetProxy = rules.getProxy;
rules.getProxy = function(url, req, callback) {
  const admission = req && admissions.get(req);
  return originalGetProxy.call(this, url, req, (err, ip, p) => {
    if (!admission) return callback(err, ip, p);
    if (err || !admission.active || !sameAuthority(req, url) || !req.rules?.proxy) {
      // The fallback is a bound deny-only listener. Never return a direct rule.
      return callback(err || new Error('Route lease unavailable'), ip, p);
    }
    const matcher = 'proxy://netverge:' + admission.route.password + '@127.0.0.1:' + admission.route.port;
    req.rules.proxy = { matcher, url: matcher, raw: 'NetVerge test route lease' };
    // Match the original ordinary proxy branch: res.js resolves loopback.
    return callback();
  });
};

// Observe actual agent selection and reject sharing an agent across leases.
// This is an assertion on pinned private APIs, not a production patch.
const originalGetAgent = config.getHttpsAgent;
config.getHttpsAgent = function(options, requestOptions) {
  const route = routes.find(r => options.proxyHost === '127.0.0.1' &&
    Number(options.proxyPort) === r.port && options.auth === 'netverge:' + r.password);
  const agent = originalGetAgent.call(this, options, requestOptions);
  if (route) {
    const prior = agents.get(agent);
    if (prior && prior !== route) throw new Error('Cross-route HTTPS agent reuse');
    agents.set(agent, route);
  }
  return agent;
};

function die() { console.error('Shared route lab listener or CA initialization failed'); process.exit(1); }
server.on('error', die);
denied.on('error', die);
denied.listen(0, '127.0.0.1', () => {
  server.listen(port, '127.0.0.1', () => whistle({
    server, host:'127.0.0.1', port, baseDir:dataDir, rcPath:'none',
    mode:'safe|disableCapture|disableHttp2|shadowRulesOnly|disableUpdateTips|disableCustomCerts',
    noGlobalPlugins:true, disableAllPlugins:true,
    shadowRules: [
      'route.netverge.test enable://capture',
      '/.*/ proxy://127.0.0.1:' + denied.address().port,
    ].join('\n'),
  }, proxy => {
    let caDer;
    try { ({caDer} = readVerifiedCa(dataDir, proxy.httpsUtil.getRootCAFile())); }
    catch { return die(); }
    ready = true;
    process.stdout.write('NETVERGE_MITM_READY ' + caDer + '\n');
  }));
});
