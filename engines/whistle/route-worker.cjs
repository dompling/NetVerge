'use strict';

// Integration candidate: dynamic authenticated, bounded original-route registry.
// Whistle private hooks remain pinned; desktop activation is not wired here.
const path = require('node:path');
const http = require('node:http');
const fs = require('node:fs');
const { randomBytes, timingSafeEqual } = require('node:crypto');
const { readVerifiedCa } = require('./ca-integrity.cjs');
if (process.platform !== 'win32') process.umask(0o077);
const settings = JSON.parse(process.env.NETVERGE_MITM_WORKER_CONFIG || '{}');
delete process.env.NETVERGE_MITM_WORKER_CONFIG;
const { dataDir, port, hosts, targetPort, controlSecret } = settings;
const validSecret = v => typeof v === 'string' && /^[A-Za-z0-9_-]{32}$/.test(v);
const validHost = v => typeof v === 'string' && v.length <= 253 && v.includes('.') &&
  !require('node:net').isIP(v) && v.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s));
if (!path.isAbsolute(dataDir || '') || !Number.isInteger(port) || port < 1024 || port > 65535 ||
    targetPort !== 443 || !Array.isArray(hosts) || !hosts.length || hosts.length > 64 ||
    !hosts.every(validHost) || !validSecret(controlSecret)) {
  throw new Error('Invalid dynamic route configuration');
}
const allowed = new Set(hosts.map(host => host + ':443'));
// This file belongs to the local MITM profile. Remote Clash profiles cannot supply rules.
const rewriteFile = path.join(dataDir, 'response-header-rule.json');
let responseRule;
let rewriteHits = 0;
function loadResponseRule() {
  responseRule = undefined;
  try {
    const stat = fs.lstatSync(rewriteFile);
    if (!stat.isFile() || stat.size > 8192) throw new Error();
    const rule = JSON.parse(fs.readFileSync(rewriteFile, 'utf8'));
    if (rule.enabled === false) return;
    if (rule.enabled !== true || !hosts.includes(rule.host) || typeof rule.path !== 'string' ||
        !/^\/[^?#\s]*$/.test(rule.path) || typeof rule.header !== 'string' ||
        !/^x-[a-z0-9-]{1,100}$/i.test(rule.header) || typeof rule.value !== 'string' ||
        rule.value.length > 1024) throw new Error();
    http.validateHeaderValue(rule.header, rule.value);
    responseRule = { ...rule, header: rule.header.toLowerCase() };
  } catch (error) {
    if (error.code !== 'ENOENT') console.error('Invalid local response header rule; rewrite disabled');
  }
}
loadResponseRule();
fs.watchFile(rewriteFile, { interval: 500, persistent: false }, loadResponseRule);

// Request rewriting has its own local rule and session counter. Do not
// accept routing, identity, framing, authentication or Whistle control
// headers: this initial implementation permits only X-Custom-* names.
const requestRewriteFile = path.join(dataDir, 'request-header-rule.json');
let requestRule;
let requestRewriteHits = 0;
function loadRequestRule() {
  requestRule = undefined;
  try {
    const stat = fs.lstatSync(requestRewriteFile);
    if (!stat.isFile() || stat.size > 8192) throw new Error();
    const rule = JSON.parse(fs.readFileSync(requestRewriteFile, 'utf8'));
    if (rule.enabled === false) return;
    if (rule.enabled !== true || Object.keys(rule).sort().join(',') !== 'enabled,header,host,path,value' ||
        !hosts.includes(rule.host) || typeof rule.path !== 'string' ||
        !/^\/[^?#\s]*$/.test(rule.path) || typeof rule.header !== 'string' ||
        !/^x-custom-[a-z0-9-]{1,91}$/i.test(rule.header) || typeof rule.value !== 'string' ||
        rule.value.length > 1024) throw new Error();
    http.validateHeaderValue(rule.header, rule.value);
    requestRule = { ...rule, header: rule.header.toLowerCase() };
  } catch (error) {
    if (error.code !== 'ENOENT') console.error('Invalid local request header rule; rewrite disabled');
  }
}
loadRequestRule();
fs.watchFile(requestRewriteFile, { interval: 500, persistent: false }, loadRequestRule);

function applyRequestRule(req, authority) {
  const rule = requestRule;
  if (!rule || authority !== rule.host + ':443' ||
      new URL(req.url, 'https://' + authority).pathname !== rule.path) return;
  // The verified request still uses its original admitted connection lease.
  // Remove every case variant from raw headers so duplicate client values
  // cannot take precedence when Whistle reconstructs the upstream request.
  strip(req, rule.header);
  req.headers[rule.header] = rule.value;
  if (Array.isArray(req.rawHeaders)) req.rawHeaders.push(rule.header, rule.value);
  requestRewriteHits = Math.min(requestRewriteHits + 1, 0xfffffffe);
}

function applyResponseRule(req, res, authority) {
  const rule = responseRule;
  if (!rule || authority !== rule.host + ':443' ||
      new URL(req.url, 'https://' + authority).pathname !== rule.path) return;
  const writeHead = res.writeHead;
  res.writeHead = function(status, reason, fields) {
    rewriteHits = Math.min(rewriteHits + 1, 0xfffffffe);
    const headers = typeof reason === 'string' ? fields : reason;
    // Explicit writeHead fields take precedence over setHeader, including
    // differently cased or repeated fields. Preserve every unrelated field.
    if (Array.isArray(headers)) {
      const pairs = [];
      for (let i = 0; i < headers.length; i += 2) {
        if (headers[i].toLowerCase() !== rule.header) pairs.push(headers[i], headers[i + 1]);
      }
      pairs.push(rule.header, rule.value);
      return typeof reason === 'string' ? writeHead.call(this, status, reason, pairs) : writeHead.call(this, status, pairs);
    }
    const updated = { ...headers };
    for (const name of Object.keys(updated)) {
      if (name.toLowerCase() === rule.header) delete updated[name];
    }
    updated[rule.header] = rule.value;
    return typeof reason === 'string' ? writeHead.call(this, status, reason, updated) : writeHead.call(this, status, updated);
  };
}

const routes = new Map();
const maxRoutes = 128;
const controlAuthority = '127.0.0.1:' + port;
const controlPath = '/__netverge_routes';
const authValue = secret => Buffer.from('Basic ' + Buffer.from('netverge:' + secret).toString('base64'));
const controlAuth = authValue(controlSecret);
const matchesAuth = (auth, expected) => auth.length === expected.length && timingSafeEqual(auth, expected);
function removeRoute(route) {
  if (!route || routes.get(route.ingress) !== route) return;
  routes.delete(route.ingress);
  clearTimeout(route.timer);
  route.active = false;
  route.socket?.destroy();
  // Whistle 2.10.15 uses hagent.TunnelingAgent, not http.Agent.
  // Drain pending requests before destroying sockets: removeSocket would
  // otherwise launch another queued CONNECT. Socket entries can be placeholders.
  for (const state of route.agentStates || []) {
    const { agent, connecting } = state;
    const pending = Array.isArray(agent.requests) ? agent.requests.splice(0) : [];
    for (const item of pending) {
      item.request?.destroy?.();
    }
    for (const req of connecting) req.destroy();
    connecting.clear();
    if (typeof agent.destroy === 'function') {
      agent.destroy();
    } else if (Array.isArray(agent.sockets)) {
      for (const socket of agent.sockets.slice()) {
        if (typeof socket?.destroy === 'function') socket.destroy();
      }
    }
  }
  route.agentStates?.clear();
}
function reply(res,status) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, {Connection:'close','Cache-Control':'no-store','Content-Length':'0'});
  res.end();
}
function control(req,res) {
  if (req.url !== controlPath || req.headers.host !== controlAuthority) return false;
  const auth = Buffer.from(req.headers['proxy-authorization'] || '');
  if (!ready || req.headers[TUNNEL] || !matchesAuth(auth,controlAuth)) {
    reply(res,403); return true;
  }
  if (req.method === 'GET' && !req.headers['transfer-encoding'] && !Number(req.headers['content-length'] || 0)) {
    const body = JSON.stringify({protocol:1,hosts:[...new Set(hosts)],rewriteHits,requestRewriteHits});
    res.writeHead(200, {Connection:'close','Cache-Control':'no-store','Content-Type':'application/json','Content-Length':Buffer.byteLength(body)});
    res.end(body);
    return true;
  }
  if (!['POST','DELETE'].includes(req.method) || req.headers['content-type'] !== 'application/json' ||
      req.headers['transfer-encoding'] || !/^[0-9]{1,4}$/.test(req.headers['content-length'] || '') ||
      Number(req.headers['content-length']) > 1024) {
    reply(res,400); return true;
  }
  const parts = [];
  let total = 0;
  req.setTimeout(2000,()=>req.destroy());
  req.on('data',chunk=>{total+=chunk.length;if(total>1024)req.destroy();else parts.push(chunk);});
  req.on('error',()=>{});
  req.on('end',()=>{
    let entry;
    try {entry=JSON.parse(Buffer.concat(parts).toString('utf8'));}catch{return reply(res,400);}
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !validSecret(entry.ingress)) return reply(res,400);
    if (req.method === 'DELETE') {
      if (Object.keys(entry).length !== 1) return reply(res,400);
      removeRoute(routes.get(entry.ingress));
      return reply(res,204);
    }
    if (Object.keys(entry).sort().join(',') !== 'authority,ingress,password,port' ||
        !allowed.has(entry.authority) || !validSecret(entry.password) ||
        entry.ingress === entry.password || entry.ingress === controlSecret || entry.password === controlSecret ||
        !Number.isInteger(entry.port) || entry.port < 1024 || entry.port > 65535 ||
        entry.port === port || entry.port === denied.address().port) return reply(res,400);
    if (routes.size >= maxRoutes) return reply(res,503);
    for (const route of routes.values()) {
      if (route.port === entry.port || [route.ingress,route.password].includes(entry.ingress) ||
          [route.ingress,route.password].includes(entry.password)) return reply(res,409);
    }
    const route = {...entry,auth:authValue(entry.ingress),claimed:false,active:true};
    route.timer=setTimeout(()=>removeRoute(route),60000);
    route.timer.unref();
    routes.set(route.ingress,route);
    reply(res,201);
  });
  return true;
}
process.stdin.on('end', () => process.exit(0));
process.stdin.on('error', () => process.exit(0));
process.stdin.resume();

const whistle = require('whistle');
if (require('whistle/package.json').version !== '2.10.15') throw new Error('Whistle version mismatch');
const rules = require('whistle/lib/rules');
const config = require('whistle/lib/config');
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
function sameAuthority(req, authority, url = req.url) {
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
    const route = [...routes.values()].find(r => matchesAuth(auth,r.auth));
    if (!ready || !route || !route.active || req.url !== route.authority || req.headers.host !== route.authority || route.claimed) {
      const code = route ? '403 Forbidden' : '407 Proxy Authentication Required';
      socket.end('HTTP/1.1 ' + code + '\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return true;
    }
    route.claimed = true; // One original connection, one admitted downstream tunnel.
    route.socket = socket;
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
    if (control(req,res)) return true;
    const admission = capabilities.get(req.headers[TUNNEL]);
    strip(req, TUNNEL);
    strip(req, 'proxy-authorization');
    if (!ready || !admission?.active || !admission.route.active || admission.requestClaimed || !sameAuthority(req,admission.route.authority)) {
      res.writeHead(403, {Connection:'close', 'Content-Length':'0'}); res.end();
      return true;
    }
    admission.requestClaimed = true;
    // After the internal TLS bridge, do not trust any user-supplied route
    // header; route identity lives only on the admitted request object.
    admissions.set(req, admission);
    applyRequestRule(req, admission.route.authority);
    applyResponseRule(req, res, admission.route.authority);
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
    if (err || !admission.active || !admission.route.active || !sameAuthority(req,admission.route.authority,url) || !req.rules?.proxy) {
      // The response inspector does not consistently propagate getProxy's
      // error argument. Explicitly retain a deny-only proxy instead.
      const deniedMatcher = 'proxy://127.0.0.1:' + denied.address().port;
      req.rules.proxy = { matcher: deniedMatcher, url: deniedMatcher, lineProps: {}, raw: 'NetVerge deny route' };
      console.error('Dynamic route: unavailable lease denied');
      return callback();
    }
    const matcher = 'proxy://netverge:' + admission.route.password + '@127.0.0.1:' + admission.route.port;
    // Preserve the resolved Whistle rule shape (notably lineProps, which
    // util.isInternalProxy dereferences). Clear alternate matcher values
    // so util.rule.getMatcher cannot select the original deny proxy.
    req.rules.proxy = {
      ...req.rules.proxy, matcher, url: matcher, value: undefined, path: undefined,
      lineProps: { ...req.rules.proxy.lineProps }, raw: 'NetVerge original route lease',
    };
    console.error('Dynamic route: admitted request selected its lease');
    // Match the original ordinary proxy branch: res.js resolves loopback.
    return callback();
  });
};

// Observe actual agent selection and reject sharing an agent across leases.
// This is an assertion on pinned private APIs, not a production patch.
const originalGetAgent = config.getHttpsAgent;
config.getHttpsAgent = function(options, requestOptions) {
  const route = [...routes.values()].find(r => options.proxyHost === '127.0.0.1' &&
    Number(options.proxyPort) === r.port && options.auth === 'netverge:' + r.password);
  const agent = originalGetAgent.call(this, options, requestOptions);
  if (route) {
    const prior = agents.get(agent);
    if (prior && prior !== route) throw new Error('Cross-route HTTPS agent reuse');
    if (!prior) {
      // hagent.request is the underlying CONNECT ClientRequest factory.
      // Retain pending CONNECTs as well as established sockets so a
      // revocation cannot leave an asynchronous connection in flight.
      if (!Array.isArray(agent.sockets) || !Array.isArray(agent.requests) ||
          typeof agent.request !== 'function' || typeof agent.addRequest !== 'function') {
        throw new Error('Unsupported pinned Whistle agent layout');
      }
      const connecting = new Set();
      const originalRequest = agent.request;
      const originalAddRequest = agent.addRequest;
      agent.request = function(...args) {
        const req = originalRequest.apply(this, args);
        connecting.add(req);
        req.once('close', () => connecting.delete(req));
        if (!route.active) req.destroy();
        return req;
      };
      agent.addRequest = function(req, ...args) {
        if (!route.active) {
          req.destroy(new Error('NetVerge route revoked'));
          return;
        }
        return originalAddRequest.call(this, req, ...args);
      };
      (route.agentStates ||= new Set()).add({agent,connecting});
      agents.set(agent, route);
    }
    console.error('Dynamic route: lease-specific HTTPS agent selected');
  }
  return agent;
};

// Emit only fixed reason codes: never log an exception stack, file path,
// certificate contents, config payload, or authentication secret.
function die(stage) {
  console.error('Dynamic route initialization failed: ' + stage);
  process.exit(1);
}
function listenerFailure(stage, error) {
  const known = ['EADDRINUSE', 'EACCES', 'EADDRNOTAVAIL'];
  die(stage + ':' + (known.includes(error?.code) ? error.code : 'OTHER'));
}
const caReasons = new Map([
  ['Unsafe CA directory', 'CA_DIRECTORY'],
  ['Unexpected CA location', 'CA_OUTSIDE_DATA_ROOT'],
  ['Unsafe CA file', 'CA_FILE_INTEGRITY'],
  ['CA file changed while opening', 'CA_OPEN_RACE'],
  ['CA file changed while reading', 'CA_READ_RACE'],
  ['Expected one public certificate', 'CA_FORMAT'],
  ['Invalid CA', 'CA_INVALID'],
  ['Root certificate and key do not match', 'CA_KEY_MISMATCH'],
]);
server.on('error', error => listenerFailure('MAIN_LISTENER', error));
denied.on('error', error => listenerFailure('DENIED_LISTENER', error));
denied.listen(0, '127.0.0.1', () => {
  server.listen(port, '127.0.0.1', () => whistle({
    server, host:'127.0.0.1', port, baseDir:dataDir, rcPath:'none',
    mode:'safe|disableCapture|disableHttp2|shadowRulesOnly|disableUpdateTips|disableCustomCerts',
    noGlobalPlugins:true, disableAllPlugins:true,
    shadowRules: [
      ...hosts.map(host => host + ' enable://capture'),
      '/.*/ proxy://127.0.0.1:' + denied.address().port,
    ].join('\n'),
  }, proxy => {
    if (config.rejectUnauthorized !== true) return die('TLS_VERIFICATION_DISABLED');
    let caDer;
    try { ({caDer} = readVerifiedCa(dataDir, proxy.httpsUtil.getRootCAFile())); }
    catch (error) {
      return die(caReasons.get(error?.message) || 'CA_READ_OR_PARSE_ERROR');
    }
    ready = true;
    process.stdout.write('NETVERGE_MITM_READY ' + caDer + '\n');
  }));
});
