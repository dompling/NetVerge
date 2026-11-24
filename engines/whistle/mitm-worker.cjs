'use strict';

const path = require('node:path');
const http = require('node:http');
const { timingSafeEqual } = require('node:crypto');
const whistle = require('whistle');
const [legacyDataDir, portText, returnPortText] = process.argv.slice(2);
const desktop = !process.send;
const settings = desktop ? JSON.parse(process.env.NETVERGE_MITM_WORKER_CONFIG || '{}') : {
  dataDir: legacyDataDir, port: Number(portText), returnPort: Number(returnPortText),
  hosts: ['mitm.netverge.test'], password: process.env.NETVERGE_LAB_RETURN_PASSWORD || '',
  forwardPassword: process.env.NETVERGE_LAB_FORWARD_PASSWORD, targetPort: Number(process.env.NETVERGE_LAB_TARGET_PORT),
};
const { dataDir, port, returnPort, hosts, password, forwardPassword, targetPort } = settings;
const validHost = host => typeof host === 'string' && host.length <= 253 &&
  host.includes('.') && host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
if (!dataDir || !path.isAbsolute(dataDir) || ![port, returnPort].every(p => Number.isInteger(p) && p > 0 && p < 65536) || port === returnPort ||
    !Array.isArray(hosts) || !hosts.length || !hosts.every(validHost) || typeof password !== 'string' ||
    !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535 ||
    !/^[A-Za-z0-9_-]{32}$/.test(forwardPassword || '') || !/^[A-Za-z0-9_-]{32}$/.test(password) || forwardPassword === password) {
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
const auth = password ? 'netverge:' + password + '@' : '';
// Supply Whistle's documented custom server instead of creating another proxy port.
// Guard external HTTP events before Whistle's listeners can process them.
// Whistle's internal HTTPS server may emit decrypted request events on this server.
const server = http.createServer();
const external = new WeakSet();
const authorized = new WeakSet();
const allowed = new Set(hosts.map(host => host + ':' + targetPort));
const expected = Buffer.from('Basic ' + Buffer.from('netverge:' + forwardPassword).toString('base64'));
let ready = false;
const originalEmit = server.emit;
server.emit = function(event, ...args) {
  if (event === 'connection') external.add(args[0]);
  if (event === 'connect') {
    const [req, socket] = args;
    const header = Buffer.from(req.headers['proxy-authorization'] || '');
    const authenticated = header.length === expected.length && timingSafeEqual(header, expected);
    if (!ready || !authenticated || !allowed.has(req.url)) {
      socket.end('HTTP/1.1 ' + (authenticated ? '403 Forbidden' : '407 Proxy Authentication Required') +
        '\r\nConnection: close\r\nContent-Length: 0\r\nProxy-Authenticate: Basic realm="NetVerge"\r\n\r\n');
      return true;
    }
    authorized.add(socket);
    delete req.headers['proxy-authorization'];
    for (let i = req.rawHeaders.length - 2; i >= 0; i -= 2) {
      if (req.rawHeaders[i].toLowerCase() === 'proxy-authorization') req.rawHeaders.splice(i, 2);
    }
  }
  if (event === 'request' || event === 'upgrade') {
    const [req, res] = args;
    if (external.has(req.socket) && !authorized.has(req.socket)) {
      if (event === 'request') {
        res.writeHead(403, { Connection: 'close', 'Content-Length': '0' });
        res.end();
      } else {
        res.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      }
      return true;
    }
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
  mode: 'safe|disableCapture|disableHttp2|shadowRulesOnly|disableUpdateTips',
  noGlobalPlugins: true,
  disableAllPlugins: true,
  shadowRules: [
    ...hosts.map(host => host + ' enable://capture'),
    '/.*/ proxy://' + auth + '127.0.0.1:' + returnPort,
  ].join('\n'),
}, (proxy) => {
  ready = true;
  if (desktop) {
    process.stdout.write('NETVERGE_MITM_READY\n');
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
  process.send({ event: 'ready', caPath: proxy.httpsUtil.getRootCAFile() });
}));
