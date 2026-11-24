'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

test('Whistle rewrites an HTTP request and forwards it to a loopback upstream', { timeout: 30000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'netverge-whistle-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const ruleFile = path.join(dir, 'rules.txt');
  await fs.writeFile(ruleFile, 'http://netverge-test.invalid/ method://POST\n');
  const upstream = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ method: req.method, url: req.url, host: req.headers.host }));
  });
  const upstreamPort = await listen(upstream);
  t.after(() => { upstream.closeAllConnections(); upstream.close(); });
  const reservation = net.createServer();
  const proxyPort = await listen(reservation);
  await new Promise((resolve) => reservation.close(resolve));
  const child = spawn(process.execPath, [path.join(__dirname, 'engine.cjs')], {
    env: { ...process.env, NETVERGE_HTTP_PORT: String(proxyPort), NETVERGE_MIHOMO_PORT: String(upstreamPort), NETVERGE_HTTP_DATA: dir, NETVERGE_HTTP_RULES: ruleFile },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const exited = once(child, 'exit');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await exited;
  });
  let output = '';
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Whistle readiness timeout: ' + output)), 15000);
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error('Whistle exited: ' + code + ' ' + output)); });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.stdout.on('data', (chunk) => {
      output += chunk;
      if (output.includes('"event":"ready"')) { clearTimeout(timer); resolve(); }
    });
  });
  const result = await new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1', port: proxyPort, method: 'GET',
      path: 'http://netverge-test.invalid/hello',
      headers: { host: 'netverge-test.invalid' },
      timeout: 5000,
    }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('timeout', () => req.destroy(new Error('proxy request timed out')));
    req.on('error', reject);
    req.end();
  });
  assert.equal(result.status, 200, result.body);
  const payload = JSON.parse(result.body);
  assert.equal(payload.method, 'POST');
  assert.equal(payload.host, 'netverge-test.invalid');
  assert.match(payload.url, /\/hello$/);
});
