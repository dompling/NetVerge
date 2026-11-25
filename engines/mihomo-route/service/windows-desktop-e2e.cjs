'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { once } = require('node:events');
const { spawn, execFileSync } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { setTimeout: sleep } = require('node:timers/promises');

const selected = 'api.example.test';
const bypass = 'bypass.example.test';
const sha256 = data => createHash('sha256').update(data).digest('hex');
const q = value => "'" + value.replaceAll("'", "''") + "'";

function powershell(command, stdio = ['ignore', 'pipe', 'inherit']) {
  return execFileSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', "$ErrorActionPreference='Stop'; " + command],
    { encoding: 'utf8', timeout: 60000, stdio, windowsHide: true })?.trim();
}

async function until(label, read, limit = 45000) {
  const deadline = Date.now() + limit;
  let last;
  while (Date.now() < deadline) {
    try {
      const result = await read();
      if (result) return result;
    } catch (error) { last = error; }
    await sleep(350);
  }
  throw new Error(label + ' timed out' + (last ? ': ' + last.message : ''));
}

async function freePort() {
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function firstLine(child, label) {
  return until(label, () => new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => finish(new Error(label + ' did not report readiness')), 20000);
    function finish(error, line) {
      clearTimeout(timer);
      child.stdout.off('data', onData);
      child.off('exit', onExit);
      child.off('error', finish);
      if (error) reject(error); else resolve(line);
    }
    function onData(chunk) {
      data += chunk;
      if (data.includes('\n')) finish(null, data.split('\n')[0].trim());
    }
    function onExit(code) { finish(new Error(label + ' exited with ' + code)); }
    child.stdout.on('data', onData);
    child.once('exit', onExit);
    child.once('error', finish);
  }), 21000);
}

function stopTree(child) {
  if (!child?.pid || child.exitCode !== null) return;
  try { execFileSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', timeout: 10000 }); }
  catch { child.kill(); }
}

function automation(app, action) {
  return execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'RemoteSigned',
    '-File', path.join(__dirname, 'windows-desktop-uia.ps1'), '-App', app, '-Action', action,
  ], { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true }).trim();
}

async function main() {
  assert.ok(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', 'requires a disposable Windows runner');
  const root = path.resolve(process.argv[2]);
  const appRoot = path.join(process.env.APPDATA, 'io.github.clash-verge-rev.clash-verge-rev.dev');
  const app = path.join(root, 'NetVerge-MITM.exe');
  const launcher = path.join(root, 'NetVerge-MITM.ps1');
  const node = path.join(root, 'worker', 'node.exe');
  const worker = path.join(root, 'worker', 'route-worker.cjs');
  const mitm = path.join(appRoot, 'netverge-mitm-dev');
  const netFixture = path.resolve(__dirname, '../../whistle/windows-tun-lab.cjs');
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8').replace(/^\uFEFF/, ''));
  const coreDigest = manifest.sha256['service/netverge-mihomo-service.exe'].toLowerCase();
  assert.equal(sha256(fs.readFileSync(app)), manifest.sha256['NetVerge-MITM.exe'].toLowerCase());
  assert.ok(!fs.existsSync(appRoot), 'development app state must be clean');
  assert.equal(powershell("if (Get-Service clash_verge_service_dev -ErrorAction SilentlyContinue) { 'exists' }"), '');

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'netverge-desktop-e2e-'));
  const bootstrap = path.join(temp, 'bootstrap.json');
  let origin, seed, desktop, attemptedInstall = false;
  let desktopOutput = '';
  try {
    origin = spawn(process.execPath, [netFixture, 'serve', temp], { stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true });
    const { exitPort, upstreamDnsPort } = JSON.parse(await firstLine(origin, 'TLS origin fixture'));
    // Set the origin trust only inside the fixture worker, keeping TLS
    // verification enabled without changing the Windows certificate store.
    const fixtureWorker = path.join(temp, 'route-worker.cjs');
    fs.writeFileSync(fixtureWorker, [
      "const tls = require('node:tls');",
      "const fs = require('node:fs');",
      `tls.setDefaultCACertificates([...tls.getCACertificates('default'), fs.readFileSync(${JSON.stringify(path.join(temp, 'origin-ca.pem'))}, 'utf8')]);`,
      `require(${JSON.stringify(worker)});`,
    ].join('\n'));
    const dnsPort = await freePort();
    fs.mkdirSync(path.join(appRoot, 'profiles'), { recursive: true });
    fs.mkdirSync(mitm);
    const bootstrapBytes = JSON.stringify({ node, worker: fixtureWorker, hosts: [selected] });
    fs.writeFileSync(bootstrap, bootstrapBytes);

    const caConfig = { dataDir: mitm, port: await freePort(), hosts: [selected], targetPort: 443, controlSecret: randomBytes(24).toString('base64url') };
    seed = spawn(node, [worker], {
      cwd: root,
      env: { ...process.env, HOME: mitm, USERPROFILE: mitm, NETVERGE_MITM_WORKER_CONFIG: JSON.stringify(caConfig) },
      stdio: ['pipe', 'pipe', 'inherit'],
      windowsHide: true,
    });
    const ready = await firstLine(seed, 'test CA worker');
    assert.match(ready, /^NETVERGE_MITM_READY [A-Za-z0-9+/=]+$/);
    const der = Buffer.from(ready.split(' ')[1], 'base64');
    fs.writeFileSync(path.join(temp, 'whistle.der'), der);
    stopTree(seed);
    await once(seed, 'exit');
    seed = undefined;
    fs.writeFileSync(path.join(mitm, 'route-selection.yaml'), JSON.stringify({
      version: 1, 'bootstrap-sha256': sha256(bootstrapBytes), pending: false,
      enable: true, hosts: [selected], 'ca-fingerprint': sha256(der),
    }));
    fs.writeFileSync(path.join(appRoot, 'verge.yaml'), JSON.stringify({
      language: 'en', enable_tun_mode: true, enable_system_proxy: false,
      enable_dns_settings: false, auto_check_update: false,
    }));
    fs.writeFileSync(path.join(appRoot, 'config.yaml'), JSON.stringify({
      mode: 'rule',
      tun: { device: 'NV-MITM-CI', stack: 'gvisor', 'auto-route': true, 'auto-detect-interface': false,
        'strict-route': false, 'dns-mode': 'disabled', 'dns-hijack': [], 'route-address': ['198.18.17.0/24'] },
    }));
    fs.writeFileSync(path.join(appRoot, 'profiles.yaml'), JSON.stringify({
      current: 'desktop-fixture', items: [{ uid: 'desktop-fixture', type: 'local', name: 'Desktop E2E', file: 'desktop-fixture.yaml' }],
    }));
    const dnsServer = '127.0.0.1:' + upstreamDnsPort;
    fs.writeFileSync(path.join(appRoot, 'profiles', 'desktop-fixture.yaml'), JSON.stringify({
      ipv6: false,
      dns: { enable: true, listen: '127.0.0.1:' + dnsPort, ipv6: false, 'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.17.1/24', 'fake-ip-filter': [], 'use-hosts': false, 'use-system-hosts': false,
        nameserver: [dnsServer], 'default-nameserver': [dnsServer] },
      proxies: [{ name: 'fixture-exit', type: 'http', server: '127.0.0.1', port: exitPort }],
      rules: [`DOMAIN,${selected},fixture-exit`, `DOMAIN,${bypass},fixture-exit`, 'MATCH,REJECT'],
    }));

    attemptedInstall = true;
    powershell("& " + q(launcher) + ' -Action Install', 'inherit');
    desktop = spawn(app, [], {
      cwd: root,
      env: {
        ...process.env,
        CLASH_VERGE_DEV_SERVICE_DIR: path.join(root, 'service'),
        NETVERGE_MITM_ROUTE_DEV_CONFIG: bootstrap,
        NETVERGE_MITM_SERVICE_CORE_SHA256: coreDigest,
        WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--force-renderer-accessibility',
        WEBVIEW2_USER_DATA_FOLDER: path.join(temp, 'WebView2'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    for (const stream of [desktop.stdout, desktop.stderr]) {
      stream.on('data', chunk => { desktopOutput = (desktopOutput + chunk).slice(-24000); });
    }
    await until('MITM navigation', () => automation(app, 'Open') === 'OK', 70000);
    await until('enabled service mode switch', () => automation(app, 'Switch') === 'OK');
    await until('service mode checkbox persisted', () => {
      const file = path.join(mitm, 'guarded-service.yaml');
      return fs.existsSync(file) && fs.readFileSync(file, 'utf8').includes(coreDigest);
    });
    await until('restart button', () => automation(app, 'Restart') === 'OK');
    await until('desktop process restart', () => {
      const pid = powershell("(Get-Process -Name 'NetVerge-MITM' -ErrorAction SilentlyContinue | Where-Object Path -eq " + q(app) + " | Select-Object -First 1).Id; exit 0");
      return /^\d+$/.test(pid) && Number(pid) !== desktop.pid;
    });
    await until('MITM navigation after restart', () => automation(app, 'Open') === 'OK', 70000);
    const processPath = await until('guarded service core startup', () =>
      powershell("(Get-Process -Name 'netverge-mihomo-service' -ErrorAction SilentlyContinue).Path; exit 0"), 90000);
    assert.match(processPath, /\\clash-verge-service-dev\\cores\\netverge-mihomo-service\.exe$/i);
    await until('restored desktop MITM state', () => automation(app, 'Healthy') === 'OK', 60000);
    execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled'], { stdio: 'inherit', timeout: 75000 });
    console.log('PASS: clicked desktop MITM service switch and restarted into a protected service generation');

  } catch (error) {
    console.error(powershell("Get-Process -Name 'netverge-mihomo-service','verge-mihomo','node' -ErrorAction SilentlyContinue | Select-Object ProcessName,Id | ConvertTo-Json -Compress; exit 0"));
    console.error('Desktop process exit code:', desktop?.exitCode);
    if (desktopOutput) console.error(desktopOutput);
    const logDirectory = path.join(appRoot, 'logs');
    if (fs.existsSync(logDirectory)) {
      for (const file of fs.readdirSync(logDirectory).filter(name => name.endsWith('.log')).sort((a,b) => fs.statSync(path.join(logDirectory,a)).mtimeMs - fs.statSync(path.join(logDirectory,b)).mtimeMs).slice(-3)) {
        console.error('Desktop log:', file);
        const lines = fs.readFileSync(path.join(logDirectory, file), 'utf8').split(/\r?\n/);
        console.error(lines.filter(line => !/secret|password|token|authorization/i.test(line)).slice(-65).join('\n'));
      }
    }
    console.error(powershell("Get-Process -Name 'NetVerge-MITM','msedgewebview2' -ErrorAction SilentlyContinue | Select-Object ProcessName,Id,SessionId | ConvertTo-Json -Compress; exit 0"));
    if (desktop) {
      try { console.error(automation(app, 'Inspect')); } catch {}
    }
    throw error;
  } finally {
    stopTree(seed);
    stopTree(desktop);
    stopTree(origin);
    if (desktop) powershell("Get-Process -Name 'NetVerge-MITM' -ErrorAction SilentlyContinue | Where-Object Path -eq " + q(app) + ' | Stop-Process -Force; exit 0');
    if (attemptedInstall) powershell("& " + q(launcher) + ' -Action Uninstall', 'inherit');
    fs.rmSync(temp, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
