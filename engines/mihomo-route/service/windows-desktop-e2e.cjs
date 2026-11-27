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
const {
  writeModuleManifest,
  verifyModuleApproval,
  verifyCompiledModuleBundle,
} = require('./windows-desktop-module-e2e.cjs');

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

function automation(app, action, moduleVersion) {
  return execFileSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-STA', '-ExecutionPolicy', 'RemoteSigned',
    '-File', path.join(__dirname, 'windows-desktop-uia.ps1'), '-App', app, '-Action', action,
    ...(moduleVersion ? ['-ModuleVersion', moduleVersion] : []),
  ], { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true }).trim();
}

async function changeServiceMode(app, mitm, enabled, coreDigest) {
  const action = enabled ? 'EnableService' : 'DisableService';
  const file = path.join(mitm, 'guarded-service.yaml');
  // Retry only while input has not been dispatched. Once delivered, never
  // blindly click a toggle again; verify the real application save instead.
  const dispatch = await until(action + ' input dispatch', () => {
    const output = automation(app, action);
    return output.startsWith('DISPATCHED ') ? output : false;
  });
  console.log(action + ': ' + dispatch);
  await until(action + ' preference persisted', () => {
    if (!fs.existsSync(file)) return false;
    const value = fs.readFileSync(file, 'utf8').trim();
    return enabled ? value === coreDigest : value === 'null';
  });
  console.log('PASS: ' + action + ' preference persisted by the application');
  await until(action + ' restart prompt', () => automation(app, 'ServicePending') === 'OK');
}

function desktopPid(app) {
  return Number(powershell("(Get-Process -Name 'NetVerge-MITM' -ErrorAction SilentlyContinue | Where-Object Path -eq " + q(app) + " | Select-Object -First 1).Id; exit 0"));
}

async function restartDesktop(app, previousPid) {
  assert.ok(previousPid > 0);
  await until('restart button', () => automation(app, 'Restart') === 'OK');
  await until('desktop process restart', () => {
    const pid = desktopPid(app);
    return pid > 0 && pid !== previousPid;
  });
  await until('MITM navigation after restart', () => automation(app, 'Open') === 'OK', 70000);
}

async function main() {
  assert.ok(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true', 'requires a disposable Windows runner');
  const root = path.resolve(process.argv[2]);
  const appRoot = path.join(process.env.APPDATA, 'io.github.clash-verge-rev.clash-verge-rev.dev');
  const app = path.join(root, 'NetVerge-MITM.exe');
  const launcher = path.join(root, 'NetVerge-MITM.ps1');
  const node = path.join(root, 'worker', 'node.exe');
  const rewriteTest = process.argv[3] === 'rewrite';
  const advancedModule = process.argv[3] === 'modules-advanced';
  const moduleTest = process.argv[3] === 'modules' || advancedModule;
  const worker = rewriteTest ? path.resolve(__dirname, '../../whistle/route-worker.cjs') :
    path.join(root, 'worker', 'route-worker.cjs');
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

    const moduleManifest = path.join(appRoot, 'profiles', 'desktop-fixture', 'modules', 'fixture', 'module.yaml');
    if (moduleTest) {
      fs.mkdirSync(path.dirname(moduleManifest), { recursive: true });
      writeModuleManifest(moduleManifest, selected, '1.0', [['res-init', 'response-header', { set: { 'X-NetVerge-Test': '1' } }]]);
    }

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
    await changeServiceMode(app, mitm, true, coreDigest);
    await restartDesktop(app, desktop.pid);
    const processPath = await until('guarded service core startup', () =>
      powershell("(Get-Process -Name 'netverge-mihomo-service' -ErrorAction SilentlyContinue).Path; exit 0"), 90000);
    assert.match(processPath, /\\clash-verge-service-dev\\cores\\netverge-mihomo-service\.exe$/i);
    await until('restored desktop MITM state', () => automation(app, 'Healthy') === 'OK', 60000);
    execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled'], { stdio: 'inherit', timeout: 75000 });
    console.log('PASS: clicked desktop MITM service switch and restarted into a protected service generation');

    if (moduleTest) {
      await verifyModuleApproval({
        app, manifest: moduleManifest, netFixture, temp, dnsPort, selected, advancedModule, until, automation,
      });
    }

    if (rewriteTest) {
      const file = path.join(mitm, 'response-header-rule.json');
      for (const enabled of [true, false]) {
        const rule = { enabled, host: selected, path: '/demo', header: 'X-NetVerge-Test', value: '1' };
        fs.writeFileSync(file + '.tmp', JSON.stringify(rule));
        fs.renameSync(file + '.tmp', file);
        // Each probe establishes new native TUN connections after the worker reload.
        await sleep(1200);
        execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', enabled ? 'on' : 'off'],
          { stdio: 'inherit', timeout: 75000 });
        console.log('PASS: response header rewrite ' + (enabled ? 'enabled' : 'disabled') + ', exact path, bypass and exit verified');
      }
      // Same original GET request, same host/path and same native TLS/exit
      // assertions; changing only the method condition must change the outcome.
      for (const [method, expected] of [['GET', 'on'], ['POST', 'off']]) {
        const rule = { enabled: true, host: selected, path: '/demo', method, header: 'X-NetVerge-Test', value: '1' };
        fs.writeFileSync(file + '.tmp', JSON.stringify({ version: 2, rules: [rule] }));
        fs.renameSync(file + '.tmp', file);
        await sleep(1200);
        execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', expected],
          { stdio: 'inherit', timeout: 75000 });
        console.log('PASS: HTTP method ' + method + ' condition against original GET, TLS and original exit verified');
      }
      for (const [label, payload, expected] of [
        ['matching RE2-subset URL regex with explicit rule ID/source/revision', {
          version: 2,
          revision: 2,
          rules: [{ id: 'com.example.debug:demo-header', source: 'module:com.example.debug', enabled: true, host: selected, path: '', regex: '^https://api\\.example\\.test/de[m]o$', header: 'X-NetVerge-Test', value: '1' }],
        }, 'on'],
        ['non-matching RE2-subset URL regex', {
          version: 2,
          rules: [{ enabled: true, host: selected, path: '', regex: '^https://api\\.example\\.test/v[0-9]+/demo$', header: 'X-NetVerge-Test', value: '1' }],
        }, 'off'],
        ['unsupported lookahead regex rejected', {
          version: 2,
          rules: [{ enabled: true, host: selected, path: '', regex: '^https://api\\.example\\.test/(?=demo)demo$', header: 'X-NetVerge-Test', value: '1' }],
        }, 'off'],
        ['duplicate rule IDs rejected', {
          version: 2,
          rules: [
            { id: 'dup-id', enabled: true, host: selected, path: '/demo', header: 'X-NetVerge-Test', value: '1' },
            { id: 'dup-id', enabled: false, host: selected, path: '/demo/other', header: 'X-NetVerge-Extra', value: '2' },
          ],
        }, 'off'],
      ]) {
        fs.writeFileSync(file + '.tmp', JSON.stringify(payload));
        fs.renameSync(file + '.tmp', file);
        await sleep(1200);
        execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', expected],
          { stdio: 'inherit', timeout: 75000 });
        console.log('PASS: ' + label + ' against original HTTPS URL, bypass and original exit verified');
      }
      fs.unlinkSync(file);
      await verifyCompiledModuleBundle({ mitm, file, selected, sha256, netFixture, temp, dnsPort });
      const bodyFile = path.join(mitm, 'response-body-rule.json');
      for (const enabled of [true, false]) {
        const bodyRule = { version: 2, rules: [{ enabled, host: selected, path: '/demo', search: 'netverge-windows-tun-origin', value: 'netverge-body-rewritten' }] };
        fs.writeFileSync(bodyFile + '.tmp', JSON.stringify(bodyRule));
        fs.renameSync(bodyFile + '.tmp', bodyFile);
        await sleep(1200);
        execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', enabled ? 'body-on' : 'body-off'],
          { stdio: 'inherit', timeout: 75000 });
        console.log('PASS: response body rewrite ' + (enabled ? 'enabled' : 'disabled') + ', gzip decode, Content-Length and streaming bounds verified');
      }
      fs.unlinkSync(bodyFile);
    }

    const editor = ['editor', 'editor-filters', 'editor-inspector', 'editor-rules', 'editor-body'].includes(process.argv[3]);
    const hasFilters = ['editor-filters', 'editor-inspector', 'editor-rules', 'editor-body'].includes(process.argv[3]);
    const hasInspector = ['editor-inspector', 'editor-rules', 'editor-body'].includes(process.argv[3]);
    const hasMultiRules = ['editor-rules', 'editor-body'].includes(process.argv[3]);
    const hasBody = process.argv[3] === 'editor-body';
    const directions = !editor ? [] : hasBody ? ['response', 'request', 'path', 'body'] : ['response', 'request', 'path'];
    for (const direction of directions) {
      const request = direction === 'request';
      const pathRule = direction === 'path';
      const bodyRule = direction === 'body';
      if (pathRule) await until('open URL path editor', () => automation(app, 'OpenPathRule') === 'OK');
      if (request) await until('open request header editor', () => automation(app, 'OpenRequestRule') === 'OK');
      if (bodyRule) await until('open response body editor', () => automation(app, 'OpenBodyRule') === 'OK');
      const file = path.join(mitm, pathRule ? 'url-path-rule.json' : bodyRule ? 'response-body-rule.json' : direction + '-header-rule.json');
      await until('enter and verify all rewrite field values', () => automation(app, pathRule ? 'FillPathRule' : bodyRule ? 'FillBodyRule' : request ? 'FillRequestRule' : 'FillRule') === 'OK', 70000);
      const rule = pathRule ? { enabled: false, host: selected, path: '/demo', target: '/changed' }
        : bodyRule ? { enabled: false, host: selected, path: '/demo', search: 'netverge-windows-tun-origin', value: 'netverge-body-rewritten' }
        : { enabled: false, host: selected, path: '/demo', header: request ? 'X-Custom-NetVerge-Test' : 'X-NetVerge-Test', value: request ? 'rewritten' : '1' };
      for (const [index, enabled] of [false, true, false].entries()) {
        if (enabled !== rule.enabled) await until('toggle rewrite', () => automation(app, 'ToggleRule') === 'OK');
        rule.enabled = enabled;
        await until('autosaved rewrite (enabled=' + enabled + ')', () => {
          const expectedSaved = hasMultiRules ? { version: 2, rules: [rule] } : rule;
          assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), expectedSaved);
          return true;
        });
        await sleep(1200);
        const probeKind = (pathRule ? 'path-' : bodyRule ? 'body-' : request ? 'request-' : '') + (enabled ? 'on' : 'off');
        execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', probeKind],
          { stdio: 'inherit', timeout: 75000 });
        if (enabled && pathRule) await until('recent request shows exact path, status and matched rule', () => automation(app, 'RecentRequests') === 'OK');
        if (enabled && pathRule && hasFilters) {
          await until('filter recent requests by path and matched rule', () => automation(app, 'FilterRecent') === 'OK');
          console.log('PASS: recent request search, rule filter, no-match result and clearing search');
        }
        if (enabled && pathRule && hasInspector) {
          await until('inspect recent request details, timing and header redaction', () => automation(app, 'InspectRecent') === 'OK');
          await until('clear recent requests and confirm empty session state', () => automation(app, 'ClearRecent') === 'OK');
          await sleep(2500);
          assert.equal(automation(app, 'RecentEmpty'), 'OK');
          if (hasBody) {
            await until('pause the empty recent request list', () => automation(app, 'PauseRecent') === 'OK');
            execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', probeKind],
              { stdio: 'inherit', timeout: 75000 });
            await sleep(2500);
            assert.equal(automation(app, 'RecentEmpty'), 'OK');
            await until('resume recent request updates', () => automation(app, 'ResumeRecent') === 'OK');
            await until('show the matching request completed while paused', () => automation(app, 'RecentPathVisible') === 'OK');
            console.log('PASS: paused recent requests stayed frozen and resumed with matching TLS traffic');
          }
          console.log('PASS: recent request detail disclosure, timing, header redaction and clear');
        }
        if (index === 0) await until('visible zero rewrite hits before enabling', () => automation(app, 'RuleHitsZero') === 'OK');
        if (enabled) await until('visible positive rewrite hits after matching TLS request', () => automation(app, 'RuleHits') === 'OK');
        if (enabled && direction === 'response' && hasMultiRules) {
          const second = { enabled: true, host: selected, path: '/demo', header: 'X-NetVerge-Extra', value: 'second' };
          await until('add and fill second response rule', () => automation(app, 'AddSecondRule') === 'OK', 70000);
          await until('enable second response rule', () => automation(app, 'ToggleSecondRule') === 'OK');
          await until('autosaved distinct two-rule list', () => {
            assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { version: 2, rules: [rule, second] });
            return true;
          });
          await sleep(1200);
          execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', 'multi-both'], { stdio: 'inherit', timeout: 75000 });

          const conflict = { ...second, header: 'X-NetVerge-Test', value: 'override' };
          await until('edit second rule to conflicting header name', () => automation(app, 'ConflictSecondRule') === 'OK', 70000);
          await until('autosaved conflicting two-rule list', () => {
            assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { version: 2, rules: [rule, conflict] });
            return true;
          });
          await sleep(1200);
          execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', 'multi-override'], { stdio: 'inherit', timeout: 75000 });

          await until('move second rule above first rule', () => automation(app, 'MoveUpSecondRule') === 'OK');
          await until('autosaved reordered two-rule list', () => {
            assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { version: 2, rules: [conflict, rule] });
            return true;
          });
          await sleep(1200);
          execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', 'on'], { stdio: 'inherit', timeout: 75000 });

          await until('independently disable second rule', () => automation(app, 'ToggleSecondRule') === 'OK');
          await until('autosaved independently disabled second rule', () => {
            assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { version: 2, rules: [conflict, { ...rule, enabled: false }] });
            return true;
          });
          await sleep(1200);
          execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', 'multi-override'], { stdio: 'inherit', timeout: 75000 });

          await until('restore original rule to top', () => automation(app, 'MoveUpSecondRule') === 'OK');
          await until('re-enable restored top rule', () => automation(app, 'ToggleRule') === 'OK');
          await until('delete second rule', () => automation(app, 'DeleteSecondRule') === 'OK');
          await until('autosaved restored single-rule list', () => {
            assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { version: 2, rules: [rule] });
            return true;
          });
          console.log('PASS: multi-rule response list addition, distinct headers, conflict override, reorder, independent toggle and deletion');
        }
      }
      await until('delete rewrite', () => automation(app, 'DeleteRule') === 'OK');
      await until('removed rewrite file', () => !fs.existsSync(file));
      console.log('PASS: packaged ' + direction + ' editor autosave, toggle, TLS, hits and deletion');
    }

    if (rewriteTest || editor) {
      // The editor acceptance runs the newly packaged worker, while the
      // independent rewrite scenario runs the current source worker.
      const file = path.join(mitm, 'request-header-rule.json');
      const rule = { enabled: true, host: selected, path: '/demo', header: 'X-Custom-NetVerge-Test', value: 'rewritten' };
      for (const [name, candidate, expected] of [
        ['enabled', rule, 'request-on'],
        ['disabled', { ...rule, enabled: false }, 'request-off'],
        ['reserved control header rejected', { ...rule, header: 'X-Whistle-Tunnel-Data' }, 'request-off'],
      ]) {
        fs.writeFileSync(file + '.tmp', JSON.stringify(candidate));
        fs.renameSync(file + '.tmp', file);
        await sleep(1200);
        execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', expected],
          { stdio: 'inherit', timeout: 75000 });
        console.log('PASS: request header rewrite ' + name + ', exact path, bypass, TLS and original exit verified');
      }
      fs.unlinkSync(file);
    }

    const serviceDesktopPid = desktopPid(app);
    await changeServiceMode(app, mitm, false, coreDigest);
    await restartDesktop(app, serviceDesktopPid);
    await until('restored Sidecar MITM state', () => automation(app, 'Healthy') === 'OK', 90000);
    const sidecarPath = powershell("(Get-Process -Name 'verge-mihomo').Path");
    assert.equal(path.normalize(sidecarPath).toLowerCase(), path.join(root, 'verge-mihomo.exe').toLowerCase());
    assert.equal(powershell("if (Get-Process -Name 'netverge-mihomo-service' -ErrorAction SilentlyContinue) { 'running' }; exit 0"), '');
    execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled'], { stdio: 'inherit', timeout: 75000 });
    console.log('PASS: service mode disabled, guarded core stopped and Sidecar preserved the selected TLS scope and exit');
  } catch (error) {
    console.error(powershell("Get-Process -Name 'netverge-mihomo-service','verge-mihomo','node' -ErrorAction SilentlyContinue | Select-Object ProcessName,Id | ConvertTo-Json -Compress; exit 0"));
    const preferencePath = path.join(mitm, 'guarded-service.yaml');
    if (fs.existsSync(preferencePath)) {
      const preference = fs.readFileSync(preferencePath, 'utf8').trim();
      console.error('Preference after failure:', preference === coreDigest ? 'guarded core' : JSON.stringify(preference).slice(0,100));
    }
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
