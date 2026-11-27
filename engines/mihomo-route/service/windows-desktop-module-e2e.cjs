'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { setTimeout: sleep } = require('node:timers/promises');

function writeModuleManifest(file, selected, version, changes) {
  fs.writeFileSync(file + '.tmp', JSON.stringify({
    kind: 'netverge-module',
    schema: 1,
    id: 'com.example.desktop-approval',
    name: 'Desktop Approval Fixture',
    version,
    rewrite: changes.map(([id, type, action]) => ({
      id,
      type,
      match: { host: selected, path: '/demo' },
      action,
    })),
  }));
  fs.renameSync(file + '.tmp', file);
}

async function verifyModuleApproval({
  app,
  manifest,
  netFixture,
  temp,
  dnsPort,
  selected,
  advancedModule,
  until,
  automation,
}) {
  const probe = expected => {
    execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', expected],
      { stdio: 'inherit', timeout: 75000 });
  };

  await until('discovered module awaiting approval', () => automation(app, 'ModulePending', '1.0') === 'OK');
  probe('off');
  await until('click Approve for discovered module', () => automation(app, 'ApproveModule', '1.0') === 'OK');
  await until('module is active', () => automation(app, 'ModuleActive', '1.0') === 'OK');
  await sleep(1200);
  probe('on');
  console.log('PASS: desktop module approval enabled the scoped rewrite over TUN/TLS');

  const updatedActions = advancedModule ? [
    ['req-rm', 'request-header', { remove: ['X-Custom-NetVerge-Test'] }],
    ['res-rm', 'response-header', { remove: ['X-NetVerge-Test'] }],
    ['url-rm', 'url', { 'remove-query': ['debug'] }],
    ['body-whole', 'response-body', {
      search: '{"marker":"netverge-windows-tun-origin","path":"/demo"}',
      replace: '{"marker":"netverge-body-rewritten","path":"/demo"}',
      'match-whole': true,
    }],
  ] : [
    ['res-set', 'response-header', { set: { 'X-NetVerge-Test': 'override' } }],
  ];
  writeModuleManifest(manifest, selected, '1.1', updatedActions);
  await until('refresh module list after a manifest edit', () => automation(app, 'RefreshMitm') === 'OK');
  await until('updated module awaiting approval', () => automation(app, 'ModuleUpdatePending', '1.1') === 'OK');
  probe(advancedModule ? 'module-pending' : 'on');
  await until('click Approve for updated module', () => automation(app, 'ApproveModule', '1.1') === 'OK');
  await until('updated module is active', () => automation(app, 'ModuleActive', '1.1') === 'OK');
  await sleep(1200);
  probe(advancedModule ? 'module-remove' : 'multi-override');
  if (!advancedModule) {
    console.log('PASS: editing the manifest preserved the approved rewrite until the update was approved');
    return;
  }
  console.log('PASS: approved module removed both headers and selected query parameters only on the matched request');
  probe('body-whole');
  console.log('PASS: a whole-body rule rewrote the exact gzip payload and preserved the one-byte variant');

  const profileRoot = path.resolve(path.dirname(manifest), '../..');
  const assetFile = path.join(profileRoot, 'assets', 'mock.json');
  fs.mkdirSync(path.dirname(assetFile), { recursive: true });
  fs.writeFileSync(assetFile, '{"marker":"netverge-map-local-v1","path":"/demo"}');
  writeModuleManifest(manifest, selected, '1.2', [
    ['url-forward', 'url', { replace: '/changed' }],
    ['req-set', 'request-header', { set: { 'X-Custom-NetVerge-Test': 'rewritten' } }],
    ['map-first', 'map-local', {
      status: 201,
      file: 'assets/mock.json',
      headers: { 'X-NetVerge-Test': 'map-local' },
    }],
    ['mock-second', 'mock', {
      status: 200,
      'content-type': 'application/json; charset=utf-8',
      body: '{"marker":"shadowed","path":"/demo"}',
    }],
  ]);
  await until('refresh module list after adding map-local', () => automation(app, 'RefreshMitm') === 'OK');
  await until('map-local module awaiting approval', () => automation(app, 'ModuleUpdatePending', '1.2') === 'OK');
  await until('approve map-local module', () => automation(app, 'ApproveModule', '1.2') === 'OK');
  await until('map-local module active', () => automation(app, 'ModuleActive', '1.2') === 'OK');
  await sleep(1200);
  probe('map-local-v1');
  console.log('PASS: map-local took terminal precedence with zero upstream origin HTTP request');

  // Editing only the referenced workspace asset must mark UpdatePending while keeping approved v1 bytes active.
  fs.writeFileSync(assetFile, '{"marker":"netverge-map-local-v2","path":"/demo"}');
  await until('refresh module list after editing map-local asset', () => automation(app, 'RefreshMitm') === 'OK');
  await until('asset edit marks module UpdatePending', () => automation(app, 'ModuleUpdatePending', '1.2') === 'OK');
  probe('map-local-v1');
  await until('approve updated map-local asset', () => automation(app, 'ApproveModule', '1.2') === 'OK');
  await until('re-approved map-local module active', () => automation(app, 'ModuleActive', '1.2') === 'OK');
  await sleep(1200);
  probe('map-local-v2');
  console.log('PASS: unapproved asset edit preserved v1 bytes until re-approval committed v2');
  await until('arm one-shot JSON response preview', () => automation(app, 'ArmPreview') === 'OK');
  probe('map-local-v2');
  await until('inspect captured local JSON response', () => automation(app, 'PreviewCaptured') === 'OK');
  await until('clear preview and recent requests', () => automation(app, 'ClearRecent') === 'OK');
  console.log('PASS: opt-in JSON preview observed final local response; clear discarded the session preview');
}

async function verifyCompiledModuleBundle({ mitm, file, selected, sha256, netFixture, temp, dnsPort }) {
  const probe = expected => {
    execFileSync(process.execPath, [netFixture, 'probe', temp, String(dnsPort), 'enabled', expected],
      { stdio: 'inherit', timeout: 75000 });
  };
  const moduleBundleFile = path.join(mitm, 'compiled-module-rules.json');
  const modRule = value => ({
    id: 'com.example.debug:resp', source: 'module:com.example.debug', enabled: true,
    host: selected, path: '', regex: '^https://api\\.example\\.test/demo$', header: 'X-NetVerge-Test', value,
  });
  fs.writeFileSync(moduleBundleFile + '.tmp', JSON.stringify({
    version: 1, profileUid: 'desktop-fixture', revision: 1, request: [], response: [modRule('1')], path: [], body: [],
  }));
  fs.renameSync(moduleBundleFile + '.tmp', moduleBundleFile);
  await sleep(1200);
  probe('on');
  console.log('PASS: compiled module rewrite bundle applied over Windows TUN and native TLS');

  fs.writeFileSync(moduleBundleFile + '.tmp', JSON.stringify({
    version: 1, profileUid: 'desktop-fixture', revision: 2, request: [], response: [modRule('module-shadowed')], path: [], body: [],
  }));
  fs.renameSync(moduleBundleFile + '.tmp', moduleBundleFile);
  fs.writeFileSync(file + '.tmp', JSON.stringify({ version: 2, rules: [{ enabled: true, host: selected, path: '/demo', header: 'X-NetVerge-Test', value: '1' }] }));
  fs.renameSync(file + '.tmp', file);
  await sleep(1200);
  probe('on');
  console.log('PASS: local rewrite rule retained precedence over conflicting module rule');

  const mockPayload = Buffer.from('{"marker":"netverge-inline-mock","path":"/demo"}', 'utf8');
  const mockSha = sha256(mockPayload);
  const blobsDir = path.join(mitm, 'approved-blobs');
  fs.mkdirSync(blobsDir, { recursive: true });
  fs.writeFileSync(path.join(blobsDir, mockSha), mockPayload);
  fs.writeFileSync(moduleBundleFile + '.tmp', JSON.stringify({
    version: 1,
    profileUid: 'desktop-fixture',
    revision: 3,
    request: [],
    response: [],
    path: [{ id: 'com.example.debug:url', source: 'module:com.example.debug', enabled: true, host: selected, path: '/demo', target: '/changed' }],
    body: [],
    local: [{
      id: 'com.example.debug:mock',
      source: 'module:com.example.debug',
      enabled: true,
      host: selected,
      path: '/demo',
      status: 200,
      contentType: 'application/json; charset=utf-8',
      headers: [['X-NetVerge-Test', 'module-shadowed']],
      bodySha256: mockSha,
      bodyLen: mockPayload.length,
    }],
  }));
  fs.renameSync(moduleBundleFile + '.tmp', moduleBundleFile);
  await sleep(1200);
  probe('mock-local-override');
  console.log('PASS: terminal local response suppressed upstream origin request and kept local header override');
  fs.unlinkSync(moduleBundleFile);
  fs.rmSync(blobsDir, { recursive: true, force: true });
  fs.unlinkSync(file);
}

module.exports = {
  writeModuleManifest,
  verifyModuleApproval,
  verifyCompiledModuleBundle,
};
