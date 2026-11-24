'use strict';

const path = require('node:path');
const whistle = require('whistle');
const [legacyDataDir, portText, returnPortText] = process.argv.slice(2);
const desktop = !process.send;
const settings = desktop ? JSON.parse(process.env.NETVERGE_MITM_WORKER_CONFIG || '{}') : {
  dataDir: legacyDataDir, port: Number(portText), returnPort: Number(returnPortText),
  hosts: ['mitm.netverge.test'], password: process.env.NETVERGE_LAB_RETURN_PASSWORD || '',
};
const { dataDir, port, returnPort, hosts, password } = settings;
const validHost = host => typeof host === 'string' && host.length <= 253 &&
  host.includes('.') && host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
if (!dataDir || !path.isAbsolute(dataDir) || ![port, returnPort].every(p => Number.isInteger(p) && p > 0 && p < 65536) || port === returnPort ||
    !Array.isArray(hosts) || !hosts.length || !hosts.every(validHost) || typeof password !== 'string' ||
    (desktop && !/^[A-Za-z0-9_-]{32}$/.test(password))) {
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
const auth = password ? 'netverge:' + password + '@' : '';
whistle({
  host: '127.0.0.1',
  port,
  baseDir: dataDir,
  rcPath: 'none',
  mode: 'safe|disableCapture|shadowRulesOnly|disableUpdateTips',
  noGlobalPlugins: true,
  disableAllPlugins: true,
  shadowRules: [
    ...hosts.map(host => host + ' enable://capture'),
    '/.*/ proxy://' + auth + '127.0.0.1:' + returnPort,
  ].join('\n'),
}, (proxy) => {
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
});
