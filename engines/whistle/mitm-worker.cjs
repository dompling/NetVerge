'use strict';

const whistle = require('whistle');
const [dataDir, portText, returnPortText] = process.argv.slice(2);
const port = Number(portText);
const returnPort = Number(returnPortText);
if (!dataDir || ![port, returnPort].every(p => Number.isInteger(p) && p > 0 && p < 65536) || port === returnPort) {
  throw new Error('Invalid isolated lab configuration');
}

process.on('disconnect', () => process.exit(0));

whistle({
  host: '127.0.0.1',
  port,
  baseDir: dataDir,
  rcPath: 'none',
  mode: 'safe|disableCapture|shadowRulesOnly|disableUpdateTips',
  noGlobalPlugins: true,
  disableAllPlugins: true,
  shadowRules: [
    'mitm.netverge.test enable://capture',
    '/.*/ proxy://127.0.0.1:' + returnPort,
  ].join('\n'),
}, (proxy) => {
  proxy.on('request', (emitter, data) => {
    if (data.url && data.url.startsWith('https://mitm.netverge.test:')) {
      process.send({ event: 'observed', url: data.url, method: data.req.method });
    }
  });
  process.send({ event: 'ready', caPath: proxy.httpsUtil.getRootCAFile() });
});
