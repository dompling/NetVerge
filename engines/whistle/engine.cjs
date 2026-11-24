'use strict';

const fs = require('node:fs');
const path = require('node:path');
const whistle = require('whistle');

function readPort(name, value) {
  if (!/^\d+$/.test(value ?? '')) throw new Error(name + ' must be a TCP port');
  const port = Number(value);
  if (port < 1 || port > 65535) throw new Error(name + ' is out of range');
  return port;
}

const port = readPort('NETVERGE_HTTP_PORT', process.env.NETVERGE_HTTP_PORT || '8899');
const upstream = readPort('NETVERGE_MIHOMO_PORT', process.env.NETVERGE_MIHOMO_PORT);
if (port === upstream) throw new Error('Whistle and Mihomo must use different ports');
const dataDir = process.env.NETVERGE_HTTP_DATA;
if (!dataDir || !path.isAbsolute(dataDir)) {
  throw new Error('NETVERGE_HTTP_DATA must be an absolute private data directory');
}
fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const ruleFile = process.env.NETVERGE_HTTP_RULES;
const extraRules = ruleFile ? fs.readFileSync(ruleFile, 'utf8') : '';

whistle({
  host: '127.0.0.1',
  port,
  baseDir: dataDir,
  mode: 'safe',
  noGlobalPlugins: true,
  disableAllPlugins: true,
  shadowRules: extraRules + '\n/.*/ proxy://127.0.0.1:' + upstream,
}, () => {
  process.stdout.write(JSON.stringify({ event: 'ready', port, upstream }) + '\n');
});
