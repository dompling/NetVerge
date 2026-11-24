'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { X509Certificate, createPrivateKey } = require('node:crypto');

const MAX_FILE = 32768;
const unix = process.platform !== 'win32';

function privateDirectory(dir) {
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || (unix && (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0))) {
    throw new Error('Unsafe CA directory');
  }
}

function readSingleFile(file, isKey) {
  const initial = fs.lstatSync(file);
  if (!initial.isFile() || initial.nlink !== 1 || initial.size < 1 || initial.size > MAX_FILE ||
      fs.realpathSync(file) !== file ||
      (unix && isKey && (initial.uid !== process.getuid() || (initial.mode & 0o077) !== 0))) {
    throw new Error('Unsafe CA file');
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (unix ? fs.constants.O_NOFOLLOW : 0));
  let bytes;
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.dev !== initial.dev || opened.ino !== initial.ino ||
        opened.nlink !== 1 || opened.size !== initial.size ||
        (unix && isKey && (opened.uid !== process.getuid() || (opened.mode & 0o077) !== 0))) {
      throw new Error('CA file changed while opening');
    }
    bytes = Buffer.alloc(opened.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const final = fs.fstatSync(fd);
    if (offset !== opened.size || final.size !== opened.size || final.nlink !== 1 ||
        (unix && isKey && (final.uid !== process.getuid() || (final.mode & 0o077) !== 0))) {
      throw new Error('CA file changed while reading');
    }
    return bytes.subarray(0, offset);
  } catch (error) {
    if (isKey && bytes) bytes.fill(0);
    throw error;
  } finally {
    fs.closeSync(fd);
  }
}

// Validate the existing Whistle-owned root. Never create, rotate, install,
// export or log a private key. Windows ACLs are NOT verified by Node stat.
function readVerifiedCa(dataDir, caPath) {
  privateDirectory(dataDir);
  const root = fs.realpathSync(dataDir);
  const resolved = fs.realpathSync(caPath);
  const relative = path.relative(root, resolved);
  if (!relative || relative === '..' || relative.startsWith('..' + path.sep) ||
      path.isAbsolute(relative) || !fs.lstatSync(caPath).isFile() ||
      !['root.crt', 'root_new.crt'].includes(path.basename(resolved))) {
    throw new Error('Unexpected CA location');
  }
  let dir = path.dirname(resolved);
  while (dir !== root) {
    privateDirectory(dir);
    dir = path.dirname(dir);
  }
  const pem = readSingleFile(resolved, false).toString('utf8');
  if (!/^\s*-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----\s*$/.test(pem)) {
    throw new Error('Expected one public certificate');
  }
  const cert = new X509Certificate(pem);
  const now = Date.now();
  if (!cert.ca || !cert.checkIssued(cert) || !cert.verify(cert.publicKey) ||
      !Number.isFinite(Date.parse(cert.validFrom)) || !Number.isFinite(Date.parse(cert.validTo)) ||
      Date.parse(cert.validFrom) > now || Date.parse(cert.validTo) <= now || cert.raw.length > 16384) {
    throw new Error('Invalid CA');
  }
  const keyPath = path.join(path.dirname(resolved), path.basename(resolved, '.crt') + '.key');
  const keyBytes = readSingleFile(keyPath, true);
  try {
    if (!cert.checkPrivateKey(createPrivateKey(keyBytes))) {
      throw new Error('Root certificate and key do not match');
    }
  } finally {
    keyBytes.fill(0);
  }
  return { caPath: resolved, caDer: cert.raw.toString('base64') };
}

module.exports = { readVerifiedCa };
