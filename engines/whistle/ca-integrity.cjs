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

// Keep full-width file identities: NTFS file IDs may exceed Number's
// exact integer range. Do not waive volume or inode checks on Windows.
// libuv < 1.51 has a known Windows path/handle volume-serial mismatch.
function sameFileSnapshot(a, b) {
  return a.isFile() && b.isFile() && a.dev === b.dev && a.ino !== 0n &&
    a.ino === b.ino && a.nlink === 1n && b.nlink === 1n &&
    a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

function privateKeyStat(stat) {
  return !unix || (stat.uid === BigInt(process.getuid()) && (stat.mode & 0o077n) === 0n);
}

function readSingleFile(file, isKey) {
  const initial = fs.lstatSync(file, { bigint: true });
  if (!initial.isFile() || initial.nlink !== 1n || initial.size < 1n ||
      initial.size > BigInt(MAX_FILE) || fs.realpathSync(file) !== file ||
      (isKey && !privateKeyStat(initial))) {
    throw new Error('Unsafe CA file');
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (unix ? fs.constants.O_NOFOLLOW : 0));
  let bytes;
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!sameFileSnapshot(initial, opened) || (isKey && !privateKeyStat(opened))) {
      throw new Error('CA file changed while opening');
    }
    // Size was bounded before conversion to Number.
    const size = Number(opened.size);
    bytes = Buffer.alloc(size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    const final = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(file, { bigint: true });
    if (offset !== size || !sameFileSnapshot(opened, final) ||
        !sameFileSnapshot(final, current) || fs.realpathSync(file) !== file ||
        (isKey && (!privateKeyStat(final) || !privateKeyStat(current)))) {
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
