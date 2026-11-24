'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const forge = require('node-forge');
const { X509Certificate } = require('node:crypto');
const { readVerifiedCa } = require('./ca-integrity.cjs');

function makeRoot(serial) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = serial;
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  const subject = [{ name: 'commonName', value: 'NetVerge isolated CA fixture ' + serial }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([{ name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { pem: forge.pki.certificateToPem(cert), key: forge.pki.privateKeyToPem(keys.privateKey) };
}

test('CA custody validation fails closed on wrong keys, unsafe files and permissions', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'netverge-ca-integrity-'));
  try {
    const dir = path.join(root, 'certs');
    fs.mkdirSync(dir, { mode: 0o700 });
    const certPath = path.join(dir, 'root.crt');
    const keyPath = path.join(dir, 'root.key');
    const a = makeRoot('01');
    const b = makeRoot('02');
    fs.writeFileSync(certPath, a.pem, { mode: 0o600 });
    fs.writeFileSync(keyPath, a.key, { mode: 0o600 });
    const result = readVerifiedCa(root, certPath);
    assert.equal(result.caDer, new X509Certificate(a.pem).raw.toString('base64'));
    assert.deepEqual(Object.keys(result).sort(), ['caDer', 'caPath']);
    fs.writeFileSync(keyPath, b.key, { mode: 0o600 });
    assert.throws(() => readVerifiedCa(root, certPath), /do not match/);
    fs.writeFileSync(keyPath, a.key, { mode: 0o600 });
    const hardlink = path.join(dir, 'extra-key');
    fs.linkSync(keyPath, hardlink);
    assert.throws(() => readVerifiedCa(root, certPath), /Unsafe CA file/);
    fs.unlinkSync(hardlink);
    if (process.platform !== 'win32') {
      fs.chmodSync(keyPath, 0o644);
      assert.throws(() => readVerifiedCa(root, certPath), /Unsafe CA file/);
      fs.chmodSync(keyPath, 0o600);
      fs.chmodSync(dir, 0o755);
      assert.throws(() => readVerifiedCa(root, certPath), /Unsafe CA directory/);
      fs.chmodSync(dir, 0o700);
      const moved = path.join(dir, 'old-key');
      fs.renameSync(keyPath, moved);
      fs.symlinkSync(moved, keyPath);
      assert.throws(() => readVerifiedCa(root, certPath), /Unsafe CA file/);
      fs.unlinkSync(keyPath);
      fs.renameSync(moved, keyPath);
    }
    fs.writeFileSync(keyPath, Buffer.alloc(32769));
    assert.throws(() => readVerifiedCa(root, certPath), /Unsafe CA file/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
