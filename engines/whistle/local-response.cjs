'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { createHash } = require('node:crypto');

const ALLOWED_STATUS = new Set([200, 201, 202, 204, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503]);
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const MAX_LOCAL_BODY_BYTES = 262144;
const MAX_BUNDLE_LOCAL_BYTES = 1048576;
const ALLOWED_KEYS = new Set(['enabled', 'host', 'path', 'status', 'contentType', 'headers', 'bodySha256', 'bodyLen']);
const MIME_RE = /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+(?:\s*;\s*[A-Za-z0-9!#$&^_.+-]+=[A-Za-z0-9!#$&^_.+-]+)*$/;

function createBlobLoader(dataDir) {
  let totalBytes = 0;
  const cache = new Map();
  return (bodySha256, bodyLen) => {
    if (bodyLen === 0) {
      if (bodySha256 !== EMPTY_SHA256) throw new Error();
      return Buffer.alloc(0);
    }
    if (cache.has(bodySha256)) {
      const cached = cache.get(bodySha256);
      if (cached.length !== bodyLen) throw new Error();
      return cached;
    }
    const blobPath = path.join(dataDir, 'approved-blobs', bodySha256);
    const stat = fs.lstatSync(blobPath);
    if (!stat.isFile() || stat.size !== bodyLen) throw new Error();
    totalBytes += bodyLen;
    if (totalBytes > MAX_BUNDLE_LOCAL_BYTES) throw new Error();
    const buf = fs.readFileSync(blobPath);
    if (buf.length !== bodyLen || createHash('sha256').update(buf).digest('hex') !== bodySha256) {
      throw new Error();
    }
    cache.set(bodySha256, buf);
    return buf;
  };
}

function validateLocalRule(rule, validHost, loadBlob) {
  const keys = Object.keys(rule);
  if (keys.some(k => !ALLOWED_KEYS.has(k)) ||
      typeof rule.enabled !== 'boolean' || typeof rule.host !== 'string' ||
      typeof rule.path !== 'string' || !ALLOWED_STATUS.has(rule.status) ||
      !Number.isInteger(rule.bodyLen) || rule.bodyLen < 0 || rule.bodyLen > MAX_LOCAL_BODY_BYTES ||
      typeof rule.bodySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(rule.bodySha256)) {
    throw new Error();
  }
  if (rule.status === 204 && (rule.bodyLen !== 0 || rule.contentType != null)) {
    throw new Error();
  }
  if (rule.contentType != null) {
    if (typeof rule.contentType !== 'string' || rule.contentType.length < 3 ||
        rule.contentType.length > 128 || !MIME_RE.test(rule.contentType)) {
      throw new Error();
    }
    http.validateHeaderValue('content-type', rule.contentType);
  }
  const headers = [];
  if (rule.headers != null) {
    if (!Array.isArray(rule.headers) || rule.headers.length < 1 || rule.headers.length > 4) {
      throw new Error();
    }
    const seen = new Set();
    for (const pair of rule.headers) {
      if (!Array.isArray(pair) || pair.length !== 2 ||
          typeof pair[0] !== 'string' || typeof pair[1] !== 'string') {
        throw new Error();
      }
      const lower = pair[0].toLowerCase();
      if (!/^x-[a-z0-9-]{1,100}$/.test(lower) || seen.has(lower) || pair[1].length > 1024) {
        throw new Error();
      }
      http.validateHeaderValue(pair[0], pair[1]);
      seen.add(lower);
      headers.push([pair[0], pair[1]]);
    }
  }
  if (!rule.enabled) return null;
  if (!validHost(rule.host) || !/^\/[^?#\s]*$/.test(rule.path)) throw new Error();
  const payload = loadBlob(rule.bodySha256, rule.bodyLen);
  return {
    enabled: true,
    host: rule.host,
    path: rule.path,
    status: rule.status,
    contentType: rule.contentType ?? null,
    headers,
    bodySha256: rule.bodySha256,
    bodyLen: rule.bodyLen,
    payload,
  };
}

function writeLocalResponse(req, res, localRule, onHit) {
  req?.on?.('error', () => {});
  req?.resume?.();
  const payload = localRule.payload ?? Buffer.alloc(0);
  const pairs = ['Cache-Control', 'no-store', 'Connection', 'close'];
  if (localRule.status !== 204) {
    if (localRule.contentType) pairs.push('Content-Type', localRule.contentType);
    pairs.push('Content-Length', String(payload.length));
  }
  for (const [name, value] of localRule.headers || []) {
    pairs.push(name, value);
  }
  onHit();
  res.writeHead(localRule.status, pairs);
  if (localRule.status === 204 || req?.method === 'HEAD') res.end();
  else res.end(payload);
}

module.exports = {
  EMPTY_SHA256,
  createBlobLoader,
  validateLocalRule,
  writeLocalResponse,
};
