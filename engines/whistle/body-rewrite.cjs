'use strict';

const zlib = require('node:zlib');

const MAX_BODY_BYTES = 262144;

const TEXT_TYPES = /^(?:text\/|application\/(?:json|javascript|ecmascript|xml|xhtml\+xml|x-www-form-urlencoded|graphql|ld\+json|problem\+json|vnd\.[^;]+\+(?:json|xml)))(?:$|;|\s)/i;
const STREAM_TYPES = /^(?:text\/event-stream|multipart\/x-mixed-replace|application\/grpc)(?:$|;|\s)/i;

function readHeader(headers, target) {
  if (Array.isArray(headers)) {
    for (let i = headers.length - 2; i >= 0; i -= 2) {
      if (String(headers[i]).toLowerCase() === target) return headers[i + 1];
    }
    return undefined;
  }
  if (headers && typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === target) return v;
    }
  }
  return undefined;
}

function getHeader(res, explicit, name) {
  const fromExplicit = readHeader(explicit, name);
  if (fromExplicit !== undefined) return Array.isArray(fromExplicit) ? fromExplicit.join(', ') : String(fromExplicit);
  const fromRes = res.getHeader(name);
  return fromRes === undefined ? '' : Array.isArray(fromRes) ? fromRes.join(', ') : String(fromRes);
}

function parseCharset(contentType) {
  const match = /;\s*charset\s*=\s*"?([^";\s]+)"?/i.exec(contentType);
  if (!match) return 'utf-8';
  const raw = match[1].toLowerCase();
  if (raw === 'utf-8' || raw === 'utf8' || raw === 'us-ascii' || raw === 'ascii') return 'utf-8';
  if (raw === 'iso-8859-1' || raw === 'latin1') return 'latin1';
  return null;
}

function supportedEncoding(encoding) {
  const normalized = encoding.trim().toLowerCase();
  if (!normalized || normalized === 'identity' || normalized === 'gzip' || normalized === 'x-gzip' ||
      normalized === 'deflate' || normalized === 'br') return normalized || 'identity';
  if (normalized === 'zstd' && typeof zlib.zstdDecompressSync === 'function') return 'zstd';
  return null;
}

function decompressBody(buffer, encoding) {
  if (!buffer.length || encoding === 'identity') return buffer;
  const opts = { maxOutputLength: MAX_BODY_BYTES + 1 };
  if (encoding === 'gzip' || encoding === 'x-gzip') return zlib.gunzipSync(buffer, opts);
  if (encoding === 'br') return zlib.brotliDecompressSync(buffer, opts);
  if (encoding === 'zstd') return zlib.zstdDecompressSync(buffer, opts);
  try {
    return zlib.inflateSync(buffer, opts);
  } catch {
    return zlib.inflateRawSync(buffer, opts);
  }
}

function decodeText(buffer, charset) {
  if (charset === 'latin1') return buffer.toString('latin1');
  return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
}

function rewriteHeadersForBody(res, explicit, byteLength, charsetChanged) {
  const drop = new Set(['content-encoding', 'transfer-encoding', 'content-length', 'etag', 'content-md5']);
  for (const name of res.getHeaderNames()) {
    if (drop.has(name.toLowerCase())) res.removeHeader(name);
  }
  const normalizeCt = value => charsetChanged
    ? String(value).replace(/;\s*charset\s*=\s*"?[^";\s]+"?/i, '; charset=utf-8')
    : value;
  if (Array.isArray(explicit)) {
    const pairs = [];
    for (let i = 0; i + 1 < explicit.length; i += 2) {
      const lower = String(explicit[i]).toLowerCase();
      if (drop.has(lower)) continue;
      pairs.push(explicit[i], lower === 'content-type' ? normalizeCt(explicit[i + 1]) : explicit[i + 1]);
    }
    pairs.push('content-length', String(byteLength));
    return pairs;
  }
  const updated = { ...(explicit && typeof explicit === 'object' ? explicit : {}) };
  for (const key of Object.keys(updated)) {
    const lower = key.toLowerCase();
    if (drop.has(lower)) delete updated[key];
    else if (lower === 'content-type') updated[key] = normalizeCt(updated[key]);
  }
  updated['content-length'] = String(byteLength);
  return updated;
}

function validateBodyRule(rule, validHost) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule) ||
      Object.keys(rule).sort().join(',') !== 'enabled,host,path,search,value' ||
      typeof rule.enabled !== 'boolean' || typeof rule.host !== 'string' ||
      typeof rule.path !== 'string' || typeof rule.search !== 'string' ||
      typeof rule.value !== 'string') throw new Error();
  if (!rule.enabled) return null;
  if (!validHost(rule.host) || !/^\/[^?#\s]*$/.test(rule.path) ||
      !rule.search.length || Buffer.byteLength(rule.search, 'utf8') > 1024 ||
      Buffer.byteLength(rule.value, 'utf8') > 4096) throw new Error();
  return rule;
}

function installBodyRewrite(req, res, matched, onHit) {
  if (!matched.length || req.method === 'HEAD') return;
  const rawWriteHead = res.writeHead;
  const rawWrite = res.write;
  const rawEnd = res.end;
  let buffering = false;
  let passthrough = false;
  let savedStatus = 200;
  let savedReason;
  let savedExplicit;
  let encoding = 'identity';
  let charset = 'utf-8';
  let total = 0;
  const chunks = [];

  function flushHead(explicitFields) {
    return typeof savedReason === 'string'
      ? rawWriteHead.call(res, savedStatus, savedReason, explicitFields)
      : explicitFields !== undefined
        ? rawWriteHead.call(res, savedStatus, explicitFields)
        : rawWriteHead.call(res, savedStatus);
  }

  function abandonToStream() {
    buffering = false;
    passthrough = true;
    flushHead(savedExplicit);
    for (const part of chunks.splice(0)) rawWrite.call(res, part);
  }

  res.writeHead = function(status, reason, fields) {
    if (passthrough || buffering) return rawWriteHead.apply(this, arguments);
    const code = Number(status) || 200;
    const explicit = typeof reason === 'string' ? fields : reason;
    const ct = getHeader(this, explicit, 'content-type');
    const ce = supportedEncoding(getHeader(this, explicit, 'content-encoding'));
    const clRaw = getHeader(this, explicit, 'content-length').trim();
    const cl = clRaw ? Number(clRaw) : NaN;
    const parsedCharset = parseCharset(ct);
    if ((code >= 100 && code < 200) || code === 204 || code === 205 || code === 206 || code === 304 ||
        STREAM_TYPES.test(ct) || (ct && !TEXT_TYPES.test(ct)) || !ce || !parsedCharset ||
        (Number.isFinite(cl) && cl > MAX_BODY_BYTES)) {
      passthrough = true;
      return rawWriteHead.apply(this, arguments);
    }
    buffering = true;
    savedStatus = code;
    savedReason = typeof reason === 'string' ? reason : undefined;
    savedExplicit = explicit;
    encoding = ce;
    charset = parsedCharset;
    return this;
  };

  res.write = function(chunk, enc, cb) {
    if (!buffering) return rawWrite.apply(this, arguments);
    if (chunk == null) return true;
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof enc === 'string' ? enc : 'utf8');
    if (total + buf.length > MAX_BODY_BYTES) {
      abandonToStream();
      return rawWrite.call(this, buf, cb);
    }
    chunks.push(buf);
    total += buf.length;
    if (typeof enc === 'function') enc();
    else if (typeof cb === 'function') cb();
    return true;
  };

  res.end = function(chunk, enc, cb) {
    if (typeof chunk === 'function') { cb = chunk; chunk = null; enc = undefined; }
    else if (typeof enc === 'function') { cb = enc; enc = undefined; }
    if (!buffering) {
      if (passthrough) return rawEnd.apply(this, arguments);
      // Implicit 200 head when res.end() was called without res.writeHead().
      this.writeHead(this.statusCode || 200);
      if (!buffering) return rawEnd.apply(this, arguments);
    }
    if (chunk != null) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof enc === 'string' ? enc : 'utf8');
      if (total + buf.length > MAX_BODY_BYTES) {
        abandonToStream();
        return rawEnd.call(this, buf, cb);
      }
      chunks.push(buf);
      total += buf.length;
    }
    buffering = false;
    const rawBody = Buffer.concat(chunks.splice(0), total);
    try {
      const decompressed = decompressBody(rawBody, encoding);
      if (decompressed.length > MAX_BODY_BYTES) throw new Error('Body exceeds decoded limit');
      const originalText = decodeText(decompressed, charset);
      let text = originalText;
      let hit = false;
      for (const rule of matched) {
        if (text.includes(rule.search)) {
          text = text.replaceAll(rule.search, rule.value);
          hit = true;
        }
      }
      if (!hit) {
        flushHead(savedExplicit);
        return rawEnd.call(this, rawBody, cb);
      }
      const out = Buffer.from(text, 'utf8');
      const updated = rewriteHeadersForBody(this, savedExplicit, out.length, charset !== 'utf-8');
      onHit();
      flushHead(updated);
      return rawEnd.call(this, out, cb);
    } catch {
      flushHead(savedExplicit);
      return rawEnd.call(this, rawBody, cb);
    }
  };
}

module.exports = { installBodyRewrite, validateBodyRule };
