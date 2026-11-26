'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { installBodyRewrite, validateBodyRule } = require('./body-rewrite.cjs');

const MAX_FILE_BYTES = 8192;
const MAX_BODY_RULE_FILE_BYTES = 16384;
const MAX_RULES = 16;
const MAX_REGEX_LEN = 256;
const MAX_REGEX_STATES = 128;
const MAX_REGEX_DEPTH = 8;
const MAX_REGEX_REPEAT = 16;
const MAX_URL_MATCH_LEN = 2048;
const MAX_REGEX_CACHE = 256;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const SHORTHANDS = new Set([0x64, 0x44, 0x77, 0x57, 0x73, 0x53]);
const compiledCache = new Map();

const isAsciiAlnum = c => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
const isWordCode = c => isAsciiAlnum(c) || c === 0x5f;
const setBit = (mask, c) => { mask[c >>> 5] |= 1 << (c & 31); };
const setRange = (mask, lo, hi) => { for (let c = lo; c <= hi; c++) setBit(mask, c); };

function applyShorthand(mask, esc) {
  for (let c = 0x20; c <= 0x7e; c++) {
    const ok = esc === 0x64 ? (c >= 0x30 && c <= 0x39)
      : esc === 0x44 ? (c < 0x30 || c > 0x39)
      : esc === 0x77 ? isWordCode(c)
      : esc === 0x57 ? !isWordCode(c)
      : esc === 0x73 ? c === 0x20 : c !== 0x20;
    if (ok) setBit(mask, c);
  }
}

// Compile a strict RE2-compatible ASCII subset into a linear-time Thompson NFA.
// Backreferences, lookarounds, inline flags and unbounded state blowups fail closed.
function compileUrlRegex(pattern) {
  if (typeof pattern !== 'string' || !pattern.length || pattern.length > MAX_REGEX_LEN) throw new Error();
  const len = pattern.length;
  for (let i = 0; i < len; i++) {
    const c = pattern.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) throw new Error();
  }
  let pos = 0;
  const peek = () => (pos < len ? pattern.charCodeAt(pos) : -1);
  const nextByte = () => {
    if (pos >= len) throw new Error();
    return pattern.charCodeAt(pos++);
  };
  const parseBound = () => {
    const start = pos;
    let value = 0;
    while (pos < len && pattern.charCodeAt(pos) >= 0x30 && pattern.charCodeAt(pos) <= 0x39) {
      value = value * 10 + (pattern.charCodeAt(pos++) - 0x30);
      if (value > MAX_REGEX_REPEAT) throw new Error();
    }
    if (pos === start) throw new Error();
    return value;
  };
  const readClassAtom = () => {
    const b = nextByte();
    if (b === 0x5b) throw new Error();
    if (b !== 0x5c) return { lit: b, esc: 0 };
    const esc = nextByte();
    if (SHORTHANDS.has(esc)) return { lit: null, esc };
    if (isAsciiAlnum(esc)) throw new Error();
    return { lit: esc, esc: 0 };
  };
  const parseClass = () => {
    const mask = new Uint32Array(4);
    const neg = peek() === 0x5e && (pos++, true);
    if (pos >= len || peek() === 0x5d) throw new Error();
    while (pos < len && peek() !== 0x5d) {
      const first = readClassAtom();
      if (pos + 1 < len && peek() === 0x2d && pattern.charCodeAt(pos + 1) !== 0x5d) {
        pos++;
        const second = readClassAtom();
        if (first.lit === null || second.lit === null || first.lit > second.lit) throw new Error();
        setRange(mask, first.lit, second.lit);
      } else if (first.lit !== null) setBit(mask, first.lit);
      else applyShorthand(mask, first.esc);
    }
    if (nextByte() !== 0x5d) throw new Error();
    if (neg) for (let c = 0x20; c <= 0x7e; c++) mask[c >>> 5] ^= 1 << (c & 31);
    return { kind: 'char', mask, nullable: false, cost: 1, quantifiable: true };
  };
  const parseAtom = depth => {
    const b = nextByte();
    if (b === 0x5e || b === 0x24) return { kind: 'anchor', code: b, nullable: true, cost: 1, quantifiable: false };
    if (b === 0x2a || b === 0x2b || b === 0x3f || b === 0x7b || b === 0x7d) throw new Error();
    if (b === 0x2e) {
      const mask = new Uint32Array(4);
      setRange(mask, 0x20, 0x7e);
      return { kind: 'char', mask, nullable: false, cost: 1, quantifiable: true };
    }
    if (b === 0x28) {
      if (depth >= MAX_REGEX_DEPTH) throw new Error();
      if (peek() === 0x3f) { pos++; if (nextByte() !== 0x3a) throw new Error(); }
      const inner = parseAlt(depth + 1, true);
      if (nextByte() !== 0x29) throw new Error();
      return { ...inner, quantifiable: true };
    }
    if (b === 0x5b) return parseClass();
    const mask = new Uint32Array(4);
    if (b === 0x5c) {
      const esc = nextByte();
      if (SHORTHANDS.has(esc)) applyShorthand(mask, esc);
      else if (isAsciiAlnum(esc)) throw new Error();
      else setBit(mask, esc);
    } else setBit(mask, b);
    return { kind: 'char', mask, nullable: false, cost: 1, quantifiable: true };
  };
  const parseQuantifier = atom => {
    const op = peek();
    if (op !== 0x2a && op !== 0x2b && op !== 0x3f && op !== 0x7b) return atom;
    if (!atom.quantifiable || atom.nullable) throw new Error();
    pos++;
    let min = 0, max = null;
    if (op === 0x2b) min = 1;
    else if (op === 0x3f) max = 1;
    else if (op === 0x7b) {
      min = parseBound();
      const sep = nextByte();
      if (sep === 0x7d) {
        if (min < 1) throw new Error();
        max = min;
      } else if (sep === 0x2c) {
        if (peek() === 0x7d) pos++;
        else {
          max = parseBound();
          if (nextByte() !== 0x7d || min > max || max < 1) throw new Error();
        }
      } else throw new Error();
    }
    if (peek() === 0x3f) pos++;
    const next = peek();
    if (next === 0x2a || next === 0x2b || next === 0x3f || next === 0x7b) throw new Error();
    const cost = max === null ? Math.max(1, min) * atom.cost + 1 : max * atom.cost + (max - min);
    if (cost >= MAX_REGEX_STATES) throw new Error();
    return { kind: 'rep', sub: atom, min, max, nullable: min === 0, cost };
  };
  const parseSeq = (depth, inGroup) => {
    const items = [];
    let nullable = true, cost = 0;
    while (pos < len) {
      const b = peek();
      if (b === 0x7c || (inGroup && b === 0x29)) break;
      if (!inGroup && b === 0x29) throw new Error();
      const item = parseQuantifier(parseAtom(depth));
      items.push(item);
      nullable = nullable && item.nullable;
      cost += item.cost;
      if (cost >= MAX_REGEX_STATES) throw new Error();
    }
    if (!items.length) throw new Error();
    return items.length === 1 ? items[0] : { kind: 'seq', items, nullable, cost };
  };
  const parseAlt = (depth, inGroup) => {
    const branches = [parseSeq(depth, inGroup)];
    let { nullable, cost } = branches[0];
    while (peek() === 0x7c) {
      pos++;
      const branch = parseSeq(depth, inGroup);
      branches.push(branch);
      nullable = nullable || branch.nullable;
      cost += 1 + branch.cost;
      if (cost >= MAX_REGEX_STATES) throw new Error();
    }
    return branches.length === 1 ? branches[0] : { kind: 'alt', branches, nullable, cost };
  };

  const root = parseAlt(0, false);
  if (pos !== len || root.cost + 1 > MAX_REGEX_STATES) throw new Error();
  const states = [];
  const push = st => (states.push(st) - 1);
  const compile = (node, next) => {
    if (node.kind === 'anchor') return push({ op: 'anchor', code: node.code, out: next });
    if (node.kind === 'char') return push({ op: 'char', mask: node.mask, out: next });
    if (node.kind === 'seq') {
      let cur = next;
      for (let i = node.items.length - 1; i >= 0; i--) cur = compile(node.items[i], cur);
      return cur;
    }
    if (node.kind === 'alt') {
      let cur = compile(node.branches[node.branches.length - 1], next);
      for (let i = node.branches.length - 2; i >= 0; i--) {
        const left = compile(node.branches[i], next);
        cur = push({ op: 'split', out1: left, out2: cur });
      }
      return cur;
    }
    if (node.max === null) {
      const loop = push({ op: 'split', out1: -1, out2: next });
      const body = compile(node.sub, loop);
      states[loop].out1 = body;
      if (node.min === 0) return loop;
      let cur = body;
      for (let i = 1; i < node.min; i++) cur = compile(node.sub, cur);
      return cur;
    }
    let cur = next;
    for (let i = 0; i < node.max - node.min; i++) {
      const body = compile(node.sub, cur);
      cur = push({ op: 'split', out1: body, out2: cur });
    }
    for (let i = 0; i < node.min; i++) cur = compile(node.sub, cur);
    return cur;
  };
  const start = compile(root, push({ op: 'match' }));

  return url => {
    if (typeof url !== 'string' || url.length > MAX_URL_MATCH_LEN) return false;
    const ulen = url.length;
    const seen = new Int32Array(states.length);
    let step = 1, matched = false, curr = [], next = [];
    const add = (list, idx, index) => {
      if (seen[idx] === step) return;
      seen[idx] = step;
      const st = states[idx];
      if (st.op === 'match') { matched = true; return; }
      if (st.op === 'split') { add(list, st.out1, index); if (!matched) add(list, st.out2, index); return; }
      if (st.op === 'anchor') {
        if ((st.code === 0x5e && index === 0) || (st.code === 0x24 && index === ulen)) add(list, st.out, index);
        return;
      }
      list.push(idx);
    };
    add(curr, start, 0);
    if (matched) return true;
    for (let i = 0; i < ulen; i++) {
      const code = url.charCodeAt(i);
      next.length = 0;
      step++;
      for (let j = 0; j < curr.length; j++) {
        const st = states[curr[j]];
        if (code >= 0x20 && code <= 0x7e && ((st.mask[code >>> 5] >>> (code & 31)) & 1) !== 0) {
          add(next, st.out, i + 1);
          if (matched) return true;
        }
      }
      add(next, start, i + 1);
      if (matched) return true;
      const tmp = curr; curr = next; next = tmp;
    }
    return false;
  };
}

function getCompiledRegex(pattern) {
  const cached = compiledCache.get(pattern);
  if (cached) return cached;
  try {
    const compiled = compileUrlRegex(pattern);
    if (compiledCache.size >= MAX_REGEX_CACHE) compiledCache.clear();
    compiledCache.set(pattern, compiled);
    return compiled;
  } catch { return null; }
}

const validHost = v => typeof v === 'string' && v.length <= 253 && v.includes('.') &&
  !net.isIP(v) && v.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s));

const validPath = value => typeof value === 'string' && /^\/(?!\/)[A-Za-z0-9/._~%-]*$/.test(value) &&
  !/%(?![0-9a-f]{2})/i.test(value) && new URL(value, 'https://example.test').pathname === value;

function parseRuleFile(filePath, validateRule, maxBytes = MAX_FILE_BYTES) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error();
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error();
  const list = 'version' in raw ? (() => {
    if (raw.version !== 2 || Object.keys(raw).sort().join(',') !== 'rules,version' ||
        !Array.isArray(raw.rules) || raw.rules.length > MAX_RULES) throw new Error();
    return raw.rules;
  })() : [raw];
  const active = [];
  for (const item of list) {
    // All four existing action validators share the same optional method and
    // bounded URL regex conditions without changing legacy action schemas.
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error();
    const { method, regex, ...action } = item;
    if (method != null && !METHODS.has(method)) throw new Error();
    if (regex != null) {
      const compiled = compileUrlRegex(regex);
      if (compiledCache.size >= MAX_REGEX_CACHE) compiledCache.clear();
      compiledCache.set(regex, compiled);
    }
    const omittedPath = regex != null && action.path === '';
    const parsed = validateRule(omittedPath ? { ...action, path: '/' } : action);
    if (parsed) {
      const out = omittedPath ? { ...parsed, path: '' } : parsed;
      active.push({
        ...out,
        ...(method == null ? {} : { method }),
        ...(regex == null ? {} : { regex }),
      });
    }
  }
  return active;
}

function validateHeaderRule(rule, pattern) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule) ||
      Object.keys(rule).sort().join(',') !== 'enabled,header,host,path,value' ||
      typeof rule.enabled !== 'boolean' || typeof rule.host !== 'string' ||
      typeof rule.path !== 'string' || typeof rule.header !== 'string' ||
      typeof rule.value !== 'string') throw new Error();
  if (!rule.enabled) return null;
  if (!validHost(rule.host) || !/^\/[^?#\s]*$/.test(rule.path) ||
      !pattern.test(rule.header) || rule.value.length > 1024) throw new Error();
  http.validateHeaderValue(rule.header, rule.value);
  return { ...rule, header: rule.header.toLowerCase() };
}

function validatePathRule(rule) {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule) ||
      Object.keys(rule).sort().join(',') !== 'enabled,host,path,target' ||
      typeof rule.enabled !== 'boolean' || typeof rule.host !== 'string' ||
      typeof rule.path !== 'string' || typeof rule.target !== 'string') throw new Error();
  if (!rule.enabled) return null;
  if (!validHost(rule.host) || !validPath(rule.path) || !validPath(rule.target)) throw new Error();
  return rule;
}

// A request gets one ordered match plan before any rewrite mutates its URL.
// Match only the already admitted HTTPS authority and the original URL path.
// This is a pure planning boundary, not a replacement for route admission.
function planRequest(allowedHosts, lists, rawTarget, authority, method) {
  const empty = { request: [], response: [], body: [], pathTarget: null };
  if (typeof authority !== 'string' || !authority.endsWith(':443') ||
      typeof rawTarget !== 'string') return empty;
  const host = authority.slice(0, -4);
  if (!validHost(host) || !allowedHosts.has(host)) return empty;
  let url;
  try {
    const origin = 'https://' + host;
    url = new URL(rawTarget, origin);
    if (url.origin !== origin || url.username || url.password || url.hash) return empty;
  } catch { return empty; }
  const query = rawTarget.indexOf('?');
  const rawQuery = query < 0 ? '' : rawTarget.slice(query);
  const originalUrl = 'https://' + host + url.pathname + rawQuery;
  const matches = rule => {
    if (rule.host !== host) return false;
    if (rule.path !== '' && rule.path !== url.pathname) return false;
    if (rule.path === '' && rule.regex == null) return false;
    if (rule.method != null && rule.method !== method) return false;
    if (rule.regex != null) {
      const matcher = getCompiledRegex(rule.regex);
      if (!matcher || !matcher(originalUrl)) return false;
    }
    return true;
  };
  const pathRule = lists.path.find(matches);
  // Preserve the original raw query bytes, including an empty query.
  const pathTarget = pathRule
    ? (rawTarget.startsWith('/') ? '' : url.origin) + pathRule.target + rawQuery
    : null;
  return {
    request: lists.request.filter(matches),
    response: lists.response.filter(matches),
    body: lists.body.filter(matches),
    pathTarget,
  };
}

function createRewriteEngine({ dataDir, hosts, strip }) {
  const allowedHosts = new Set(hosts);
  const files = {
    response: path.join(dataDir, 'response-header-rule.json'),
    request: path.join(dataDir, 'request-header-rule.json'),
    path: path.join(dataDir, 'url-path-rule.json'),
    body: path.join(dataDir, 'response-body-rule.json'),
  };
  let responseRules = [];
  let requestRules = [];
  let pathRules = [];
  let bodyRules = [];
  let rewriteHits = 0;
  let requestRewriteHits = 0;
  let pathHits = 0;
  let bodyHits = 0;

  function watch(filePath, label, validator, assign, maxBytes = MAX_FILE_BYTES) {
    const reload = () => {
      assign([]);
      try {
        assign(parseRuleFile(filePath, validator, maxBytes));
      } catch (error) {
        if (error?.code !== 'ENOENT') console.error(`Invalid local ${label} rule; rewrite disabled`);
      }
    };
    reload();
    fs.watchFile(filePath, { interval: 500, persistent: false }, reload);
  }

  watch(files.response, 'response header', r => validateHeaderRule(r, /^x-[a-z0-9-]{1,100}$/i), v => { responseRules = v; });
  watch(files.request, 'request header', r => validateHeaderRule(r, /^x-custom-[a-z0-9-]{1,91}$/i), v => { requestRules = v; });
  watch(files.path, 'URL path', validatePathRule, v => { pathRules = v; });
  watch(files.body, 'response body', r => validateBodyRule(r, validHost), v => { bodyRules = v; }, MAX_BODY_RULE_FILE_BYTES);

  function plan(req, authority) {
    return planRequest(allowedHosts, {
      request: requestRules, response: responseRules, body: bodyRules, path: pathRules,
    }, req.url, authority, req.method);
  }

  function applyRequestRules(req, matched, entry) {
    if (!matched.length) return;
    // Execute in top-to-bottom list order: distinct headers accumulate while
    // later rules with the same case-insensitive name override earlier ones.
    for (const rule of matched) {
      strip(req, rule.header);
      req.headers[rule.header] = rule.value;
      if (Array.isArray(req.rawHeaders)) req.rawHeaders.push(rule.header, rule.value);
    }
    entry.requestRule = true;
    requestRewriteHits = Math.min(requestRewriteHits + 1, 0xfffffffe);
  }

  function applyResponseRules(res, matched, entry) {
    if (!matched.length) return;
    const writeHead = res.writeHead;
    res.writeHead = function(status, reason, fields) {
      entry.responseRule = true;
      rewriteHits = Math.min(rewriteHits + 1, 0xfffffffe);
      const headers = typeof reason === 'string' ? fields : (reason ?? fields);
      if (Array.isArray(headers)) {
        let pairs = headers.slice();
        for (const rule of matched) {
          const next = [];
          for (let i = 0; i + 1 < pairs.length; i += 2) {
            if (String(pairs[i]).toLowerCase() !== rule.header) next.push(pairs[i], pairs[i + 1]);
          }
          next.push(rule.header, rule.value);
          pairs = next;
        }
        return typeof reason === 'string' ? writeHead.call(this, status, reason, pairs) : writeHead.call(this, status, pairs);
      }
      const updated = { ...headers };
      for (const rule of matched) {
        for (const name of Object.keys(updated)) {
          if (name.toLowerCase() === rule.header) delete updated[name];
        }
        updated[rule.header] = rule.value;
      }
      return typeof reason === 'string' ? writeHead.call(this, status, reason, updated) : writeHead.call(this, status, updated);
    };
  }

  function applyPathRules(req, target, entry) {
    if (target === null) return;
    req.url = target;
    entry.pathRule = true;
    pathHits = Math.min(pathHits + 1, 0xfffffffe);
  }

  function applyBodyRules(req, res, matched, entry) {
    installBodyRewrite(req, res, matched, () => {
      entry.bodyRule = true;
      bodyHits = Math.min(bodyHits + 1, 0xfffffffe);
    });
  }

  return {
    plan,
    applyRequestRules,
    applyResponseRules,
    applyPathRules,
    applyBodyRules,
    counts: () => ({ rewriteHits, requestRewriteHits, pathHits, bodyHits }),
  };
}

module.exports = { createRewriteEngine, validHost, planRequest, parseRuleFile, compileUrlRegex };
