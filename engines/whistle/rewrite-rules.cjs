'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { installBodyRewrite, validateBodyRule } = require('./body-rewrite.cjs');

const MAX_FILE_BYTES = 8192;
const MAX_BODY_RULE_FILE_BYTES = 16384;
const MAX_RULES = 16;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

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
    // All four existing action validators share the same optional method
    // condition, without changing their legacy action schemas.
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error();
    const { method, ...action } = item;
    if (method != null && !METHODS.has(method)) throw new Error();
    const parsed = validateRule(action);
    if (parsed) active.push(method == null ? parsed : { ...parsed, method });
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
  const matches = rule => rule.host === host && rule.path === url.pathname &&
    (rule.method == null || rule.method === method);
  const pathRule = lists.path.find(matches);
  // Preserve the original raw query bytes, including an empty query.
  const query = rawTarget.indexOf('?');
  const pathTarget = pathRule
    ? (rawTarget.startsWith('/') ? '' : url.origin) + pathRule.target +
      (query < 0 ? '' : rawTarget.slice(query))
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

module.exports = { createRewriteEngine, validHost, planRequest, parseRuleFile };
