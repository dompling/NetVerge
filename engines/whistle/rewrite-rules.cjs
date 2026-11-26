'use strict';

const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { installBodyRewrite, validateBodyRule } = require('./body-rewrite.cjs');
const { compileUrlRegex, cacheCompiledRegex, getCompiledRegex } = require('./url-regex.cjs');

const MAX_FILE_BYTES = 8192;
const MAX_BODY_RULE_FILE_BYTES = 16384;
const MAX_MODULE_BUNDLE_BYTES = 32768;
const MAX_RULES = 16;
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

const validHost = v => typeof v === 'string' && v.length <= 253 && v.includes('.') &&
  !net.isIP(v) && v.split('.').every(s => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(s));

const validPath = value => typeof value === 'string' && /^\/(?!\/)[A-Za-z0-9/._~%-]*$/.test(value) &&
  !/%(?![0-9a-f]{2})/i.test(value) && new URL(value, 'https://example.test').pathname === value;

const validRuleId = value => typeof value === 'string' && value.length >= 1 && value.length <= 64 &&
  /^[a-z0-9][a-z0-9._:-]*$/.test(value);

const validSource = value => typeof value === 'string' && value.length <= 96 && (
  value === 'local' ||
  (/^module:[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/.test(value) &&
    !value.slice(7).split('.').some(seg => seg.endsWith('-')))
);

function decodeRuleItems(filePath, maxBytes) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.size > maxBytes) throw new Error();
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error();
  if (!('version' in raw)) return { revision: 1, list: [raw] };
  const keys = Object.keys(raw).sort().join(',');
  if (raw.version !== 2 || (keys !== 'rules,version' && keys !== 'revision,rules,version') ||
      !Array.isArray(raw.rules) || raw.rules.length > MAX_RULES) throw new Error();
  if (raw.revision != null && (!Number.isInteger(raw.revision) || raw.revision < 1 || raw.revision > 0xffffffff)) throw new Error();
  return { revision: raw.revision ?? 1, list: raw.rules };
}

function normalizeRuleItems(list, revision, validateRule, phase, requireModule = false) {
  if (!Array.isArray(list) || list.length > MAX_RULES) throw new Error();
  const seenIds = new Set();
  const active = [];
  for (let index = 0; index < list.length; index++) {
    const item = list[index];
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error();
    const { id, source, method, regex, ...action } = item;
    if (requireModule && (id == null || typeof source !== 'string' || !source.startsWith('module:'))) {
      throw new Error();
    }
    if (id != null) {
      if (!validRuleId(id) || seenIds.has(id)) throw new Error();
      seenIds.add(id);
    }
    if (source != null && !validSource(source)) throw new Error();
    if (method != null && !METHODS.has(method)) throw new Error();
    if (regex != null) cacheCompiledRegex(regex);
    const omittedPath = regex != null && action.path === '';
    const parsed = validateRule(omittedPath ? { ...action, path: '/' } : action);
    if (!parsed) continue;
    const out = omittedPath ? { ...parsed, path: '' } : parsed;
    if (!phase) {
      active.push({
        ...out,
        ...(id == null ? {} : { id }),
        ...(source == null ? {} : { source }),
        ...(method == null ? {} : { method }),
        ...(regex == null ? {} : { regex }),
      });
      continue;
    }
    const resolvedSource = source ?? 'local';
    const resolvedId = id ?? `${resolvedSource}:${phase}:${index + 1}`;
    if (id == null) {
      if (seenIds.has(resolvedId)) throw new Error();
      seenIds.add(resolvedId);
    }
    active.push({
      ...out,
      id: resolvedId,
      source: resolvedSource,
      revision,
      phase,
      ...(method == null ? {} : { method }),
      ...(regex == null ? {} : { regex }),
    });
  }
  return active;
}

function parseRuleEntries(filePath, validateRule, maxBytes, phase) {
  const { revision, list } = decodeRuleItems(filePath, maxBytes);
  return { revision, rules: normalizeRuleItems(list, revision, validateRule, phase) };
}

function parseModuleBundle(filePath) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.size > MAX_MODULE_BUNDLE_BYTES) throw new Error();
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || raw.version !== 1 ||
      Object.keys(raw).sort().join(',') !== 'body,path,profileUid,request,response,revision,version' ||
      typeof raw.profileUid !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(raw.profileUid) ||
      !Number.isInteger(raw.revision) || raw.revision < 1 || raw.revision > 0xffffffff) {
    throw new Error();
  }
  return {
    revision: raw.revision,
    request: normalizeRuleItems(raw.request, raw.revision, r => validateHeaderRule(r, /^x-custom-[a-z0-9-]{1,91}$/i, true), 'request-header', true),
    response: normalizeRuleItems(raw.response, raw.revision, r => validateHeaderRule(r, /^x-[a-z0-9-]{1,100}$/i, true), 'response-header', true),
    path: normalizeRuleItems(raw.path, raw.revision, validatePathRule, 'url-path', true),
    body: normalizeRuleItems(raw.body, raw.revision, r => validateBodyRule(r, validHost), 'response-body', true),
  };
}

function parseRuleFile(filePath, validateRule, maxBytes = MAX_FILE_BYTES) {
  return parseRuleEntries(filePath, validateRule, maxBytes, null).rules;
}

function parseRuleSet(filePath, phase, validateRule, maxBytes = MAX_FILE_BYTES) {
  return parseRuleEntries(filePath, validateRule, maxBytes, phase);
}

function validateHeaderRule(rule, pattern, allowRemove = false) {
  const keys = Object.keys(rule).sort().join(',');
  if ((keys !== 'enabled,header,host,path,value' &&
      !(allowRemove && keys === 'enabled,header,host,path,remove,value' &&
        rule.remove === true && rule.value === '')) ||
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
// Match only the already admitted HTTPS authority and the original URL.
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
  const pathTarget = pathRule
    ? (rawTarget.startsWith('/') ? '' : url.origin) + pathRule.target + rawQuery
    : null;
  const planned = {
    request: lists.request.filter(matches),
    response: lists.response.filter(matches),
    body: lists.body.filter(matches),
    pathTarget,
  };
  if (pathRule?.id != null) {
    Object.defineProperty(planned, 'pathRuleId', { value: pathRule.id });
  }
  return planned;
}

function recordMatchedIds(entry, phaseDiag, ruleIds) {
  for (const id of ruleIds) {
    if (!id) continue;
    phaseDiag.ruleHits[id] = Math.min((phaseDiag.ruleHits[id] || 0) + 1, 0xfffffffe);
    if (Array.isArray(entry?.matchedRuleIds) && entry.matchedRuleIds.length < 16 &&
        !entry.matchedRuleIds.includes(id)) {
      entry.matchedRuleIds.push(id);
    }
  }
}

function createRewriteEngine({ dataDir, hosts, strip }) {
  const allowedHosts = new Set(hosts);
  const files = {
    response: path.join(dataDir, 'response-header-rule.json'),
    request: path.join(dataDir, 'request-header-rule.json'),
    path: path.join(dataDir, 'url-path-rule.json'),
    body: path.join(dataDir, 'response-body-rule.json'),
    modules: path.join(dataDir, 'compiled-module-rules.json'),
  };
  const emptyModules = () => ({ request: [], response: [], path: [], body: [] });
  let responseRules = [], requestRules = [], pathRules = [], bodyRules = [];
  let moduleBundle = emptyModules();
  let rewriteHits = 0, requestRewriteHits = 0, pathHits = 0, bodyHits = 0;
  const diag = {
    'response-header': { phase: 'response-header', revision: 0, activeRules: 0, error: null, ruleHits: {} },
    'request-header': { phase: 'request-header', revision: 0, activeRules: 0, error: null, ruleHits: {} },
    'url-path': { phase: 'url-path', revision: 0, activeRules: 0, error: null, ruleHits: {} },
    'response-body': { phase: 'response-body', revision: 0, activeRules: 0, error: null, ruleHits: {} },
  };

  function watch(filePath, phase, label, validator, assign, maxBytes = MAX_FILE_BYTES) {
    const reload = () => {
      assign([]);
      try {
        const { revision, rules } = parseRuleSet(filePath, phase, validator, maxBytes);
        const retainedHits = {};
        for (const rule of rules) retainedHits[rule.id] = diag[phase].ruleHits[rule.id] || 0;
        diag[phase] = { phase, revision, activeRules: rules.length, error: null, ruleHits: retainedHits };
        assign(rules);
      } catch (error) {
        if (error?.code === 'ENOENT') {
          diag[phase] = { phase, revision: 0, activeRules: 0, error: null, ruleHits: {} };
        } else {
          diag[phase] = { phase, revision: 0, activeRules: 0, error: 'INVALID_RULE_FILE', ruleHits: {} };
          console.error(`Invalid local ${label} rule; rewrite disabled`);
        }
      }
    };
    reload();
    fs.watchFile(filePath, { interval: 500, persistent: false }, reload);
  }

  watch(files.response, 'response-header', 'response header', r => validateHeaderRule(r, /^x-[a-z0-9-]{1,100}$/i), v => { responseRules = v; });
  watch(files.request, 'request-header', 'request header', r => validateHeaderRule(r, /^x-custom-[a-z0-9-]{1,91}$/i), v => { requestRules = v; });
  watch(files.path, 'url-path', 'URL path', validatePathRule, v => { pathRules = v; });
  watch(files.body, 'response-body', 'response body', r => validateBodyRule(r, validHost), v => { bodyRules = v; }, MAX_BODY_RULE_FILE_BYTES);

  const reloadModules = () => {
    moduleBundle = emptyModules();
    try {
      moduleBundle = parseModuleBundle(files.modules);
    } catch (error) {
      if (error?.code !== 'ENOENT') console.error('Invalid compiled module rules; module rewrites disabled');
    }
  };
  reloadModules();
  fs.watchFile(files.modules, { interval: 500, persistent: false }, reloadModules);

  // Local editor rules always retain precedence over approved module rules:
  // URL path takes the first match (local first), while headers/body take the last assignment (local last).
  function plan(req, authority) {
    return planRequest(allowedHosts, {
      request: [...moduleBundle.request, ...requestRules],
      response: [...moduleBundle.response, ...responseRules],
      body: [...moduleBundle.body, ...bodyRules],
      path: [...pathRules, ...moduleBundle.path],
    }, req.url, authority, req.method);
  }

  function applyRequestRules(req, matched, entry) {
    if (!matched.length) return;
    for (const rule of matched) {
      strip(req, rule.header);
      if (rule.remove) continue;
      req.headers[rule.header] = rule.value;
      if (Array.isArray(req.rawHeaders)) req.rawHeaders.push(rule.header, rule.value);
    }
    entry.requestRule = true;
    requestRewriteHits = Math.min(requestRewriteHits + 1, 0xfffffffe);
    recordMatchedIds(entry, diag['request-header'], matched.map(r => r.id));
  }

  function applyResponseRules(res, matched, entry) {
    if (!matched.length) return;
    const writeHead = res.writeHead;
    res.writeHead = function(status, reason, fields) {
      entry.responseRule = true;
      rewriteHits = Math.min(rewriteHits + 1, 0xfffffffe);
      recordMatchedIds(entry, diag['response-header'], matched.map(r => r.id));
      const headers = typeof reason === 'string' ? fields : (reason ?? fields);
      if (Array.isArray(headers)) {
        let pairs = headers.slice();
        for (const rule of matched) {
          const next = [];
          for (let i = 0; i + 1 < pairs.length; i += 2) {
            if (String(pairs[i]).toLowerCase() !== rule.header) next.push(pairs[i], pairs[i + 1]);
          }
          if (rule.remove) this.removeHeader(rule.header);
          else next.push(rule.header, rule.value);
          pairs = next;
        }
        return typeof reason === 'string' ? writeHead.call(this, status, reason, pairs) : writeHead.call(this, status, pairs);
      }
      const updated = { ...headers };
      for (const rule of matched) {
        for (const name of Object.keys(updated)) {
          if (name.toLowerCase() === rule.header) delete updated[name];
        }
        if (rule.remove) this.removeHeader(rule.header);
        else updated[rule.header] = rule.value;
      }
      return typeof reason === 'string' ? writeHead.call(this, status, reason, updated) : writeHead.call(this, status, updated);
    };
  }

  function applyPathRules(req, target, entry, ruleId) {
    if (target === null) return;
    req.url = target;
    entry.pathRule = true;
    pathHits = Math.min(pathHits + 1, 0xfffffffe);
    recordMatchedIds(entry, diag['url-path'], [ruleId]);
  }

  function applyBodyRules(req, res, matched, entry) {
    installBodyRewrite(req, res, matched, () => {
      entry.bodyRule = true;
      bodyHits = Math.min(bodyHits + 1, 0xfffffffe);
      recordMatchedIds(entry, diag['response-body'], matched.map(r => r.id));
    });
  }

  return {
    plan,
    applyRequestRules,
    applyResponseRules,
    applyPathRules,
    applyBodyRules,
    counts: () => ({ rewriteHits, requestRewriteHits, pathHits, bodyHits }),
    diagnostics: () => Object.values(diag).map(item => ({ ...item, ruleHits: { ...item.ruleHits } })),
    close: () => { for (const f of Object.values(files)) fs.unwatchFile(f); },
  };
}

module.exports = {
  createRewriteEngine,
  validHost,
  planRequest,
  parseRuleFile,
  parseRuleSet,
  compileUrlRegex,
};
