import type { RecentRequest } from '@/services/bindings'

import { validHostname } from './mitm-config-model'

const METHODS = /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/
const REDACTED = '[redacted]'
const MEDIA_TYPES = new Set([
  'application/json', 'application/octet-stream', 'application/xml',
  'application/x-www-form-urlencoded', 'text/plain', 'text/html',
  'text/css', 'text/xml', 'image/png', 'image/jpeg', 'image/webp',
])

// The inspector retains an original pathname, not a complete wire URL.
// Reject ambiguous, normalized, or truncated targets instead of guessing.
export function exportRequestUrl(entry: RecentRequest): string | null {
  if (!validHostname(entry.host) || !METHODS.test(entry.method) ||
      !entry.path.startsWith('/') || entry.path.startsWith('//') ||
      /[?#\\\x00-\x20\x7f-\uffff]/.test(entry.path) ||
      /%(?![a-f0-9]{2})/i.test(entry.path) || entry.path.length > 256) return null
  try {
    const url = new URL('https://' + entry.host + entry.path)
    return url.hostname === entry.host && url.pathname === entry.path &&
      !url.search && !url.hash && !url.username && !url.password ? url.href : null
  } catch {
    return null
  }
}

function headerMetadata(headers: [string, string][]) {
  return headers.flatMap(([rawName, value]) => {
    const name = rawName.toLowerCase()
    if (!/^[a-z0-9-]{1,64}$/.test(name) ||
        /^(?:x-whistle-|proxy-|authorization$|cookie$|set-cookie$|www-authenticate$)/.test(name)) return []
    // Do not export arbitrary header values: an innocently named custom
    // header or Location may contain secrets. Only fixed known MIME values
    // and numeric lengths are allowed through.
    const type = value.toLowerCase().trim()
    const mime = type.replace(/;\s*charset=utf-8$/, '')
    const safeType = MEDIA_TYPES.has(mime) && (type === mime || type.endsWith('charset=utf-8'))
    return [{ name, value: name === 'content-type' && safeType ? type :
      name === 'content-length' && /^\d{1,10}$/.test(value) ? value : REDACTED }]
  })
}

function requireUrl(entry: RecentRequest): string {
  const url = exportRequestUrl(entry)
  if (!url) throw new Error('Request target cannot be exported safely')
  return url
}

export function sanitizedHar(entry: RecentRequest): string {
  const url = requireUrl(entry)
  const completed = Date.parse(entry.completedAt)
  const duration = entry.durationMs
  if (!Number.isFinite(completed) || !Number.isSafeInteger(duration) || duration < 0 ||
      !Number.isInteger(entry.status) || entry.status < 100 || entry.status > 599) {
    throw new Error('Invalid request timing or status')
  }
  const responseHeaders = headerMetadata(entry.responseHeaders)
  const mimeType = responseHeaders.find(header => header.name === 'content-type' && header.value !== REDACTED)?.value ?? ''
  return JSON.stringify({
    log: {
      version: '1.2',
      creator: { name: 'NetVerge', version: '1' },
      comment: 'Sanitized inspector metadata only. Original pathname may contain private identifiers. Query, cookies, bodies and arbitrary header values omitted. Headers reflect the observed processed request/response.',
      entries: [{
        startedDateTime: new Date(completed - duration).toISOString(),
        time: duration,
        request: {
          method: entry.method, url, httpVersion: '', cookies: [],
          headers: headerMetadata(entry.requestHeaders), queryString: [],
          headersSize: -1, bodySize: -1,
        },
        response: {
          status: entry.status, statusText: '', httpVersion: '', cookies: [],
          headers: responseHeaders, content: { size: 0, mimeType, comment: 'Body omitted; decoded size unknown.' },
          redirectURL: '', headersSize: -1, bodySize: -1,
        },
        cache: {},
        timings: { send: 0, wait: duration, receive: 0, comment: 'Aggregate observed duration, not measured phase timings.' },
        _netverge: { durationMs: duration, localResponse: Boolean(entry.localRule), bodyOmitted: true },
      }],
    },
  }, null, 2)
}

// Generate a command template only; no execution, original credentials,
// arbitrary headers, query, cookies, response preview or request body.
export function sanitizedCurl(entry: RecentRequest, windows: boolean): string {
  const url = requireUrl(entry)
  const quote = (value: string) => "'" + value.replaceAll("'", windows ? "''" : "'\\''") + "'"
  return (windows ? 'curl.exe' : 'curl') + ' --disable --globoff --path-as-is --request ' +
    quote(entry.method) + ' --url ' + quote(url)
}
