import { describe, expect, it } from 'vitest'

import type { RecentRequest } from '@/services/bindings'
import { exportRequestUrl, sanitizedCurl, sanitizedHar } from './recent-request-export'

const row: RecentRequest = {
  id: 1, method: 'GET', host: 'api.example.test', path: '/demo',
  requestRule: false, responseRule: false, bodyRule: false, pathRule: false,
  status: 201, completedAt: '2026-11-27T00:00:01.000Z', durationMs: 50,
  localRule: true,
  requestHeaders: [
    ['authorization', 'Bearer raw-secret'], ['cookie', 'cookie-secret'],
    ['x-custom-debug', 'arbitrary-secret'], ['x-whistle-tunnel-data', 'internal-secret'],
    ['x-observed-path', '/demo?token=query-secret'],
  ],
  responseHeaders: [
    ['set-cookie', 'response-secret'], ['location', 'https://elsewhere.test/?token=location-secret'],
    ['content-type', 'application/json; charset=utf-8'], ['content-length', '42'],
  ],
  responsePreview: '{"token":"preview-secret"}',
}

describe('sanitized inspector export', () => {
  it('keeps only observed metadata and never includes raw header values or body previews', () => {
    const text = sanitizedHar(row)
    expect(text).not.toContain('secret')
    const har = JSON.parse(text).log
    expect(har.version).toBe('1.2')
    const [entry] = har.entries
    expect(entry.request.url).toBe('https://api.example.test/demo')
    expect(entry.request.cookies).toEqual([])
    expect(entry.request.queryString).toEqual([])
    expect(entry.request.postData).toBeUndefined()
    expect(entry.request.headers).toContainEqual({ name: 'x-custom-debug', value: '[redacted]' })
    expect(entry.response.status).toBe(201)
    expect(entry.response.content.text).toBeUndefined()
    expect(entry.response.headers).toContainEqual({ name: 'content-type', value: 'application/json; charset=utf-8' })
    expect(entry.startedDateTime).toBe('2026-11-27T00:00:00.950Z')
    expect(entry.time).toBe(50)
    expect(entry._netverge.localResponse).toBe(true)
  })

  it('redacts even a deceptive MIME header or length', () => {
    const text = sanitizedHar({ ...row, responseHeaders: [
      ['content-type', 'application/json; token=secret'],
      ['content-length', '12secret'],
    ] })
    expect(text).not.toContain('secret')
    expect(JSON.parse(text).log.entries[0].response.headers.every((h: { value: string }) => h.value === '[redacted]')).toBe(true)
  })

  it('generates shell-specific quoted templates without request or response data', () => {
    expect(sanitizedCurl(row, true)).toBe("curl.exe --disable --globoff --path-as-is --request 'GET' --url 'https://api.example.test/demo'")
    const quoted = { ...row, path: "/a'$(whoami)" }
    expect(sanitizedCurl(quoted, false)).toContain("'\\''")
    expect(sanitizedCurl(quoted, true)).toContain("a''$(whoami)")
    expect(sanitizedCurl(row, false)).not.toContain('secret')
  })

  it('rejects unsafe or truncated original targets instead of inventing a URL', () => {
    for (const bad of [
      { ...row, host: 'api.example.test@evil.test' },
      { ...row, host: 'api.example.test:8443' },
      { ...row, path: '//evil.test/demo' },
      { ...row, path: '/demo?token=secret' },
      { ...row, path: '/demo#secret' },
      { ...row, path: '/a/../demo' },
      { ...row, path: '/demo…' },
      { ...row, path: '/demo%xx' },
      { ...row, method: 'GET; whoami' },
    ]) {
      expect(exportRequestUrl(bad)).toBeNull()
      expect(() => sanitizedCurl(bad, true)).toThrow()
      expect(() => sanitizedHar(bad)).toThrow()
    }
  })
})
