import { nanoid } from 'nanoid'

import type {
  ResponseBodyRule,
  ResponseHeaderRule,
  UrlPathRule,
} from '@/services/bindings'
import {
  getMitmRewriteDiagnostics,
  getRequestHeaderHits,
  getRequestHeaderRules,
  getResponseBodyHits,
  getResponseBodyRules,
  getResponseHeaderHits,
  getResponseHeaderRules,
  getUrlPathHits,
  getUrlPathRules,
  saveRequestHeaderRules,
  saveResponseBodyRules,
  saveResponseHeaderRules,
  saveUrlPathRules,
} from '@/services/cmds'

export const MAX_RULES = 16

export type Direction = 'request' | 'response' | 'path' | 'body'

export type DraftRule = ResponseHeaderRule & { uid: string }

export const HTTP_METHODS = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
] as const

export const DIRECTION_TABS = [
  ['response', 'settings.mitm.rewrite.title'],
  ['request', 'settings.mitm.rewrite.requestTitle'],
  ['path', 'settings.mitm.rewrite.pathTitle'],
  ['body', 'settings.mitm.rewrite.bodyTitle'],
] as const

export const blankRule = (): DraftRule => ({
  uid: nanoid(),
  enabled: false,
  host: '',
  path: '/',
  header: '',
  value: '',
})

export const stripUid = ({
  uid: _uid,
  ...rule
}: DraftRule): ResponseHeaderRule => rule

// Tauri command failures are structured objects, not necessarily Error instances.
export function errorDetail(error: unknown): string {
  if (
    typeof error === 'object' &&
    error !== null &&
    'detail' in error &&
    typeof error.detail === 'string'
  ) {
    return error.detail
  }
  return error instanceof Error ? error.message : String(error)
}

export const isBlank = (rule: ResponseHeaderRule) =>
  !rule.enabled &&
  !rule.host &&
  !rule.method &&
  !rule.regex &&
  (!rule.path || rule.path === '/') &&
  !rule.header &&
  !rule.value

export const isComplete = (rule: ResponseHeaderRule, direction: Direction) =>
  Boolean(
    rule.host &&
      (rule.path || rule.regex) &&
      (direction === 'path' ? rule.value : rule.header),
  )

export const PHASE_BY_DIRECTION: Record<Direction, string> = {
  response: 'response-header',
  request: 'request-header',
  path: 'url-path',
  body: 'response-body',
}

export const readRewriteDiagnostics = getMitmRewriteDiagnostics

// Adapt path and body forms to the shared autosave editor. Only native schemas cross IPC.
const toPath = (rules: ResponseHeaderRule[]): UrlPathRule[] =>
  rules.map((rule) => ({
    id: rule.id,
    source: rule.source,
    enabled: rule.enabled,
    host: rule.host,
    path: rule.path,
    method: rule.method,
    regex: rule.regex,
    target: rule.value,
  }))

const toBody = (rules: ResponseHeaderRule[]): ResponseBodyRule[] =>
  rules.map((rule) => ({
    id: rule.id,
    source: rule.source,
    enabled: rule.enabled,
    host: rule.host,
    path: rule.path,
    method: rule.method,
    regex: rule.regex,
    search: rule.header,
    value: rule.value,
  }))

export const editors = {
  body: {
    read: async (): Promise<ResponseHeaderRule[]> =>
      (await getResponseBodyRules()).map((rule) => ({
        id: rule.id,
        source: rule.source,
        enabled: rule.enabled,
        host: rule.host,
        path: rule.path,
        method: rule.method,
        regex: rule.regex,
        header: rule.search,
        value: rule.value,
      })),
    save: (expected: ResponseHeaderRule[], rules: ResponseHeaderRule[]) =>
      saveResponseBodyRules(toBody(expected), toBody(rules)),
    hits: getResponseBodyHits,
  },
  path: {
    read: async (): Promise<ResponseHeaderRule[]> =>
      (await getUrlPathRules()).map((rule) => ({
        id: rule.id,
        source: rule.source,
        enabled: rule.enabled,
        host: rule.host,
        path: rule.path,
        method: rule.method,
        regex: rule.regex,
        value: rule.target,
        header: '',
      })),
    save: (expected: ResponseHeaderRule[], rules: ResponseHeaderRule[]) =>
      saveUrlPathRules(toPath(expected), toPath(rules)),
    hits: getUrlPathHits,
  },
  request: {
    read: getRequestHeaderRules,
    save: saveRequestHeaderRules,
    hits: getRequestHeaderHits,
  },
  response: {
    read: getResponseHeaderRules,
    save: saveResponseHeaderRules,
    hits: getResponseHeaderHits,
  },
}
