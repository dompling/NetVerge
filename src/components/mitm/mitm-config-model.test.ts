import { describe, expect, it } from 'vitest'

import type { MitmConfigView_Serialize } from '@/services/bindings'

import {
  configCandidate,
  createMitmConfigDraft,
  hasMitmConfigConflict,
  sameMitmSelection,
  validateMitmCandidate,
} from './mitm-config-model'

const view: MitmConfigView_Serialize = {
  available: true,
  active: { enable: false, hostname: [], policy: null },
  saved: { enable: true, hostname: ['api.example.test'], policy: 'DIRECT' },
  revision: 'first',
  restartRequired: true,
  policies: ['DIRECT', 'Work'],
}

describe('restart-scoped MITM configuration', () => {
  it('edits saved rather than active configuration, without changing the original', () => {
    const draft = createMitmConfigDraft(view)!
    expect(draft.enable).toBe(true)
    expect(draft.hostnameText).toBe('api.example.test')
    const changed = configCandidate({ ...draft, hostnameText: ' api.example.test \r\n\nother.test ' })
    expect(changed.hostname).toEqual(['api.example.test', 'other.test'])
    expect(view.active?.enable).toBe(false)
    expect(view.saved?.hostname).toEqual(['api.example.test'])
    expect(sameMitmSelection(configCandidate(draft), view.saved!)).toBe(true)
    expect(sameMitmSelection(changed, view.saved!)).toBe(false)
  })

  it('blocks stale revisions and unavailable configurations', () => {
    const draft = createMitmConfigDraft(view)!
    expect(hasMitmConfigConflict(draft, view)).toBe(false)
    expect(hasMitmConfigConflict(draft, { ...view, revision: 'new' })).toBe(true)
    expect(hasMitmConfigConflict(draft, undefined)).toBe(true)
    expect(createMitmConfigDraft({ ...view, available: false })).toBeNull()
    expect(createMitmConfigDraft({ ...view, revision: null })).toBeNull()
  })

  it('checks exact hostnames, duplicates and limits', () => {
    const selected = view.saved!
    for (const hostname of ['*.example.test', 'https://a.test', '127.0.0.1', 'A.test', 'a.test:443', '-a.test']) {
      expect(validateMitmCandidate({ ...selected, hostname: [hostname] }, view.policies)).toBe('invalidHost')
    }
    expect(validateMitmCandidate({ ...selected, hostname: ['a.test', 'a.test'] }, view.policies)).toBe('duplicateHost')
    expect(validateMitmCandidate({ ...selected, hostname: Array.from({ length: 65 }, (_, i) => 'a' + i + '.test') }, view.policies)).toBe('tooManyHosts')
  })

  it('requires policy and domains when enabled, permits explicitly disabling', () => {
    const selected = view.saved!
    expect(validateMitmCandidate(selected, view.policies)).toBeNull()
    expect(validateMitmCandidate({ ...selected, hostname: [] }, view.policies)).toBe('requiresHost')
    expect(validateMitmCandidate({ ...selected, policy: null }, view.policies)).toBe('requiresPolicy')
    expect(validateMitmCandidate({ ...selected, policy: 'removed' }, view.policies)).toBe('missingPolicy')
    expect(validateMitmCandidate({ enable: false, hostname: [], policy: null }, view.policies)).toBeNull()
    expect(validateMitmCandidate({ ...selected, enable: false, policy: 'removed' }, view.policies)).toBeNull()
  })
})
