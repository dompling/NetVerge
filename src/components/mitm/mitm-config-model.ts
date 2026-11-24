import type {
  MitmConfigView_Serialize,
  MitmSettings_Serialize,
} from '@/services/bindings'

export interface MitmConfigDraft {
  revision: string
  enable: boolean
  hostnameText: string
  policy: string | null
}

export type MitmConfigError =
  | 'invalidHost'
  | 'duplicateHost'
  | 'tooManyHosts'
  | 'requiresHost'
  | 'requiresPolicy'
  | 'missingPolicy'

export function createMitmConfigDraft(view: MitmConfigView_Serialize | undefined): MitmConfigDraft | null {
  if (!view?.available || !view.saved || !view.active || !view.revision) return null
  return {
    revision: view.revision,
    enable: view.saved.enable,
    hostnameText: view.saved.hostname.join('\n'),
    policy: view.saved.policy,
  }
}

export function configCandidate(draft: MitmConfigDraft): MitmSettings_Serialize {
  return {
    enable: draft.enable,
    hostname: draft.hostnameText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
    policy: draft.policy,
  }
}

export function sameMitmSelection(a: MitmSettings_Serialize, b: MitmSettings_Serialize) {
  return a.enable === b.enable && a.policy === b.policy &&
    a.hostname.length === b.hostname.length &&
    a.hostname.every((host, index) => host === b.hostname[index])
}

export function hasMitmConfigConflict(draft: MitmConfigDraft | null, view: MitmConfigView_Serialize | undefined) {
  return Boolean(draft && (!view?.available || draft.revision !== view.revision))
}

function validHostname(host: string) {
  return host.length <= 253 && host.includes('.') &&
    !/^\d+(?:\.\d+){3}$/.test(host) &&
    host.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
}

export function validateMitmCandidate(candidate: MitmSettings_Serialize, policies: readonly string[]): MitmConfigError | null {
  if (candidate.hostname.length > 64) return 'tooManyHosts'
  if (candidate.hostname.some((host) => !validHostname(host))) return 'invalidHost'
  if (new Set(candidate.hostname).size !== candidate.hostname.length) return 'duplicateHost'
  if (!candidate.enable) return null
  if (!candidate.hostname.length) return 'requiresHost'
  if (!candidate.policy) return 'requiresPolicy'
  if (!policies.includes(candidate.policy)) return 'missingPolicy'
  return null
}
