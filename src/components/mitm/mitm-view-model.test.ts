import { describe, expect, it } from 'vitest'

import {
  canManageMitmCertificate,
  hasMitmIdentityMismatch,
  type MitmSnapshot,
} from './mitm-view-model'

const fingerprint = 'a'.repeat(64)
const snapshot: MitmSnapshot = {
  status: {
    developmentRequested: true,
    state: 'local_link_healthy',
    coreGenerationCurrent: true,
    recoveryAttempts: 0,
    maxRecoveryAttempts: 3,
    caFingerprint: fingerprint,
  },
  trust: {
    fingerprint,
    userStore: 'absent',
    systemStore: 'absent',
    assessment: 'root_policy_rejected',
  },
}

describe('MITM certificate view', () => {
  it('allows manual management of an identified CA without claiming trust', () => {
    expect(canManageMitmCertificate(snapshot)).toBe(true)
    expect(hasMitmIdentityMismatch(snapshot)).toBe(false)
  })

  it('rejects missing, disabled, or changed certificate snapshots', () => {
    expect(canManageMitmCertificate(undefined)).toBe(false)
    expect(canManageMitmCertificate({ ...snapshot, trust: null })).toBe(false)
    expect(canManageMitmCertificate({
      ...snapshot,
      status: { ...snapshot.status, developmentRequested: false },
    })).toBe(false)
    const changed = {
      ...snapshot,
      trust: { ...snapshot.trust!, fingerprint: 'b'.repeat(64) },
    }
    expect(hasMitmIdentityMismatch(changed)).toBe(true)
    expect(canManageMitmCertificate(changed)).toBe(false)
    expect(canManageMitmCertificate({
      ...snapshot,
      status: { ...snapshot.status, caFingerprint: null },
    })).toBe(false)
  })
})
