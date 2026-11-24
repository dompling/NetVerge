import type { MitmStatus_Serialize, MitmTrustStatus_Serialize } from '@/services/bindings'

export interface MitmSnapshot {
  status: MitmStatus_Serialize
  trust: MitmTrustStatus_Serialize | null
}

export function canManageMitmCertificate(snapshot: MitmSnapshot | undefined) {
  const fingerprint = snapshot?.status.caFingerprint
  return Boolean(
    fingerprint &&
      /^[a-f0-9]{64}$/.test(fingerprint) &&
      snapshot?.status.developmentRequested &&
      snapshot?.trust?.fingerprint === fingerprint,
  )
}

export function hasMitmIdentityMismatch(snapshot: MitmSnapshot | undefined) {
  return Boolean(
    snapshot?.status.caFingerprint &&
      snapshot.status.caFingerprint !== snapshot.trust?.fingerprint,
  )
}
