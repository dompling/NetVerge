import { Alert, Box, Button, Chip, Divider, Stack, Typography } from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState, type Ref } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { BaseDialog, type DialogRef } from '@/components/base'
import {
  exportMitmPublicCa,
  getMitmStatus,
  getMitmTrustStatus,
  openMitmCertificateManager,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

import { useSettingDialog } from '../settings-search-context'
import { canManageMitmCertificate, hasMitmIdentityMismatch, type MitmSnapshot } from './mitm-view-model'

async function readSnapshot(): Promise<MitmSnapshot> {
  const status = await getMitmStatus()
  const trust = status.caFingerprint ? await getMitmTrustStatus() : null
  return { status, trust }
}

export function MitmViewer({ ref }: { ref?: Ref<DialogRef> }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const { data, error, isValidating, mutate } = useSWR(
    open ? 'netverge-mitm-certificate-status' : null,
    readSnapshot,
    { revalidateOnMount: true, revalidateOnFocus: true, shouldRetryOnError: false },
  )
  const close = () => {
    if (!busy) setOpen(false)
  }
  useSettingDialog(ref, 'mitm-viewer', open, () => ({
    open: () => setOpen(true),
    close,
  }))
  const action = useLockFn(async (kind: 'export' | 'manage') => {
    setBusy(true)
    try {
      const fresh = await mutate()
      if (!canManageMitmCertificate(fresh)) return
      const fingerprint = fresh?.status.caFingerprint
      if (!fingerprint) return
      if (kind === 'export') {
        if (await exportMitmPublicCa()) showNotice.success(t('settings.mitm.exported'))
      } else {
        await openMitmCertificateManager(fingerprint)
      }
      await mutate()
    } catch (error) {
      showNotice.error(error)
    } finally {
      setBusy(false)
    }
  })

  const status = data?.status
  const trust = data?.trust
  const disabled = busy || isValidating || Boolean(error) || !canManageMitmCertificate(data)
  const mismatch = hasMitmIdentityMismatch(data)
  return (
    <BaseDialog
      title={t('settings.mitm.title')}
      open={open}
      contentSx={{ width: { xs: 300, sm: 460 }, maxWidth: '100%' }}
      disableFooter
      onClose={close}
    >
      <Stack spacing={1.5} data-settings-dialog="mitm-viewer">
        <Alert severity="info">{t('settings.mitm.experimental')}</Alert>
        {error && <Alert severity="error">{t('settings.mitm.error')}</Alert>}
        {isValidating && <Typography variant="caption" role="status">{t('settings.mitm.loading')}</Typography>}
        {status && !error && (
          <>
            {!status.developmentRequested && <Alert severity="info">{t('settings.mitm.inactive')}</Alert>}
            <Stack direction="row" alignItems="center" justifyContent="space-between" gap={1}>
              <Typography variant="body2">{t('settings.mitm.health')}</Typography>
              <Chip size="small" label={t(`settings.mitm.states.${status.state}`)} />
            </Stack>
            <Typography variant="body2">{t('settings.mitm.generation')}: {status.coreGenerationCurrent ? t('settings.mitm.yes') : t('settings.mitm.no')}</Typography>
            <Typography variant="body2">{t('settings.mitm.recovery')}: {status.recoveryAttempts} / {status.maxRecoveryAttempts}</Typography>
            <Typography variant="caption" color="text.secondary">{t('settings.mitm.localOnly')}</Typography>
            <Divider />
            <Typography variant="subtitle2">{t('settings.mitm.certificate')}</Typography>
            {status.caFingerprint ? (
              <Box>
                <Typography variant="caption" color="text.secondary">{t('settings.mitm.fingerprint')}</Typography>
                <Typography component="div" variant="body2" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere', userSelect: 'text' }}>{status.caFingerprint}</Typography>
              </Box>
            ) : <Typography variant="body2" color="text.secondary">{t('settings.mitm.noCa')}</Typography>}
            {mismatch && <Alert severity="warning">{t('settings.mitm.identityChanged')}</Alert>}
            {trust && !mismatch && (
              <Stack spacing={0.5}>
                <Typography variant="body2">{t('settings.mitm.userStore')}: {t(`settings.mitm.stores.${trust.userStore}`)}</Typography>
                <Typography variant="body2">{t('settings.mitm.systemStore')}: {t(`settings.mitm.stores.${trust.systemStore}`)}</Typography>
                <Typography variant="body2">{t('settings.mitm.trust')}: {t(`settings.mitm.assessments.${trust.assessment}`)}</Typography>
              </Stack>
            )}
            <Typography variant="caption" color="text.secondary">{t('settings.mitm.manual')}</Typography>
          </>
        )}
        <Stack direction="row" flexWrap="wrap" gap={1}>
          <Button size="small" variant="outlined" disabled={busy || isValidating} onClick={() => void mutate()}>{t('settings.mitm.refresh')}</Button>
          <Button size="small" variant="outlined" disabled={disabled} onClick={() => void action('export')}>{t('settings.mitm.export')}</Button>
          <Button size="small" variant="outlined" disabled={disabled} onClick={() => void action('manage')}>{t('settings.mitm.manage')}</Button>
          <Button size="small" disabled={busy} onClick={close}>{t('settings.mitm.close')}</Button>
        </Stack>
      </Stack>
    </BaseDialog>
  )
}
