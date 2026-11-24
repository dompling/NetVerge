import { RefreshRounded } from '@mui/icons-material'
import {
  Alert, Box, Button, Card, Chip, Divider, Grid, Stack, Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { BasePage } from '@/components/base'
import {
  canManageMitmCertificate,
  hasMitmIdentityMismatch,
  type MitmSnapshot,
} from '@/components/mitm/mitm-view-model'
import {
  exportMitmPublicCa,
  getMitmStatus,
  getMitmTrustStatus,
  openMitmCertificateManager,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

async function readSnapshot(): Promise<MitmSnapshot> {
  const status = await getMitmStatus()
  const trust = status.caFingerprint ? await getMitmTrustStatus() : null
  return { status, trust }
}

const MitmPage = () => {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  // The route is mounted only while visiting MITM. Never poll native stores.
  const { data, error, isValidating, mutate } = useSWR(
    'netverge-mitm-certificate-status',
    readSnapshot,
    { revalidateOnMount: true, revalidateOnFocus: true, shouldRetryOnError: false },
  )
  const action = useLockFn(async (kind: 'export' | 'manage') => {
    const expected = data?.status.caFingerprint
    if (!expected || !canManageMitmCertificate(data)) return
    setBusy(true)
    try {
      // Fetch a fresh pair instead of relying on stale cached SWR data.
      const fresh = await readSnapshot()
      await mutate(fresh, { revalidate: false })
      if (!canManageMitmCertificate(fresh) || fresh.status.caFingerprint !== expected) {
        showNotice.warning('settings.mitm.identityChanged')
        return
      }
      if (kind === 'export') {
        if (await exportMitmPublicCa()) showNotice.success('settings.mitm.exported')
      } else {
        await openMitmCertificateManager(expected)
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
    <BasePage
      title={t('settings.mitm.title')}
      header={
        <Button size="small" variant="outlined" startIcon={<RefreshRounded />}
          disabled={busy || isValidating} onClick={() => void mutate()}>
          {t('settings.mitm.refresh')}
        </Button>
      }
    >
      <Stack spacing={1.5}>
        <Typography variant="body2" color="text.secondary">{t('settings.mitm.summary')}</Typography>
        <Alert severity="info">{t('settings.mitm.experimental')}</Alert>
        {error && <Alert severity="error">{t('settings.mitm.error')}</Alert>}
        {isValidating && <Typography variant="caption" role="status">{t('settings.mitm.loading')}</Typography>}
        {status && !error && (
          <>
            {!status.developmentRequested && <Alert severity="info">{t('settings.mitm.inactive')}</Alert>}
            <Grid container spacing={1.5} columns={12}>
              <Grid size={{ xs: 12, md: 5 }}>
                <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                  <Stack spacing={1.5}>
                    <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between', gap: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t('settings.mitm.health')}</Typography>
                      <Chip size="small" label={t(`settings.mitm.states.${status.state}`)} />
                    </Stack>
                    <Divider />
                    <Stack direction="row" sx={{ justifyContent: 'space-between', gap: 1 }}>
                      <Typography variant="body2" color="text.secondary">{t('settings.mitm.generation')}</Typography>
                      <Typography variant="body2">{status.coreGenerationCurrent ? t('settings.mitm.yes') : t('settings.mitm.no')}</Typography>
                    </Stack>
                    <Stack direction="row" sx={{ justifyContent: 'space-between', gap: 1 }}>
                      <Typography variant="body2" color="text.secondary">{t('settings.mitm.recovery')}</Typography>
                      <Typography variant="body2">{status.recoveryAttempts} / {status.maxRecoveryAttempts}</Typography>
                    </Stack>
                    <Typography variant="caption" color="text.secondary">{t('settings.mitm.localOnly')}</Typography>
                  </Stack>
                </Card>
              </Grid>
              <Grid size={{ xs: 12, md: 7 }}>
                <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                  <Stack spacing={1.5}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t('settings.mitm.certificate')}</Typography>
                    <Divider />
                    {status.caFingerprint ? (
                      <Box>
                        <Typography variant="caption" color="text.secondary">{t('settings.mitm.fingerprint')}</Typography>
                        <Typography component="div" variant="body2" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere', userSelect: 'text' }}>{status.caFingerprint}</Typography>
                      </Box>
                    ) : <Typography variant="body2" color="text.secondary">{t('settings.mitm.noCa')}</Typography>}
                    {mismatch && <Alert severity="warning">{t('settings.mitm.identityChanged')}</Alert>}
                    {trust && !mismatch && (
                      <Stack spacing={1}>
                        <Typography variant="body2">{t('settings.mitm.userStore')}: {t(`settings.mitm.stores.${trust.userStore}`)}</Typography>
                        <Typography variant="body2">{t('settings.mitm.systemStore')}: {t(`settings.mitm.stores.${trust.systemStore}`)}</Typography>
                        <Typography variant="body2">{t('settings.mitm.trust')}: {t(`settings.mitm.assessments.${trust.assessment}`)}</Typography>
                      </Stack>
                    )}
                    <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 1 }}>
                      <Button size="small" variant="outlined" disabled={disabled} onClick={() => void action('export')}>{t('settings.mitm.export')}</Button>
                      <Button size="small" variant="contained" disabled={disabled} onClick={() => void action('manage')}>{t('settings.mitm.manage')}</Button>
                    </Stack>
                    <Typography variant="caption" color="text.secondary">{t('settings.mitm.manual')}</Typography>
                  </Stack>
                </Card>
              </Grid>
            </Grid>
          </>
        )}
      </Stack>
    </BasePage>
  )
}

export default MitmPage
