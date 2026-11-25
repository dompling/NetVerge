import { RefreshRounded } from '@mui/icons-material'
import {
  Alert, Box, Button, Card, Chip, Divider, Grid, Stack, Switch, Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR, { useSWRConfig } from 'swr'

import { BasePage } from '@/components/base'
import { MitmConfigEditor, MITM_CONFIG_KEY } from '@/components/mitm/mitm-config-editor'
import {
  canManageMitmCertificate,
  hasMitmIdentityMismatch,
  type MitmSnapshot,
} from '@/components/mitm/mitm-view-model'
import {
  exportMitmPublicCa,
  getMitmStatus,
  getMitmConfig,
  saveMitmConfig,
  getMitmTrustStatus,
  openMitmCertificateManager,
  restartApp,
  setMitmServiceMode,
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
  const { mutate: revalidate } = useSWRConfig()
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

  const { data: config, mutate: mutateConfig, isValidating: configLoading, error: configError } = useSWR(MITM_CONFIG_KEY, getMitmConfig)
  const live = Boolean(data?.status.developmentRequested && config?.available)
  const toggle = useLockFn(async (enable: boolean) => {
    if (!live || !config?.saved || !config.revision) return
    setBusy(true)
    try {
      const saved = await saveMitmConfig(config.revision, { ...config.saved, enable, policy: null })
      if (saved) await mutateConfig(saved, { revalidate: false })
    } catch (err) {
      showNotice.error(err)
    } finally {
      await mutateConfig()
      await mutate()
      setBusy(false)
    }
  })
  const status = data?.status
  const servicePending = status?.serviceModeNextStart != null
    && status.serviceModeNextStart !== Boolean(status.serviceModeRequested)
  const toggleService = useLockFn(async (enabled: boolean) => {
    setBusy(true)
    try {
      await setMitmServiceMode(enabled)
      await mutate()
    } catch (err) {
      showNotice.error(err)
    } finally {
      setBusy(false)
    }
  })
  const trust = data?.trust
  const disabled = busy || isValidating || Boolean(error) || !canManageMitmCertificate(data)
  const mismatch = hasMitmIdentityMismatch(data)
  return (
    <BasePage
      title={<Stack direction="row" sx={{ alignItems: 'center', gap: 1 }}>
        <Typography component="span" variant="h6" sx={{ fontWeight: 700 }}>{t('settings.mitm.title')}</Typography>
        {!status?.serviceModeRequested && <Switch checked={live && Boolean(config?.active?.enable)} disabled={!live || busy || configLoading || Boolean(configError) || (!config?.active?.enable && !config?.saved?.hostname.length)} onChange={(_, checked) => void toggle(checked)} slotProps={{ input: { 'aria-label': t('settings.mitm.config.enable') } }} />}
      </Stack>}
      header={
        <Button size="small" variant="outlined" startIcon={<RefreshRounded />}
          disabled={busy || isValidating} onClick={() => { void mutate(); void revalidate(MITM_CONFIG_KEY) }}>
          {t('settings.mitm.refresh')}
        </Button>
      }
    >
      <Stack spacing={1.5}>
        <Typography variant="body2" color="text.secondary">{t('settings.mitm.summary')}</Typography>
        {status?.serviceModeNextStart != null && (
          <Card variant="outlined" sx={{ p: 2 }}>
            <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
              <Typography variant="subtitle2">{t('settings.mitm.serviceMode')}</Typography>
              <Switch
                checked={status.serviceModeNextStart}
                disabled={busy || isValidating}
                onChange={(_, checked) => void toggleService(checked)}
                slotProps={{ input: { 'aria-label': t('settings.mitm.serviceMode') } }}
              />
            </Stack>
            {servicePending && <Alert severity="info" action={
              <Button size="small" disabled={busy} onClick={() => { void restartApp().catch(showNotice.error) }}>
                {t('shared.actions.restart')}
              </Button>
            }>{t('settings.mitm.serviceRestartRequired')}</Alert>}
          </Card>
        )}
        {!live && !status?.serviceModeRequested && <Alert severity="info">{t('settings.mitm.routingPaused')}</Alert>}
        {status?.serviceFailure && <Alert severity="error">{status.serviceFailure}</Alert>}
        {error && <Alert severity="error">{t('settings.mitm.error')}</Alert>}
        {isValidating && <Typography variant="caption" role="status">{t('settings.mitm.loading')}</Typography>}
        <Grid container spacing={1.5} columns={12}>
          {status && !error && (
              <Grid size={{ xs: 12, md: 6 }}>
                <Card variant="outlined" sx={{ p: 2, height: '100%' }}>
                  <Stack spacing={1.5}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t('settings.mitm.certificate')}</Typography>
                    <Chip size="small" sx={{ alignSelf: 'flex-start' }} label={t(`settings.mitm.states.${status.state}`)} />
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
          )}
          {!status?.serviceModeRequested && <Grid size={{ xs: 12, md: 6 }}><MitmConfigEditor live={live} busy={busy} onChanged={() => { void mutate() }} /></Grid>}
        </Grid>
      </Stack>
    </BasePage>
  )
}

export default MitmPage
