import { Alert, Button, Card, Stack, Typography } from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { commands } from '@/services/bindings'

export function RecentRequests() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const { data, error } = useSWR(open ? 'mitm-recent-requests' : null, commands.getMitmRecentRequests, { refreshInterval: 2000 })
  return <Card variant="outlined" sx={{ p: 1 }}>
    <Button aria-expanded={open} onClick={() => setOpen(!open)}>{t('settings.mitm.recent.title')}</Button>
    {open && <Stack spacing={1} sx={{ p: 1, maxHeight: 320, overflow: 'auto' }}>
      {error && <Alert severity="error">{t('settings.mitm.error')}</Alert>}
      {data?.length === 0 && <Typography variant="body2">{t('settings.mitm.recent.empty')}</Typography>}
      {data?.map((entry, index) => {
        const rules = [
          entry.requestRule && t('settings.mitm.rewrite.requestTitle'),
          entry.responseRule && t('settings.mitm.rewrite.title'),
          entry.pathRule && t('settings.mitm.rewrite.pathTitle'),
        ].filter(Boolean)
        const line = `${entry.method} ${entry.host}${entry.path} · ${entry.status}`
        const matches = rules.join(', ') || t('settings.mitm.recent.none')
        return <Stack key={index} role="group" aria-label={line + ' · ' + matches}>
          <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{line}</Typography>
          <Typography variant="caption" color="text.secondary">{t('settings.mitm.recent.matched')} · {matches}</Typography>
        </Stack>
      })}
    </Stack>}
  </Card>
}
