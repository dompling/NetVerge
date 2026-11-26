import { Alert, Button, Card, Stack, TextField, Typography } from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { commands } from '@/services/bindings'

export function RecentRequests() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const needle = query.trim().toLowerCase()
  const { data, error } = useSWR(open ? 'mitm-recent-requests' : null, commands.getMitmRecentRequests, { refreshInterval: 2000 })
  const rows = data?.filter(entry => {
    if (!`${entry.host}${entry.path}`.toLowerCase().includes(needle)) return false
    switch (filter) {
      case 'request': return entry.requestRule
      case 'response': return entry.responseRule
      case 'path': return entry.pathRule
      case 'none': return !entry.requestRule && !entry.responseRule && !entry.pathRule
      default: return true
    }
  })
  return <Card variant="outlined" sx={{ p: 1 }}>
    <Button aria-expanded={open} onClick={() => setOpen(!open)}>{t('settings.mitm.recent.title')}</Button>
    {open && <Stack spacing={1} sx={{ p: 1 }}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
        <TextField size="small" type="search" fullWidth label={t('settings.mitm.recent.search')} value={query}
          onChange={event => setQuery(event.target.value)} />
        <TextField select size="small" label={t('settings.mitm.recent.matched')} value={filter}
          sx={{ minWidth: 170 }} slotProps={{ select: { native: true } }} onChange={event => setFilter(event.target.value)}>
          <option value="all">{t('settings.mitm.recent.all')}</option>
          <option value="request">{t('settings.mitm.rewrite.requestTitle')}</option>
          <option value="response">{t('settings.mitm.rewrite.title')}</option>
          <option value="path">{t('settings.mitm.rewrite.pathTitle')}</option>
          <option value="none">{t('settings.mitm.recent.none')}</option>
        </TextField>
      </Stack>
      {error && <Alert severity="error">{t('settings.mitm.error')}</Alert>}
      {data?.length === 0 && <Typography variant="body2">{t('settings.mitm.recent.empty')}</Typography>}
      {Boolean(data?.length) && rows?.length === 0 && <Typography variant="body2">{t('settings.mitm.recent.noMatches')}</Typography>}
      <Stack spacing={1} sx={{ maxHeight: 320, overflow: 'auto' }}>
      {rows?.map((entry, index) => {
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
      </Stack>
    </Stack>}
  </Card>
}
