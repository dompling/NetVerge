import { AddRounded, DeleteOutlineRounded, EditOutlined } from '@mui/icons-material'
import {
  Alert, Box, Button, Card, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, Stack, TextField, Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { getMitmConfig, saveMitmConfig } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

import { validateMitmCandidate } from './mitm-config-model'

export const MITM_CONFIG_KEY = 'netverge-mitm-local-config'

export function MitmConfigEditor({ live, busy, onChanged }: { live: boolean; busy: boolean; onChanged: () => void }) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState<{ original: string | null; value: string; revision: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const { data, error, isValidating, mutate } = useSWR(
    MITM_CONFIG_KEY, getMitmConfig,
    { revalidateOnMount: true, revalidateOnFocus: true, shouldRetryOnError: false },
  )
  const hosts = data?.saved?.hostname ?? []
  const editable = Boolean(data?.available && data.revision && data.saved && !busy && !saving && !error && !isValidating)
  const persist = useLockFn(async (hostname: string[], expected: string) => {
    if (!editable || !data || data.revision !== expected) {
      showNotice.warning('settings.mitm.config.conflict')
      return
    }
    // Keep the current enable state; host changes never choose an egress.
    const candidate = { enable: live && Boolean(data.active?.enable), hostname, policy: null }
    const validation = validateMitmCandidate(candidate, [])
    if (validation) {
      showNotice.warning(`settings.mitm.config.${validation}`)
      return
    }
    setSaving(true)
    try {
      const saved = await saveMitmConfig(expected, candidate)
      if (!saved) return
      await mutate(saved, { revalidate: false })
      setEditing(null)
      onChanged()
    } catch (err) {
      showNotice.error(err)
      await mutate()
    } finally {
      setSaving(false)
    }
  })
  const openEditor = (original: string | null) => {
    if (!editable || !data?.revision) return
    setEditing({ original, value: original ?? '', revision: data.revision })
  }
  const confirm = () => {
    if (!editing) return
    const value = editing.value.trim()
    if (!value) return
    const next = editing.original === null
      ? [...hosts, value]
      : hosts.map((host) => host === editing.original ? value : host)
    void persist(next, editing.revision)
  }
  return (
    <Stack spacing={1}>
      <Card variant="outlined" sx={{ minHeight: 360 }}>
        <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between', bgcolor: 'action.hover', px: 2, py: 0.5 }}>
          <Typography variant="subtitle2">{t('settings.mitm.config.hostname')} · {hosts.length}/64</Typography>
          <IconButton size="small" aria-label={t('settings.mitm.addHost')} disabled={!editable || hosts.length >= 64} onClick={() => openEditor(null)}><AddRounded /></IconButton>
        </Stack>
        {error && <Alert severity="error">{t('settings.mitm.config.readError')}</Alert>}
        {data && !data.available && <Alert severity="info">{t('settings.mitm.config.notAvailable')}</Alert>}
        {isValidating && <Typography variant="caption" sx={{ px: 2 }}>{t('settings.mitm.config.loading')}</Typography>}
        {data?.available && hosts.length === 0 && <Typography color="text.secondary" variant="body2" sx={{ p: 2 }}>{t('settings.mitm.config.noHosts')}</Typography>}
        {hosts.map(host => (
          <Stack key={host} direction="row" sx={{ alignItems: 'center', gap: 1, px: 2, py: 0.5, borderBottom: 1, borderColor: 'divider' }}>
            <Box sx={{ flex: 1, minWidth: 0, overflowWrap: 'anywhere' }}>{host}</Box>
            <IconButton size="small" aria-label={t('settings.mitm.editHost') + ' ' + host} disabled={!editable} onClick={() => openEditor(host)}><EditOutlined fontSize="small" /></IconButton>
            <IconButton size="small" aria-label={t('settings.mitm.removeHost') + ' ' + host} disabled={!editable} onClick={() => { if (data?.revision) void persist(hosts.filter(value => value !== host), data.revision) }}><DeleteOutlineRounded fontSize="small" /></IconButton>
          </Stack>
        ))}
      </Card>
      <Typography variant="caption" color="text.secondary">{t('settings.mitm.config.hostnameHint')}</Typography>
      <Dialog open={editing !== null} onClose={() => { if (!saving) setEditing(null) }} fullWidth maxWidth="xs">
        <DialogTitle>{t(editing?.original ? 'settings.mitm.editHost' : 'settings.mitm.addHost')}</DialogTitle>
        <DialogContent>
          <TextField autoFocus fullWidth size="small" sx={{ mt: 1 }} label={t('settings.mitm.config.hostname')} value={editing?.value ?? ''} disabled={saving} onChange={event => setEditing(previous => previous ? { ...previous, value: event.target.value } : null)} onKeyDown={event => { if (event.key === 'Enter') confirm() }} />
        </DialogContent>
        <DialogActions>
          <Button disabled={saving} onClick={() => setEditing(null)}>{t('shared.actions.close')}</Button>
          <Button loading={saving} disabled={!editable || !editing?.value.trim() || editing.revision !== data?.revision} onClick={confirm}>{t('settings.mitm.confirmHost')}</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}
