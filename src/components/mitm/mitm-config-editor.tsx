import {
  Alert, Button, Card, Chip, Divider, FormControlLabel, MenuItem, Stack,
  Switch, TextField, Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import type { MitmSettings_Serialize } from '@/services/bindings'
import { getMitmConfig, saveMitmConfig } from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

import {
  configCandidate,
  createMitmConfigDraft,
  hasMitmConfigConflict,
  sameMitmSelection,
  validateMitmCandidate,
  type MitmConfigDraft,
} from './mitm-config-model'

export const MITM_CONFIG_KEY = 'netverge-mitm-local-config'

function SelectionSummary({ title, selection }: { title: string; selection: MitmSettings_Serialize }) {
  const { t } = useTranslation()
  return (
    <Stack spacing={0.5} sx={{ minWidth: 0, flex: 1 }}>
      <Typography variant="subtitle2">{title}</Typography>
      <Chip size="small" sx={{ alignSelf: 'flex-start' }} label={t(selection.enable ? 'settings.mitm.config.enabled' : 'settings.mitm.config.disabled')} />
      <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>
        {t('settings.mitm.config.policy')}: {selection.policy ?? t('settings.mitm.config.none')}
      </Typography>
      <Typography variant="caption" sx={{ overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}>
        {selection.hostname.length ? selection.hostname.join('\n') : t('settings.mitm.config.noHosts')}
      </Typography>
    </Stack>
  )
}

export function MitmConfigEditor() {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<MitmConfigDraft | null>(null)
  const [saving, setSaving] = useState(false)
  const { data, error, isValidating, mutate } = useSWR(
    MITM_CONFIG_KEY, getMitmConfig,
    { revalidateOnMount: true, revalidateOnFocus: true, shouldRetryOnError: false },
  )
  const current = draft ?? createMitmConfigDraft(data)
  const candidate = current ? configCandidate(current) : null
  const conflict = hasMitmConfigConflict(draft, data)
  const dirty = Boolean(candidate && data?.saved && !sameMitmSelection(candidate, data.saved))
  const validation = candidate ? validateMitmCandidate(candidate, data?.policies ?? []) : null
  const editable = Boolean(current && data?.available && !saving && !error && !conflict)
  const canSave = editable && dirty && !isValidating && !validation

  const patch = (change: Partial<Omit<MitmConfigDraft, 'revision'>>) => {
    if (!editable) return
    setDraft((previous) => {
      const initial = previous ?? createMitmConfigDraft(data)
      return initial ? { ...initial, ...change } : null
    })
  }

  const save = useLockFn(async () => {
    if (!canSave || !current || !candidate) return
    setSaving(true)
    try {
      // The backend validates the same revision and requires native confirmation.
      // A canceled dialog returns null; leave the user's unsaved draft intact.
      const saved = await saveMitmConfig(current.revision, candidate)
      if (!saved) return
      await mutate(saved, { revalidate: false })
      setDraft(null)
      showNotice.success('settings.mitm.config.savedNotice')
    } catch (err) {
      showNotice.error(err)
      await mutate()
    } finally {
      setSaving(false)
    }
  })

  const discard = () => {
    if (saving) return
    setDraft(null)
    void mutate()
  }

  return (
    <Card variant="outlined" sx={{ p: 2 }}>
      <Stack spacing={2}>
        <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between', gap: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{t('settings.mitm.config.title')}</Typography>
          {data?.restartRequired && <Chip size="small" color="warning" label={t('settings.mitm.config.pending')} />}
        </Stack>
        {isValidating && <Typography variant="caption" role="status">{t('settings.mitm.config.loading')}</Typography>}
        {error && <Alert severity="error">{t('settings.mitm.config.readError')}</Alert>}
        {data && !data.available && <Alert severity="info">{t('settings.mitm.config.notAvailable')}</Alert>}
        {data?.available && current && (
          <>
            {data.restartRequired && <Alert severity="warning">{t('settings.mitm.config.pendingDescription')}</Alert>}
            {data.active && data.saved && (
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                <SelectionSummary title={t('settings.mitm.config.active')} selection={data.active} />
                <SelectionSummary title={t('settings.mitm.config.saved')} selection={data.saved} />
              </Stack>
            )}
            <Typography variant="caption" color="text.secondary">{t('settings.mitm.config.currentNotProof')}</Typography>
            <Divider />
            <FormControlLabel
              control={<Switch checked={current.enable} disabled={!editable} onChange={(_, checked) => patch({ enable: checked })} />}
              label={t('settings.mitm.config.enable')}
            />
            <TextField
              fullWidth multiline minRows={4} maxRows={10}
              label={t('settings.mitm.config.hostname')}
              placeholder={t('settings.mitm.config.hostnamePlaceholder')}
              value={current.hostnameText}
              disabled={!editable}
              onChange={(event) => patch({ hostnameText: event.target.value })}
              helperText={(candidate?.hostname.length ?? 0) + ' / 64 · ' + t('settings.mitm.config.hostnameHint')}
              sx={{ '& textarea': { fontFamily: 'monospace' } }}
            />
            <TextField
              select fullWidth size="small"
              label={t('settings.mitm.config.policy')}
              disabled={!editable}
              value={current.policy ?? ''}
              onChange={(event) => patch({ policy: event.target.value || null })}
              helperText={t('settings.mitm.config.policyHint')}
            >
              <MenuItem value="">{t('settings.mitm.config.selectPolicy')}</MenuItem>
              {current.policy && !data.policies.includes(current.policy) && (
                <MenuItem value={current.policy} disabled>{current.policy} ({t('settings.mitm.config.missingPolicy')})</MenuItem>
              )}
              {data.policies.map((policy) => <MenuItem key={policy} value={policy}>{policy}</MenuItem>)}
            </TextField>
            {conflict ? <Alert severity="warning">{t('settings.mitm.config.conflict')}</Alert> : validation ? (
              <Alert severity="warning">{t('settings.mitm.config.' + validation as 'settings.mitm.config.invalidHost' | 'settings.mitm.config.duplicateHost' | 'settings.mitm.config.tooManyHosts' | 'settings.mitm.config.requiresHost' | 'settings.mitm.config.requiresPolicy' | 'settings.mitm.config.missingPolicy')}</Alert>
            ) : dirty && <Typography variant="caption" color="text.secondary">{t('settings.mitm.config.dirty')}</Typography>}
            <Typography variant="caption" color="text.secondary">{t('settings.mitm.config.restartNote')}</Typography>
          </>
        )}
        <Stack direction="row" sx={{ flexWrap: 'wrap', justifyContent: 'flex-end', gap: 1 }}>
          <Button size="small" disabled={saving || isValidating} onClick={() => void mutate()}>{t('settings.mitm.refresh')}</Button>
          <Button size="small" variant="outlined" disabled={saving || !draft} onClick={discard}>{t('settings.mitm.config.discard')}</Button>
          <Button size="small" variant="contained" loading={saving} disabled={!canSave} onClick={() => void save()}>{t('settings.mitm.config.save')}</Button>
        </Stack>
      </Stack>
    </Card>
  )
}
