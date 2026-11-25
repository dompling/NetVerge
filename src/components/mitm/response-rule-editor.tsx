import { Alert, Button, Card, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { commands, type ResponseHeaderRule } from '@/services/bindings'

const blank: ResponseHeaderRule = { enabled: false, host: '', path: '/', header: '', value: '' }

export function ResponseRuleEditor() {
  const { t } = useTranslation()
  const { data, error, mutate } = useSWR('mitm-response-rule', commands.getResponseHeaderRule, {
    revalidateOnMount: true, revalidateOnFocus: false, revalidateOnReconnect: false,
  })
  if (error) return <Alert severity="error" action={<Button onClick={() => void mutate()}>{t('shared.actions.retry')}</Button>}>{String(error)}</Alert>
  if (data === undefined) return null
  return <RuleForm initial={data} changed={rule => { void mutate(rule, { revalidate: false }) }} />
}

function RuleForm({ initial, changed }: { initial: ResponseHeaderRule | null; changed: (rule: ResponseHeaderRule | null) => void }) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState(initial)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const saved = useRef(initial)
  const queue = useRef(Promise.resolve())
  const latest = useRef(0)
  const { data: hits } = useSWR('mitm-response-hits', commands.getResponseHeaderHits, { refreshInterval: 3000 })
  // Publish the label and count as one accessible status, not separate text nodes.
  const hitStatus = hits == null ? null : `${t('settings.mitm.rewrite.hits')} · ${hits}`
  const persist = (next: ResponseHeaderRule | null) => {
    const version = ++latest.current
    setPending(true)
    queue.current = queue.current.then(async () => {
      if (version !== latest.current) return
      try {
        if (JSON.stringify(next) !== JSON.stringify(saved.current)) {
          await commands.saveResponseHeaderRule(saved.current, next)
          saved.current = next
          changed(next)
        }
        if (version === latest.current) setError('')
      } catch (err) {
        if (version === latest.current) setError(String(err))
      } finally {
        if (version === latest.current) setPending(false)
      }
    })
  }
  const commit = (next: ResponseHeaderRule) => {
    if (!next.host || !next.header || !next.path) return
    persist(next)
  }
  return <Card variant="outlined" sx={{ p: 2 }}>
    <Stack spacing={1.5}>
      <Typography variant="subtitle1">{t('settings.mitm.rewrite.title')}</Typography>
      {!draft ? <Button size="small" sx={{ alignSelf: 'flex-start' }} onClick={() => setDraft({ ...blank })}>{t('settings.mitm.rewrite.add')}</Button> : <>
        <Typography variant="caption">{t('settings.mitm.rewrite.hint')}</Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1}>
          {(['host', 'path', 'header', 'value'] as const).map(field =>
            <TextField key={field} fullWidth size="small" label={t(`settings.mitm.rewrite.${field}`)}
              value={draft[field]} onChange={event => setDraft({ ...draft, [field]: event.target.value })}
              onBlur={() => commit(draft)} onKeyDown={event => { if (event.key === 'Enter') event.currentTarget.querySelector('input')?.blur() }} />)}
        </Stack>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
          <FormControlLabel label={t('settings.mitm.rewrite.enable')} control={<Switch checked={draft.enabled}
            disabled={!draft.host || !draft.path || !draft.header}
            onChange={(_, enabled) => { const next = { ...draft, enabled }; setDraft(next); commit(next) }} />} />
          {hitStatus !== null && <Typography variant="caption" role="status" aria-label={hitStatus}>{hitStatus}</Typography>}
          <Button size="small" onClick={() => { setDraft(null); persist(null) }}>{t('shared.actions.delete')}</Button>
        </Stack>
      </>}
      {pending && <Typography variant="caption">{t('settings.mitm.rewrite.saving')}</Typography>}
      {error && <Alert severity="error" action={<Button onClick={() => persist(draft)}>{t('shared.actions.retry')}</Button>}>{error}</Alert>}
    </Stack>
  </Card>
}
