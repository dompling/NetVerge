import { Alert, Button, Card, FormControlLabel, Stack, Switch, ToggleButton, ToggleButtonGroup, TextField, Typography } from '@mui/material'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import { commands, type ResponseHeaderRule, type UrlPathRule } from '@/services/bindings'

const blank: ResponseHeaderRule = { enabled: false, host: '', path: '/', header: '', value: '' }

// Tauri command failures are structured objects, not necessarily Error instances.
function errorDetail(error: unknown): string {
  if (typeof error === 'object' && error !== null && 'detail' in error && typeof error.detail === 'string') return error.detail
  return error instanceof Error ? error.message : String(error)
}

type Direction = 'request' | 'response' | 'path'

// Adapt the path-only form to the shared autosave editor. Only the native
// path schema crosses IPC; header rules retain their existing format.
const toPath = (rule: ResponseHeaderRule | null): UrlPathRule | null => rule && ({
  enabled: rule.enabled, host: rule.host, path: rule.path, target: rule.value,
})
const editors = {
  path: {
    read: async () => {
      const rule = await commands.getUrlPathRule()
      return rule && { enabled: rule.enabled, host: rule.host, path: rule.path, value: rule.target, header: '' }
    },
    save: (expected: ResponseHeaderRule | null, rule: ResponseHeaderRule | null) => commands.saveUrlPathRule(toPath(expected), toPath(rule)),
    hits: commands.getUrlPathHits,
  },
  request: { read: commands.getRequestHeaderRule, save: commands.saveRequestHeaderRule, hits: commands.getRequestHeaderHits },
  response: { read: commands.getResponseHeaderRule, save: commands.saveResponseHeaderRule, hits: commands.getResponseHeaderHits },
}

export function HeaderRuleEditor() {
  const { t } = useTranslation()
  const [direction, setDirection] = useState<Direction>('response')
  return <Stack spacing={1}>
    <ToggleButtonGroup size="small" exclusive value={direction}
      onChange={(_, next: Direction | null) => { if (next) setDirection(next) }}>
      <ToggleButton value="response">{t('settings.mitm.rewrite.title')}</ToggleButton>
      <ToggleButton value="request">{t('settings.mitm.rewrite.requestTitle')}</ToggleButton>
      <ToggleButton value="path">{t('settings.mitm.rewrite.pathTitle')}</ToggleButton>
    </ToggleButtonGroup>
    {(['response', 'request', 'path'] as const).map(kind => <div key={kind} hidden={direction !== kind}>
      <Editor direction={kind} visible={direction === kind} />
    </div>)}
  </Stack>
}

function Editor({ direction, visible }: { direction: Direction; visible: boolean }) {
  const { t } = useTranslation()
  const { data, error, mutate } = useSWR('mitm-' + direction + '-rule', editors[direction].read, {
    revalidateOnMount: true, revalidateOnFocus: false, revalidateOnReconnect: false,
  })
  if (error) return <Alert severity="error" action={<Button onClick={() => void mutate()}>{t('shared.actions.retry')}</Button>}>{errorDetail(error)}</Alert>
  if (data === undefined) return null
  return <RuleForm direction={direction} visible={visible} initial={data} changed={rule => { void mutate(rule, { revalidate: false }) }} />
}

function RuleForm({ initial, changed, direction, visible }: { direction: Direction; visible: boolean; initial: ResponseHeaderRule | null; changed: (rule: ResponseHeaderRule | null) => void }) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState(initial)
  // Keep the input snapshot synchronous across keyboard/blur events. A blur
  // must not save an older render's draft after a rapid field edit.
  const draftRef = useRef(initial)
  const updateDraft = (next: ResponseHeaderRule | null) => {
    draftRef.current = next
    setDraft(next)
  }
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const saved = useRef(initial)
  const queue = useRef(Promise.resolve())
  const latest = useRef(0)
  const { data: hits } = useSWR(visible ? 'mitm-' + direction + '-hits' : null, editors[direction].hits, { refreshInterval: 3000 })
  // Publish the label and count as one accessible status, not separate text nodes.
  const hitStatus = hits == null ? null : `${t('settings.mitm.rewrite.hits')} · ${hits}`
  const persist = (next: ResponseHeaderRule | null) => {
    const version = ++latest.current
    setPending(true)
    queue.current = queue.current.then(async () => {
      if (version !== latest.current) return
      try {
        if (JSON.stringify(next) !== JSON.stringify(saved.current)) {
          await editors[direction].save(saved.current, next)
          saved.current = next
          changed(next)
        }
        if (version === latest.current) setError('')
      } catch (err) {
        if (version === latest.current) setError(errorDetail(err))
      } finally {
        if (version === latest.current) setPending(false)
      }
    })
  }
  const commit = () => {
    const next = draftRef.current
    if (!next?.host || (direction === 'path' ? !next.value : !next.header) || !next.path) return
    persist(next)
  }
  return <Card variant="outlined" sx={{ p: 2 }}>
    <Stack spacing={1.5}>
      {!draft ? <Button size="small" sx={{ alignSelf: 'flex-start' }} onClick={() => updateDraft({ ...blank })}>{t('settings.mitm.rewrite.add')}</Button> : <>
        <Typography variant="caption">{t('settings.mitm.rewrite.hint')}</Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1}>
          {(['host', 'path', 'header', 'value'] as const).filter(field => direction !== 'path' || field !== 'header').map(field =>
            <TextField key={field} fullWidth size="small" label={t(direction === 'path' && field === 'value' ? 'settings.mitm.rewrite.targetPath' : field === 'header' && direction === 'request' ? 'settings.mitm.rewrite.requestHeader' : `settings.mitm.rewrite.${field}`)}
              value={draft[field]} onChange={event => {
                if (draftRef.current) updateDraft({ ...draftRef.current, [field]: event.target.value })
              }}
              onBlur={commit} onKeyDown={event => { if (event.key === 'Enter') event.currentTarget.querySelector('input')?.blur() }} />)}
        </Stack>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
          <FormControlLabel label={t('settings.mitm.rewrite.enable')} control={<Switch checked={draft.enabled}
            disabled={!draft.host || !draft.path || (direction === 'path' ? !draft.value : !draft.header)}
            onChange={(_, enabled) => {
              if (draftRef.current) { updateDraft({ ...draftRef.current, enabled }); commit() }
            }} />} />
          {hitStatus !== null && <Typography variant="caption" role="status" aria-label={hitStatus}>{hitStatus}</Typography>}
          <Button size="small" onClick={() => { updateDraft(null); persist(null) }}>{t('shared.actions.delete')}</Button>
        </Stack>
      </>}
      {pending && <Typography variant="caption">{t('settings.mitm.rewrite.saving')}</Typography>}
      {error && <Alert severity="error" action={<Button onClick={() => persist(draftRef.current)}>{t('shared.actions.retry')}</Button>}>{error}</Alert>}
    </Stack>
  </Card>
}
