import {
  Alert,
  Button,
  Card,
  Divider,
  FormControlLabel,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from '@mui/material'
import { nanoid } from 'nanoid'
import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR from 'swr'

import type { ResponseHeaderRule } from '@/services/bindings'

import {
  blankRule,
  DIRECTION_TABS,
  type Direction,
  type DraftRule,
  editors,
  errorDetail,
  HTTP_METHODS,
  isBlank,
  isComplete,
  MAX_RULES,
  PHASE_BY_DIRECTION,
  readRewriteDiagnostics,
  stripUid,
} from './rewrite-rule-model'

export function HeaderRuleEditor() {
  const { t } = useTranslation()
  const [direction, setDirection] = useState<Direction>('response')
  return (
    <Stack spacing={1}>
      <ToggleButtonGroup
        size="small"
        exclusive
        value={direction}
        onChange={(_, next: Direction | null) => {
          if (next) setDirection(next)
        }}
      >
        {DIRECTION_TABS.map(([value, key]) => (
          <ToggleButton key={value} value={value}>
            {t(key)}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
      {DIRECTION_TABS.map(([kind]) => (
        <div key={kind} hidden={direction !== kind}>
          <Editor direction={kind} visible={direction === kind} />
        </div>
      ))}
    </Stack>
  )
}

function Editor({
  direction,
  visible,
}: {
  direction: Direction
  visible: boolean
}) {
  const { t } = useTranslation()
  const { data, error, mutate } = useSWR(
    'mitm-' + direction + '-rules',
    editors[direction].read,
    {
      revalidateOnMount: true,
      revalidateOnFocus: false,
      revalidateOnReconnect: false,
    },
  )
  if (error) {
    return (
      <Alert
        severity="error"
        action={
          <Button onClick={() => void mutate()}>
            {t('shared.actions.retry')}
          </Button>
        }
      >
        {errorDetail(error)}
      </Alert>
    )
  }
  if (data === undefined) return null
  return (
    <RuleListForm
      direction={direction}
      visible={visible}
      initial={data}
      changed={(rules) => {
        void mutate(rules, { revalidate: false })
      }}
    />
  )
}

function RuleListForm({
  initial,
  changed,
  direction,
  visible,
}: {
  direction: Direction
  visible: boolean
  initial: ResponseHeaderRule[]
  changed: (rules: ResponseHeaderRule[]) => void
}) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<DraftRule[]>(() =>
    initial.map((rule) => ({ ...rule, uid: nanoid() })),
  )
  // Keep the input snapshot synchronous across keyboard/blur events. A blur
  // must not save an older render's draft after a rapid field edit.
  const draftRef = useRef<DraftRule[]>(draft)
  const updateDraft = (next: DraftRule[]) => {
    draftRef.current = next
    setDraft(next)
  }
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const saved = useRef<ResponseHeaderRule[]>(initial)
  const queue = useRef(Promise.resolve())
  const latest = useRef(0)
  const { data: hits } = useSWR(
    visible ? 'mitm-' + direction + '-hits' : null,
    editors[direction].hits,
    { refreshInterval: 3000 },
  )
  const { data: diagnostics } = useSWR(
    visible ? 'mitm-rewrite-diagnostics' : null,
    readRewriteDiagnostics,
    { refreshInterval: 3000 },
  )
  const phaseDiag = diagnostics?.find(
    (item) => item.phase === PHASE_BY_DIRECTION[direction],
  )
  // Publish the label and count as one accessible status, not separate text nodes.
  const hitStatus =
    hits == null ? null : `${t('settings.mitm.rewrite.hits')} · ${hits}`
  const persist = (next: ResponseHeaderRule[]) => {
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
  const commitRows = (rows: DraftRule[]) => {
    if (rows.some((rule) => !isBlank(rule) && !isComplete(rule, direction)))
      return
    persist(rows.filter((rule) => isComplete(rule, direction)).map(stripUid))
  }
  const commit = () => commitRows(draftRef.current)
  const move = (index: number, delta: -1 | 1) => {
    const target = index + delta
    if (target < 0 || target >= draftRef.current.length) return
    const next = draftRef.current.slice()
    const [picked] = next.splice(index, 1)
    next.splice(target, 0, picked)
    updateDraft(next)
    commitRows(next)
  }
  const remove = (uid: string) => {
    const next = draftRef.current.filter((item) => item.uid !== uid)
    updateDraft(next)
    if (next.some((rule) => !isBlank(rule) && !isComplete(rule, direction)))
      return
    persist(next.filter((rule) => isComplete(rule, direction)).map(stripUid))
  }
  return (
    <Card variant="outlined" sx={{ p: 2 }}>
      <Stack spacing={1.5}>
        {draft.length === 0 ? (
          <Button
            size="small"
            sx={{ alignSelf: 'flex-start' }}
            onClick={() => updateDraft([blankRule()])}
          >
            {t('settings.mitm.rewrite.add')}
          </Button>
        ) : (
          <>
            <Typography variant="caption">
              {t(
                direction === 'path'
                  ? 'settings.mitm.rewrite.pathHint'
                  : direction === 'body'
                    ? 'settings.mitm.rewrite.bodyHint'
                    : 'settings.mitm.rewrite.hint',
              )}
            </Typography>
            {draft.map((item, index) => {
              const suffix = index === 0 ? '' : ` #${index + 1}`
              const enableLabel = t('settings.mitm.rewrite.enable') + suffix
              return (
                <Stack key={item.uid} spacing={1}>
                  {index > 0 && <Divider />}
                  <Stack direction={{ xs: 'column', md: 'row' }} spacing={1}>
                    {(['host', 'path', 'header', 'value'] as const)
                      .filter(
                        (field) => direction !== 'path' || field !== 'header',
                      )
                      .map((field) => {
                        const baseLabel = t(
                          direction === 'path' && field === 'value'
                            ? 'settings.mitm.rewrite.targetPath'
                            : direction === 'body' && field === 'header'
                              ? 'settings.mitm.rewrite.bodySearch'
                              : direction === 'body' && field === 'value'
                                ? 'settings.mitm.rewrite.bodyValue'
                                : field === 'header' && direction === 'request'
                                  ? 'settings.mitm.rewrite.requestHeader'
                                  : `settings.mitm.rewrite.${field}`,
                        )
                        const fieldLabel = baseLabel + suffix
                        return (
                          <TextField
                            key={field}
                            fullWidth
                            size="small"
                            label={fieldLabel}
                            slotProps={{
                              htmlInput: { 'aria-label': fieldLabel },
                            }}
                            value={item[field]}
                            onChange={(event) => {
                              const value = event.target.value
                              updateDraft(
                                draftRef.current.map((row) =>
                                  row.uid === item.uid
                                    ? { ...row, [field]: value }
                                    : row,
                                ),
                              )
                            }}
                            onBlur={commit}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter') {
                                event.currentTarget
                                  .querySelector('input')
                                  ?.blur()
                              }
                            }}
                          />
                        )
                      })}
                  </Stack>
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                    <TextField
                      select
                      size="small"
                      label={`HTTP Method${suffix}`}
                      value={item.method ?? ''}
                      sx={{ minWidth: 140 }}
                      slotProps={{
                        select: { native: true },
                        htmlInput: { 'aria-label': `HTTP Method${suffix}` },
                      }}
                      onChange={(event) => {
                        const next = draftRef.current.map((row) =>
                          row.uid === item.uid
                            ? { ...row, method: event.target.value || undefined }
                            : row,
                        )
                        updateDraft(next)
                        commitRows(next)
                      }}
                    >
                      <option value="">*</option>
                      {HTTP_METHODS.map((method) => (
                        <option key={method} value={method}>
                          {method}
                        </option>
                      ))}
                    </TextField>
                    <TextField
                      fullWidth
                      size="small"
                      label={`URL Regex${suffix}`}
                      slotProps={{
                        htmlInput: { 'aria-label': `URL Regex${suffix}` },
                      }}
                      value={item.regex ?? ''}
                      onChange={(event) => {
                        const regex = event.target.value || undefined
                        updateDraft(
                          draftRef.current.map((row) =>
                            row.uid === item.uid ? { ...row, regex } : row,
                          ),
                        )
                      }}
                      onBlur={commit}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          event.currentTarget.querySelector('input')?.blur()
                        }
                      }}
                    />
                  </Stack>
                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{ alignItems: 'center', flexWrap: 'wrap' }}
                  >
                    <FormControlLabel
                      label={enableLabel}
                      control={
                        <Switch
                          checked={item.enabled}
                          disabled={!isComplete(item, direction)}
                          slotProps={{ input: { 'aria-label': enableLabel } }}
                          onChange={(_, enabled) => {
                            const next = draftRef.current.map((row) =>
                              row.uid === item.uid ? { ...row, enabled } : row,
                            )
                            updateDraft(next)
                            commitRows(next)
                          }}
                        />
                      }
                    />
                    {draft.length > 1 && (
                      <>
                        <Button
                          size="small"
                          disabled={index === 0}
                          aria-label={`${t('settings.mitm.rewrite.moveUp')} #${index + 1}`}
                          onClick={() => move(index, -1)}
                        >
                          {t('settings.mitm.rewrite.moveUp')}
                        </Button>
                        <Button
                          size="small"
                          disabled={index === draft.length - 1}
                          aria-label={`${t('settings.mitm.rewrite.moveDown')} #${index + 1}`}
                          onClick={() => move(index, 1)}
                        >
                          {t('settings.mitm.rewrite.moveDown')}
                        </Button>
                      </>
                    )}
                    <Button
                      size="small"
                      aria-label={t('shared.actions.delete') + suffix}
                      onClick={() => remove(item.uid)}
                    >
                      {t('shared.actions.delete')}
                    </Button>
                  </Stack>
                </Stack>
              )
            })}
            <Stack
              direction="row"
              spacing={1}
              sx={{ alignItems: 'center', flexWrap: 'wrap' }}
            >
              {draft.length < MAX_RULES && (
                <Button
                  size="small"
                  onClick={() =>
                    updateDraft([...draftRef.current, blankRule()])
                  }
                >
                  {t('settings.mitm.rewrite.addAnother')}
                </Button>
              )}
              {hitStatus !== null && (
                <Typography
                  variant="caption"
                  role="status"
                  aria-label={hitStatus}
                >
                  {hitStatus}
                </Typography>
              )}
            </Stack>
          </>
        )}
        {pending && (
          <Typography variant="caption">
            {t('settings.mitm.rewrite.saving')}
          </Typography>
        )}
        {phaseDiag?.error && (
          <Alert severity="warning">{phaseDiag.error}</Alert>
        )}
        {error && (
          <Alert
            severity="error"
            action={
              <Button
                onClick={() =>
                  persist(
                    draftRef.current
                      .filter((rule) => isComplete(rule, direction))
                      .map(stripUid),
                  )
                }
              >
                {t('shared.actions.retry')}
              </Button>
            }
          >
            {error}
          </Alert>
        )}
      </Stack>
    </Card>
  )
}
