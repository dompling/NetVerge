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

import type {
  ResponseBodyRule,
  ResponseHeaderRule,
  UrlPathRule,
} from '@/services/bindings'
import {
  getRequestHeaderHits,
  getRequestHeaderRules,
  getResponseBodyHits,
  getResponseBodyRules,
  getResponseHeaderHits,
  getResponseHeaderRules,
  getUrlPathHits,
  getUrlPathRules,
  saveRequestHeaderRules,
  saveResponseBodyRules,
  saveResponseHeaderRules,
  saveUrlPathRules,
} from '@/services/cmds'

const MAX_RULES = 16

type DraftRule = ResponseHeaderRule & { uid: string }

const blankRule = (): DraftRule => ({
  uid: nanoid(),
  enabled: false,
  host: '',
  path: '/',
  header: '',
  value: '',
})

const stripUid = ({ uid: _uid, ...rule }: DraftRule): ResponseHeaderRule => rule

// Tauri command failures are structured objects, not necessarily Error instances.
function errorDetail(error: unknown): string {
  if (
    typeof error === 'object' &&
    error !== null &&
    'detail' in error &&
    typeof error.detail === 'string'
  ) {
    return error.detail
  }
  return error instanceof Error ? error.message : String(error)
}

type Direction = 'request' | 'response' | 'path' | 'body'

const isBlank = (rule: ResponseHeaderRule) =>
  !rule.enabled &&
  !rule.host &&
  !rule.method &&
  rule.path === '/' &&
  !rule.header &&
  !rule.value

const isComplete = (rule: ResponseHeaderRule, direction: Direction) =>
  Boolean(
    rule.host && rule.path && (direction === 'path' ? rule.value : rule.header),
  )

// Adapt the path-only form to the shared autosave editor. Only the native
// path schema crosses IPC; header rules retain their existing format.
const toPath = (rules: ResponseHeaderRule[]): UrlPathRule[] =>
  rules.map((rule) => ({
    enabled: rule.enabled,
    host: rule.host,
    path: rule.path,
    method: rule.method,
    target: rule.value,
  }))

const toBody = (rules: ResponseHeaderRule[]): ResponseBodyRule[] =>
  rules.map((rule) => ({
    enabled: rule.enabled,
    host: rule.host,
    path: rule.path,
    method: rule.method,
    search: rule.header,
    value: rule.value,
  }))

const editors = {
  body: {
    read: async (): Promise<ResponseHeaderRule[]> => {
      const rules = await getResponseBodyRules()
      return rules.map((rule) => ({
        enabled: rule.enabled,
        host: rule.host,
        path: rule.path,
        method: rule.method,
        header: rule.search,
        value: rule.value,
      }))
    },
    save: (expected: ResponseHeaderRule[], rules: ResponseHeaderRule[]) =>
      saveResponseBodyRules(toBody(expected), toBody(rules)),
    hits: getResponseBodyHits,
  },
  path: {
    read: async (): Promise<ResponseHeaderRule[]> => {
      const rules = await getUrlPathRules()
      return rules.map((rule) => ({
        enabled: rule.enabled,
        host: rule.host,
        path: rule.path,
        method: rule.method,
        value: rule.target,
        header: '',
      }))
    },
    save: (expected: ResponseHeaderRule[], rules: ResponseHeaderRule[]) =>
      saveUrlPathRules(toPath(expected), toPath(rules)),
    hits: getUrlPathHits,
  },
  request: {
    read: getRequestHeaderRules,
    save: saveRequestHeaderRules,
    hits: getRequestHeaderHits,
  },
  response: {
    read: getResponseHeaderRules,
    save: saveResponseHeaderRules,
    hits: getResponseHeaderHits,
  },
}

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
        <ToggleButton value="response">
          {t('settings.mitm.rewrite.title')}
        </ToggleButton>
        <ToggleButton value="request">
          {t('settings.mitm.rewrite.requestTitle')}
        </ToggleButton>
        <ToggleButton value="path">
          {t('settings.mitm.rewrite.pathTitle')}
        </ToggleButton>
        <ToggleButton value="body">
          {t('settings.mitm.rewrite.bodyTitle')}
        </ToggleButton>
      </ToggleButtonGroup>
      {(['response', 'request', 'path', 'body'] as const).map((kind) => (
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
                  <TextField
                    select
                    size="small"
                    label={`HTTP Method${suffix}`}
                    value={item.method ?? ''}
                    sx={{ alignSelf: 'flex-start', minWidth: 140 }}
                    slotProps={{ select: { native: true }, htmlInput: { 'aria-label': `HTTP Method${suffix}` } }}
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
                    {['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].map((method) => (
                      <option key={method} value={method}>{method}</option>
                    ))}
                  </TextField>
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
