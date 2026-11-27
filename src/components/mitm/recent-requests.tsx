import {
  Alert,
  Box,
  Button,
  Card,
  Divider,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR, { useSWRConfig } from 'swr'

import type { RecentRequest } from '@/services/bindings'
import { armMitmResponsePreview, clearMitmRecentRequests, getMitmRecentRequests } from '@/services/cmds'

function HeaderList({
  title,
  empty,
  headers,
}: {
  title: string
  empty: string
  headers: [string, string][]
}) {
  return (
    <Box>
      <Typography variant="caption" sx={{ fontWeight: 600 }}>
        {title}
      </Typography>
      {headers.length === 0 ? (
        <Typography variant="caption" component="div" color="text.secondary">
          {empty}
        </Typography>
      ) : (
        headers.map(([name, value]) => {
          const line = `${name}: ${value}`
          return (
            <Typography
              key={name}
              variant="caption"
              component="div"
              role="group"
              aria-label={line}
              sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}
            >
              {line}
            </Typography>
          )
        })
      )}
    </Box>
  )
}

export function RecentRequests() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [clearing, setClearing] = useState(false)
  const [actionError, setActionError] = useState(false)
  const [arming, setArming] = useState(false)
  const [armedNotice, setArmedNotice] = useState(false)
  const needle = query.trim().toLowerCase()
  const [snapshot, setSnapshot] = useState<RecentRequest[] | null>(null)
  const { mutate } = useSWRConfig()
  const { data: live, error } = useSWR(
    open && snapshot === null ? 'mitm-recent-requests' : null,
    getMitmRecentRequests,
    { refreshInterval: 2000 },
  )
  const data = snapshot ?? live
  const armPreview = async () => {
    setArming(true)
    setArmedNotice(false)
    setActionError(false)
    try {
      await armMitmResponsePreview()
      setArmedNotice(true)
    } catch {
      setActionError(true)
    } finally {
      setArming(false)
    }
  }
  const clear = async () => {
    setClearing(true)
    setActionError(false)
    try {
      await clearMitmRecentRequests()
      setArmedNotice(false)
      setExpandedId(null)
      setSnapshot((current) => (current === null ? null : []))
      await mutate('mitm-recent-requests', [], { revalidate: false })
    } catch {
      setActionError(true)
    } finally {
      setClearing(false)
    }
  }
  const rows = data?.filter((entry) => {
    if (!`${entry.host}${entry.path}`.toLowerCase().includes(needle))
      return false
    switch (filter) {
      case 'request':
        return entry.requestRule
      case 'response':
        return entry.responseRule
      case 'body':
        return entry.bodyRule
      case 'path':
        return entry.pathRule
      case 'none':
        return (
          !entry.requestRule &&
          !entry.responseRule &&
          !entry.bodyRule &&
          !entry.pathRule &&
          !entry.localRule
        )
      default:
        return true
    }
  })
  return (
    <Card variant="outlined" sx={{ p: 1 }}>
      <Button
        aria-expanded={open}
        onClick={() => {
          setOpen(!open)
          setSnapshot(null)
        }}
      >
        {t('settings.mitm.recent.title')}
      </Button>
      {open && (
        <Stack spacing={1} sx={{ p: 1 }}>
          <Stack
            direction="row"
            spacing={1}
            sx={{
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
            }}
          >
            <Typography
              variant="caption"
              color="text.secondary"
              role="group"
              aria-label={t('settings.mitm.recent.limit')}
            >
              {t('settings.mitm.recent.limit')}
            </Typography>
            <Stack direction="row" spacing={1}>
              <Button
                size="small"
                disabled={clearing || !data}
                onClick={() => setSnapshot(snapshot === null ? (live ?? []) : null)}
              >
                {t(
                  snapshot === null
                    ? 'settings.mitm.recent.pause'
                    : 'settings.mitm.recent.resume',
                )}
              </Button>
              <Button
                size="small"
                disabled={clearing || arming || (!data?.length && !armedNotice)}
                onClick={() => void clear()}
              >
                {t('settings.mitm.recent.clear')}
              </Button>
            </Stack>
          </Stack>
          <Stack spacing={0.5}>
            <Button
              size="small"
              sx={{ alignSelf: 'flex-start' }}
              disabled={arming || clearing || snapshot !== null}
              onClick={() => void armPreview()}
            >
              Capture next JSON response
            </Button>
            <Typography variant="caption" color="text.secondary">
              Optional one-shot preview of the next admitted response within 30 seconds.
              Only complete uncompressed UTF-8 JSON up to 2 KiB. Known sensitive keys
              are redacted; other sensitive content may remain. Clear requests to cancel
              capture and discard previews. Nothing is saved to disk.
            </Typography>
            {armedNotice && (
              <Typography variant="caption" role="status">
                Capture requested (30-second window)
              </Typography>
            )}
          </Stack>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
            <TextField
              size="small"
              type="search"
              fullWidth
              label={t('settings.mitm.recent.search')}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <TextField
              select
              size="small"
              label={t('settings.mitm.recent.matched')}
              value={filter}
              sx={{ minWidth: 170 }}
              slotProps={{ select: { native: true } }}
              onChange={(event) => setFilter(event.target.value)}
            >
              <option value="all">{t('settings.mitm.recent.all')}</option>
              <option value="request">
                {t('settings.mitm.rewrite.requestTitle')}
              </option>
              <option value="response">
                {t('settings.mitm.rewrite.title')}
              </option>
              <option value="body">
                {t('settings.mitm.rewrite.bodyTitle')}
              </option>
              <option value="path">
                {t('settings.mitm.rewrite.pathTitle')}
              </option>
              <option value="none">{t('settings.mitm.recent.none')}</option>
            </TextField>
          </Stack>
          {(Boolean(error) || actionError) && (
            <Alert severity="error">{t('settings.mitm.error')}</Alert>
          )}
          {data?.length === 0 && (
            <Typography variant="body2">
              {t('settings.mitm.recent.empty')}
            </Typography>
          )}
          {Boolean(data?.length) && rows?.length === 0 && (
            <Typography variant="body2">
              {t('settings.mitm.recent.noMatches')}
            </Typography>
          )}
          <Stack spacing={1} sx={{ maxHeight: 360, overflow: 'auto' }}>
            {rows?.map((entry) => {
              const rules = [
                entry.localRule && 'Local response',
                entry.requestRule && t('settings.mitm.rewrite.requestTitle'),
                entry.responseRule && t('settings.mitm.rewrite.title'),
                entry.bodyRule && t('settings.mitm.rewrite.bodyTitle'),
                entry.pathRule && t('settings.mitm.rewrite.pathTitle'),
              ].filter(Boolean)
              const line = `${entry.method} ${entry.host}${entry.path} · ${entry.status}`
              const matches = rules.join(', ') || t('settings.mitm.recent.none')
              const expanded = expandedId === entry.id
              const shortTime =
                entry.completedAt.length >= 19
                  ? `${entry.completedAt.slice(11, 19)} UTC`
                  : entry.completedAt
              const timing = `${t('settings.mitm.recent.completed')} · ${entry.completedAt} · ${entry.durationMs} ms`
              return (
                <Stack
                  key={entry.id}
                  spacing={0.5}
                  role="group"
                  aria-label={line + ' · ' + matches}
                >
                  <Stack
                    direction="row"
                    spacing={1}
                    sx={{
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <Box sx={{ minWidth: 0 }}>
                      <Typography
                        variant="body2"
                        sx={{ overflowWrap: 'anywhere' }}
                      >
                        {line}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {t('settings.mitm.recent.matched')} · {matches}
                        {shortTime ? ` · ${shortTime}` : ''} ·{' '}
                        {entry.durationMs} ms
                      </Typography>
                    </Box>
                    <Button
                      size="small"
                      sx={{ flexShrink: 0 }}
                      aria-expanded={expanded}
                      aria-label={`${t('settings.mitm.recent.details')} ${line}`}
                      onClick={() => setExpandedId(expanded ? null : entry.id)}
                    >
                      {t(
                        expanded
                          ? 'settings.mitm.recent.hideDetails'
                          : 'settings.mitm.recent.details',
                      )}
                    </Button>
                  </Stack>
                  {expanded && (
                    <Stack spacing={0.75} sx={{ pl: 1, pt: 0.5 }}>
                      <Divider />
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        role="group"
                        aria-label={timing}
                      >
                        {timing}
                      </Typography>
                      {Boolean(entry.matchedRuleIds?.length) && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}
                        >
                          {`Rule IDs · ${entry.matchedRuleIds?.join(', ')}`}
                        </Typography>
                      )}
                      <HeaderList
                        title={t('settings.mitm.recent.requestHeaders')}
                        empty={t('settings.mitm.recent.noHeaders')}
                        headers={entry.requestHeaders}
                      />
                      <HeaderList
                        title={t('settings.mitm.recent.responseHeaders')}
                        empty={t('settings.mitm.recent.noHeaders')}
                        headers={entry.responseHeaders}
                      />
                      {entry.responsePreview != null && (
                        <Box>
                          <Typography variant="caption" sx={{ fontWeight: 600 }}>
                            Response body preview (redacted keys)
                          </Typography>
                          <Typography
                            component="pre"
                            variant="caption"
                            role="group"
                            aria-label={`Response preview: ${entry.responsePreview}`}
                            sx={{ m: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontFamily: 'monospace' }}
                          >
                            {entry.responsePreview}
                          </Typography>
                        </Box>
                      )}
                    </Stack>
                  )}
                </Stack>
              )
            })}
          </Stack>
        </Stack>
      )}
    </Card>
  )
}
