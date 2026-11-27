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
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { save } from '@tauri-apps/plugin-dialog'
import { writeFile } from '@tauri-apps/plugin-fs'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import useSWR, { useSWRConfig } from 'swr'

import type { RecentRequest } from '@/services/bindings'
import { armMitmResponsePreview, clearMitmRecentRequests, getMitmRecentRequests, replayMitmRequest } from '@/services/cmds'
import getSystem from '@/utils/get-system'

import { exportRequestUrl, sanitizedCurl, sanitizedHar } from './recent-request-export'

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
  const [exportBusy, setExportBusy] = useState(false)
  const [exportNotice, setExportNotice] = useState('')
  const [replayTarget, setReplayTarget] = useState<RecentRequest | null>(null)
  const [replaying, setReplaying] = useState(false)
  const [replayNotice, setReplayNotice] = useState('')
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
  const exportRequest = async (entry: RecentRequest, kind: 'curl' | 'har-copy' | 'har-save') => {
    setExportBusy(true)
    setExportNotice('')
    setActionError(false)
    try {
      if (kind === 'curl') {
        await writeText(sanitizedCurl(entry, getSystem() === 'windows'))
        setExportNotice('Sanitized cURL copied')
      } else {
        const har = sanitizedHar(entry)
        if (kind === 'har-copy') {
          await writeText(har)
          setExportNotice('Sanitized HAR copied')
        } else {
          const file = await save({
            title: 'Export sanitized HAR',
            defaultPath: 'NetVerge-request.har',
            filters: [{ name: 'HTTP Archive', extensions: ['har'] }],
          })
          if (file) {
            await writeFile(file, new TextEncoder().encode(har))
            setExportNotice('Sanitized HAR saved')
          }
        }
      }
    } catch {
      setActionError(true)
    } finally {
      setExportBusy(false)
    }
  }
  const confirmReplay = async () => {
    const target = replayTarget
    if (!target || replaying || snapshot !== null) return
    const url = exportRequestUrl(target)
    if (!url || !['GET', 'HEAD'].includes(target.method)) return
    setReplayTarget(null)
    setReplayNotice('')
    setReplaying(true)
    try {
      const status = await replayMitmRequest(target.id, target.completedAt, target.method, url)
      setReplayNotice(`Replay completed: HTTP ${status}`)
    } catch {
      setReplayNotice('Replay failed. Request may have been sent; no automatic retry.')
    } finally {
      setReplaying(false)
    }
  }
  const clear = async () => {
    setClearing(true)
    setActionError(false)
    try {
      await clearMitmRecentRequests()
      setArmedNotice(false)
      setExportNotice('')
      setReplayTarget(null)
      setReplayNotice('')
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
          setReplayTarget(null)
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
                disabled={clearing || replaying || !data}
                onClick={() => { setReplayTarget(null); setSnapshot(snapshot === null ? (live ?? []) : null) }}
              >
                {t(
                  snapshot === null
                    ? 'settings.mitm.recent.pause'
                    : 'settings.mitm.recent.resume',
                )}
              </Button>
              <Button
                size="small"
                disabled={clearing || arming || exportBusy || replaying || (!data?.length && !armedNotice)}
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
          {exportNotice && <Typography variant="caption" role="status">{exportNotice}</Typography>}
          {replayNotice && <Typography variant="caption" role="status">{replayNotice}</Typography>}
          {replayTarget && (
            <Alert severity="warning">
              <Stack spacing={1}>
                <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
                  {`Send one new ${replayTarget.method} request to ${exportRequestUrl(replayTarget)}?`}
                  {' '}Original query, headers, credentials and body are omitted.
                  Current TUN rules apply; even GET can change server state.
                </Typography>
                <Stack direction="row" spacing={1}>
                  <Button size="small" onClick={() => setReplayTarget(null)}>Cancel replay</Button>
                  <Button size="small" variant="contained"
                    disabled={replaying || clearing || snapshot !== null ||
                      !live?.some(e => e.id === replayTarget.id && e.completedAt === replayTarget.completedAt)}
                    onClick={() => void confirmReplay()}>Confirm replay</Button>
                </Stack>
              </Stack>
            </Alert>
          )}
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
                      <Stack spacing={0.5}>
                        <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
                          <Button size="small" disabled={exportBusy || clearing || !exportRequestUrl(entry)}
                            onClick={() => void exportRequest(entry, 'har-save')}>Save sanitized HAR</Button>
                          <Button size="small" disabled={exportBusy || clearing || !exportRequestUrl(entry)}
                            onClick={() => void exportRequest(entry, 'har-copy')}>Copy sanitized HAR</Button>
                          <Button size="small" disabled={exportBusy || clearing || !exportRequestUrl(entry)}
                            onClick={() => void exportRequest(entry, 'curl')}>Copy sanitized cURL</Button>
                          {['GET', 'HEAD'].includes(entry.method) && (
                            <Button size="small" disabled={replaying || clearing || snapshot !== null || !exportRequestUrl(entry)}
                              onClick={() => { setReplayNotice(''); setReplayTarget(entry) }}>Replay request</Button>
                          )}
                        </Stack>
                        <Typography variant="caption" color="text.secondary">
                          Metadata only: query, credentials, arbitrary header values and bodies omitted.
                          The original hostname and path may contain private identifiers; review before sharing.
                          cURL is a command template, not a complete replay.
                        </Typography>
                      </Stack>
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
