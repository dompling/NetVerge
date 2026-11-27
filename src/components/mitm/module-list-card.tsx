import {
  Alert,
  Box,
  Button,
  Card,
  Chip,
  Divider,
  Stack,
  Switch,
  Typography,
} from '@mui/material'
import { useState } from 'react'
import useSWR from 'swr'

import type { DiscoveredModulePreview } from '@/services/bindings'
import {
  getMitmProfileModules,
  setMitmModuleApproval,
} from '@/services/cmds'

import { errorDetail } from './rewrite-rule-model'

export const MITM_MODULES_KEY = 'mitm-profile-modules'

const STATE_LABELS: Record<DiscoveredModulePreview['state'], string> = {
  unapproved: 'Pending approval',
  active: 'Active',
  disabled: 'Disabled',
  update_pending: 'Modified (review required)',
}

export function ModuleListCard() {
  const [busyId, setBusyId] = useState<string | null>(null)
  const [actionError, setActionError] = useState('')
  const { data, mutate } = useSWR(MITM_MODULES_KEY, getMitmProfileModules, {
    revalidateOnMount: true,
    revalidateOnFocus: true,
    shouldRetryOnError: false,
  })

  if (!data || (!data.modules.length && !data.diagnostics.length)) {
    return null
  }

  const updateApproval = async (
    mod: DiscoveredModulePreview,
    enabled: boolean,
  ) => {
    if (!data.profileUid) return
    setBusyId(mod.id)
    setActionError('')
    try {
      const updated = await setMitmModuleApproval(
        data.profileUid,
        mod.id,
        mod.contentSha256,
        enabled,
      )
      await mutate(updated, { revalidate: false })
    } catch (err) {
      setActionError(errorDetail(err))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <Card variant="outlined" sx={{ p: 2 }}>
      <Stack spacing={1.5}>
        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
          Profile Modules
        </Typography>
        {actionError && <Alert severity="error">{actionError}</Alert>}
        {data.diagnostics.map((diag) => (
          <Alert
            key={`${diag.manifestPath}:${diag.line ?? 0}:${diag.message}`}
            severity="warning"
          >
            {`${diag.manifestPath}${diag.line ? `:${diag.line}` : ''} — ${diag.message}`}
          </Alert>
        ))}
        {data.modules.map((mod, idx) => {
          const needsApproval =
            mod.state === 'unapproved' || mod.state === 'update_pending'
          return (
            <Stack key={mod.id} spacing={0.75}>
              {idx > 0 && <Divider />}
              <Stack
                direction="row"
                spacing={1}
                sx={{ alignItems: 'center', justifyContent: 'space-between' }}
              >
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {`${mod.name} (${mod.version})`}
                  </Typography>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}
                  >
                    {`${mod.id} · ${mod.manifestPath} · sha256:${mod.contentSha256.slice(0, 12)}`}
                  </Typography>
                  <Typography
                    variant="caption"
                    component="div"
                    color="text.secondary"
                  >
                    {`Rewrites: ${mod.rewriteCount} · Scripts: ${mod.scriptCount}`}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                  <Chip size="small" label={STATE_LABELS[mod.state]} />
                  {needsApproval && mod.enabled && (
                    <Button
                      size="small"
                      disabled={busyId !== null}
                      onClick={() => void updateApproval(mod, false)}
                    >
                      Disable
                    </Button>
                  )}
                  {needsApproval ? (
                    <Button
                      size="small"
                      variant="outlined"
                      disabled={busyId !== null}
                      onClick={() => void updateApproval(mod, true)}
                    >
                      Approve
                    </Button>
                  ) : (
                    <Switch
                      checked={mod.enabled}
                      disabled={busyId !== null}
                      slotProps={{
                        input: { 'aria-label': `Enable module ${mod.id}` },
                      }}
                      onChange={(_, checked) =>
                        void updateApproval(mod, checked)
                      }
                    />
                  )}
                </Stack>
              </Stack>
              {mod.scriptCount > 0 && (
                <Alert severity="info">
                  Script sources are pinned on approval. Script execution is not available yet.
                </Alert>
              )}
              {mod.missingMitmHostnames.length > 0 && (
                <Alert severity="info">
                  {`Proposed MITM hostnames not yet enabled: ${mod.missingMitmHostnames.join(', ')}`}
                </Alert>
              )}
            </Stack>
          )
        })}
      </Stack>
    </Card>
  )
}
