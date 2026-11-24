# MITM desktop review 04: generation-scoped process recovery

Scope: repair the remaining A02/S01 lifecycle findings, not a new user-facing feature. Parent dc9fde9 contains the cache-only change; prior network run 45322435847 passed all four platforms. Previous Windows/macOS/Linux cargo checks succeeded; Linux focused unit tests were still running when this repair was prepared.

## Functionality — pending regression evidence

- Use the existing Core lifecycle lock for the complete validated runtime write, worker preparation, reload/restart, and applied-runtime bookkeeping. Extract the existing locked restart body so reloading does not recursively acquire the same lock.
- A confirmed Core start or successfully applied runtime records the current readiness generation, rather than assuming a planned config or ready Node worker is active.
- A monitor checks for an exited worker every two seconds only when the associated Core readiness generation is current, and the lifecycle lock can be acquired. Three attempts per confirmed activation, then manual recovery; no direct fallback.
- The worker stop clears the recovery budget. A confirmed sidecar exit and sidecar-to-service handoff stop the old worker. An unprivileged Windows sidecar reload is rejected before touching the runtime file.
- A pure budget test verifies inactive/stale generations, exhaustion, and reset. Current CI needs to verify compiler compatibility and existing tests. The monitor's real child-loss/restart and shutdown timing still require an actual integration fixture.

## Architecture/reuse — partial repair

Reuse CVR's lifecycle lock, readiness generation and existing restart path. One session, one recovery monitor; no second Core manager, no new dependency, no new source of desired configuration. Local YAML remains the sole explicit MITM opt-in. Reload/stop sequencing is stronger; ordinary core application also uses the same lifecycle lock. Re-review lock ordering and existing service/sidecar regressions on all supported platforms.

A failed/ambiguous service apply may still retain the prepared worker to avoid breaking a potentially active core. Cancellation of an in-flight blocking start, a service ownership loss without confirmed stop, and recovery of a live but unresponsive worker remain unresolved. The monitor is a process-exit supervisor, not a full authenticated network health probe.

## Security/stability — pending

Recovery reuses the same session credentials and selected-domain rules; it does not alter routing or install CA trust. No automatic direct fallback. A port conflict or process launch failure consumes the retry budget, and the worker is not replaced if exit status is unknown. No new secrets are logged. The existing forward/return auth and network lab must still pass.

The remaining full-chain health probe, runtime secret storage/ACL and backup redaction, private listener boundary, actual desktop TUN verification, and explicit user-visible degraded state are still open. After budget exhaustion the selected traffic may fail; the UI does not yet surface the state.

**Gate:** all dimensions remain blocked for production. Do not start UI or CA management, merge, or release based on this change alone.
