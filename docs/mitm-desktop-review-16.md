# MITM review 16: native dynamic group connection handoff (draft)

Baseline e8ab74b: run 45356577402 passed Windows and macOS Intel, including shared Whistle isolation. macOS ARM remains queued at draft creation. This draft is deliberately isolated from feat/whistle-integration, so it cannot cancel the prior acceptance run. Do not advance the integration branch until that run passes all three platforms.

## Functional correctness
Use the pinned Mihomo native Selector, URLTest, Fallback and LoadBalance implementations with real HTTP outbound adapters and deterministic health snapshots. Resolve the original process rule once, dial the returned original group, assert actual dial counts and chain attribution. Prepare eight independent established streams; change selector and health snapshots between dials; preserve the actual existing streams through a single shared Whistle worker and two distinct TLS origins. Check nested REJECT and REJECT-DROP (successful dial return can still be a rejection). Round-robin tested; consistent hashing and sticky sessions remain separate. Health snapshots are fixtures, not real network health probes.

## Architecture and reuse
Do not preselect or independently implement a group algorithm. Source: upstream pinned 0455d0d28c4526937380505153e65a843d8612e8, tunnel/tunnel.go match/resolveMetadata and adapter/outboundgroup/{selector,urltest,fallback,loadbalance}.go. Native dial appends group names to the actual connection. Group fixture's exact expected member and chain checks are proof assertions, not a production authorization policy. Factor the test transport only; keep original single-adapter eligibility unchanged. A production reject/type identity mechanism and lazy first-write handling remain blockers.

## Security/stability
Only local controlled TLS origins, existing verified CA, distinct credentials, one-use leases, bounded timeout, no direct fallback or trust-store modification. Native reject routes must not receive a lease. No production code, user settings, system proxy or desktop activation changes. Static draft review only; no runtime result. After prior gate passes, integrate and run Windows and both macOS CI. Do not claim full policy-group support or multi-request connection reuse.
