# MITM desktop review 11: independent configuration editor

Baseline: 39fc35c passed all five priority-platform tasks in 45347764967 / 45347764856. Exact generated IPC synchronized in 0d64c7d (c75d6cc binding blob).

## Functional correctness
- Independent /mitm page has a configuration card above runtime and CA cards. Edit the saved enable switch, exact hostname list (one per line; supports add/remove/edit and bulk paste), explicit return policy from applied profile. Display active startup and saved selections separately, pending restart, unconfigured developer bootstrap, read failure, and validation errors. Existing status card stays authoritative for observed local link. Header refresh updates status and settings, without polling or automatically saving.
- The UI keeps an editing snapshot and revision, not a copy of live runtime. Reject stale drafts; preserve edits if native save confirmation is canceled or fails. Only successful backend save updates the saved view. Native dialog still owns confirmation; the UI never changes system trust or automatically restarts.
- Tests cover distinct active/saved selections, normalization, conflict, invalid hostnames, duplicates/limits, absent policies and disabling. CI executes generated frontend typecheck, locale generation parity, both feature model tests, navigation test and existing architecture check. Chinese, Traditional Chinese, English; existing fallback handles others.

## Architecture and reuse
Use existing independent page, MUI sx styling, SWR, useLockFn, command wrappers and verified Specta IPC. Isolate draft logic in pure typed model; separate reusable config card. No new dependency, router or competing runtime owner. No Rust change.

## Security and stability
Only config data and revision enter existing backend commands. Local opt-in still required; exact DNS names, explicit policy, native confirmation, backend revision/policy recheck and atomic YAML write remain authoritative. No arbitrary paths, credentials, trust mutations, live switch or misleading health claims. Disable and enable require full app restart using same developer bootstrap. Runtime hot-apply transaction, verified Windows ACL, actual desktop TUN, packaging and Linux remain open. Static three-dimensional review done; new CI and actual desktop visual verification pending.
