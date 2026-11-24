# MITM desktop review 10: restart-scoped local configuration

Accepted baseline: 1f7660e passed Windows and macOS strict checks, unit tests, generated frontend contract and frontend checks in 45346748738. The independent MITM page remains unchanged pending generated new IPC.

## Functional correctness
- Read the developer bootstrap once per application process. An optional fixed app-local YAML file contains only selected enable, exact hostnames and return policy, bound to the bootstrap SHA-256. The original explicitly selected developer YAML remains the only executable/runtime-path source. No config is enabled or created from a subscription.
- New typed read/save IPC: exposes active selection vs saved selection, revision, restartRequired and current applied-profile policy choices (DIRECT and valid existing nodes/groups). No local runtime paths or worker secrets. Validate exact lowercase DNS names, uniqueness, limit 64, explicit existing policy when enabled. Reject invalid/reserved policies and unknown YAML fields.
- Native warning dialog with actual hostnames and policy; save only after explicit confirmation and revision recheck. Atomically replace local YAML using existing private runtime writer. Cancel returns null. Runtime remains unchanged for the whole process, including TUN and profile reloads. A full application restart with the original developer bootstrap is necessary. Does not imply TUN or browser trust is enabled. If bootstrap changes, reject stale saved configuration rather than silently enabling.
- This is the backend increment. Generate Specta bindings in CI before adding the standalone-page editor; do not manually invent IPC types. Live switching is deferred until transactional core apply/rollback and worker stop/ownership are verified.

## Architecture and reuse
Reuse existing LocalConfig parser, host/policy validation, overlay planner, private YAML writer, committed runtime, native rfd dialog and startup/reload ownership. No new dependency, second runtime owner, frontend path input or arbitrary command execution. Existing environment opt-in remains mandatory. Fixed file excluded from backup restore; backup creation already uses an allowlist.

## Security and stability
Bound YAML input, reject symbolic link leaf, preserve restart snapshot and never persist credentials. Save serialized per process with revision checks before/after confirmation. This is not multi-process locking or verified Windows DACL protection; only one running NetVerge instance is supported. App-local storage is not a security boundary against the same OS user. No auto trust changes, no real desktop TUN acceptance yet. Full automatic certificate trust and hot activation remain blocked by the previously documented ACL and lifecycle issues.

Tests: domain/policy/duplicates, bootstrap binding, unknown runtime field injection, active vs saved distinction, no path disclosure, policy list filtering and backup guard. Static three-dimensional review complete; native CI and new contract generation pending.

Acceptance: 39fc35c passed both priority-platform strict Cargo checks and Rust tests, generated frontend contract, frontend checks and all three network regressions in runs 45347764967 and 45347764856. Sync exact generated contract from macOS job 138286381258 (target blob c75d6cc). No native trust writes or real Windows/macOS TUN acceptance claimed.
