# MITM desktop review 03: local YAML and worker lifecycle

Baseline 9992dcf: [network run 45322012659](https://github.com/dompling/NetVerge/actions/runs/45322012659) passed Windows, macOS Intel/ARM and Linux CONNECT plus isolated TUN; [Rust run 45321192205](https://github.com/dompling/NetVerge/actions/runs/45321192205) passed Windows/macOS/Linux Cargo checks and Linux focused tests. The previously reported 403 was resolved in the pinned lab.

This increment is intentionally scoped to local YAML and the generation/start boundary. No UI, trust store, package or Surge compatibility work.

## Functionality — BLOCKED pending checks

- F04: planning tests now cover YAML decoding, disabled configuration, unknown fields, stable credentials and no worker spawn. The existing lab still exercises the manually equivalent core config, not real desktop application. Actual Windows/macOS TUN remains unverified.
- F02: effective mixed-port order was repaired and prior Cargo checks passed. Custom listener and DNS/controller collision checks remain open.
- F03: GUI mode change guard compiled successfully; direct API mutation and concurrent mode-change paths remain unverified.

## Architecture and reuse — partial repair, BLOCKED

- A02: generation now plans the overlay without launching Node. Core start and validated apply ensure the worker before using it; confirmed core stop or successful apply without the overlay stops it. Reuse the existing core update/validation and service/sidecar paths. Windows non-admin sidecar must reject an MITM runtime instead of stripping TUN and leaving interception rules.
- A03: one explicit local YAML defines `mitm.enable`, `hostname`, and return `policy`. Temporary local executable/port provisioning lives in `runtime`. Subscription, merge and script data cannot authorize MITM. The generated proxy/listener/rule prefix is rechecked before activation. Runtime settings are fixed after first plan until restart. The env flag remains a development gate, not product UI state.
- Ambiguous failed core application still retains the worker deliberately: rollback of configuration is not proof that the core stopped using the candidate. Need authoritative applied-runtime reconciliation, including asynchronous core loss, before declaring A02 closed. Startup preparation can still leave a worker after an unsuccessful core launch; avoid a premature stop when the service may actually be running.

## Security/stability — BLOCKED

- S01: the four-platform lab verified authentication and rejection of forged bridge credentials, and checked no internal credential reached the controlled origin. Worker exit recovery and post-apply authenticated chain health remain open; no automatic direct fallback.
- S02: development startup fallback is guarded and compiles; actual startup failure/recovery needs runtime evidence.
- S03: credentials remain in generated runtime YAML; verify backup/export/log redaction, CA filesystem ACL, private TLS listener isolation and session loss. No OS trust changes.
- S04: explicit policy is still a deliberate selected-domain override. Reject/process rules, proxy chain loops, QUIC and DNS exceptions remain outside the proven scope.

## Gate

All three dimensions remain blocked for production use. Re-run Rust tests and the unchanged network baseline. No merge/release, no UI expansion until the remaining lifecycle/health and security findings are resolved. Review repair is based on source paths, not a claim of verified desktop behavior.

Re-review of the repair moved the Windows non-admin guard ahead of sidecar reservation and configuration-file writes. The generated-runtime validator is now a separate pure function, exercised by positive validation and negative tampered-rule/global-mode tests. These additions do not close the remaining crash, ambiguous-apply or credential-storage findings. The direct reload versus lifecycle stop race still needs an explicit owner boundary.
