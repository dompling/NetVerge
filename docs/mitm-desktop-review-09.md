# MITM desktop review 09: settings and certificate management UI

Baseline: 9376b39 Rust CI 45343759645 and f4b522b network CI 45344893593 passed. Synchronized exact generated native management IPC at c05d518.

## Functional correctness
Add Windows/macOS MITM entry within existing Clash settings, searchable by MITM/HTTPS/CA. Reuse dialog, status and trust IPC, show development configuration, local link health, core generation, retry budget, fingerprint, per-store membership and trust assessment. Query only while dialog is open; manual refresh and focus revalidation, no polling native trust stores. No fake activation switch, no claim of end-to-end health. Refresh before actions, disable while validating, on error, when no certificate or mismatched fingerprint. Native management still rechecks fingerprint and requires confirmation; export uses existing native dialog. Chinese, Traditional Chinese and English strings with existing fallback for other locales. UI model tests for missing/mismatched/disabled status, actual generated IPC and i18n metadata checks and architecture validation in CI.

## Architecture and reuse
Use existing MUI, BaseDialog, SettingItem, setting catalog, SWR, existing notice service and command wrappers around Specta bindings. No additional dependency or duplicate settings subsystem. Do not change remote profiles, Clash/TUN settings, or CA trust in frontend. Linux entry hidden pending final platform work.

## Security and stability
Trust membership is not proof of TLS trust; local link health is not proof of real TUN. No private key, arbitrary certificate bytes, file paths or trust mutation from UI. Native CA manager returns launch success only. Export is independently guarded on backend; stale snapshots cannot authorize management of another CA. Actual native dialog and visual desktop acceptance, Windows ACL, automatic trust mutation and production packaging remain open. Gate: static review only; CI, UI model tests and manual visual verification pending.
