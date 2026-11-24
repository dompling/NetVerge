# MITM desktop review 08: guarded native certificate management

## Accepted baseline
ca1ac30: both Windows/macOS Cargo Check and focused Rust tests succeeded (macOS 12); three network labs and generated contract/typecheck passed. Exact generated IPC blob 7c6b264 synchronized. CI push concurrency cancels only superseded runs of the same integration branch/workflow; manual and release runs unaffected.

## Functionality
- Expose open_mitm_certificate_manager(expected_fingerprint). Require exact current public CA fingerprint and validated DER; confirm using a native warning dialog, recheck current CA after confirmation, launch current-user Windows certificate console or macOS Keychain Access. Return whether the manager was opened, not whether trust was installed or removed. Existing export and read-only assessment are the other two steps. No user trust store mutation in code or CI.
- Validate root key/certificate correspondence before Worker readiness. Separate CA integrity module rejects mismatched keys, unsafe locations, symlinks at the certificate/key leaf, hard links, oversized files, invalid self-signed CAs and Unix non-private owner/mode. Read key using bounded file descriptor checks, verify against public CA, zero temporary key buffer, never publish key material. The native Windows ACL is not proved by Node stat. CA initialization is still Whistle-owned and occurs before this validation.
- New regression tests: actual generated test certificates, matching/mismatched key, hardlink, oversized file, Unix permission/symlink cases, exact fingerprint binding and tampered CA; run alongside existing Windows/macOS network tests. No system trust write in automated tests.

## Architecture and reuse
Existing verified CA snapshot, existing rfd dialog, existing Windows Win32 bindings and system tools (no shell, fixed system paths) and existing macOS app. No new dependency or duplicate CA generation in production. Extract and reuse worker validation in the actual lab and unit tests; no new trust-store writer or arbitrary file arguments.

## Security and stability
The manager is deliberately a manual native control surface, not automatic install/remove. Do not interpret opening it as trust or ownership. Do not silently add or remove roots, modify system-wide stores, or elevate. Remaining prerequisites for automatic mutation: Windows private key/directory DACL verification; Unix parent ownership/alias and key generation audit, service runtime credential copies, safe persistent ownership record and exact scope with crash reconciliation, isolated positive and negative native trust tests and actual Windows/macOS desktop TUN. No production release before them. Existing private CA may predate this check; passing current permissions cannot establish historical secrecy.

Gate: static three-dimensional review only, priority-platform CI and generated contract pending. Automatic installation/removal remains blocked, manual certificate management entry is the current increment.
