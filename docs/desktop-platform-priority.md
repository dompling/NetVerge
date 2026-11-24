# NetVerge desktop priority and certificate trust plan

Decision: Windows and macOS are the active implementation and acceptance targets. Linux is deferred, not removed. Existing Linux code, native dependencies, isolated TUN lab and regression tests are retained and available using the optional include_linux workflow-dispatch input. Ordinary integration-branch pushes run Windows and macOS; macOS network coverage retains Intel and Apple Silicon. Upstream release/PR workflows are unchanged.

## Current review gate

The ZIP name API fix at 71c5a45 passed Windows and macOS Cargo Check in run 45337519881; Linux was still installing native packages. Prior network run 45334310544 passed all four jobs including isolated Linux TUN. The Windows/macOS-only gate still requires focused Rust tests, generated Specta bindings, type checking and network results on the new commit. Do not equate compilation with complete desktop acceptance.

## CI changes

- Run existing full-workspace checks with warnings denied on both priority operating systems.
- Run focused MITM tests on both instead of depending on Linux; Unix-specific file permissions and real child recovery fixture now run on macOS as well as optional Linux. The fixture uses an OpenSSL/LibreSSL-compatible config, not a Linux-specific command-line option.
- Generate the same Specta TypeScript contract on macOS and retain the artifact and frontend typecheck. Review and commit actual generated bindings before frontend consumption.
- Linux remains available manually with include_linux=true; no cancellation of the earlier run and no removal of its tests.
- Network lab is still explicit CONNECT on Windows/macOS, not proof of real OS TUN interception. Actual desktop TUN, Windows ACL and platform-specific service behavior are mandatory before a Windows/macOS production release.

## Certificate trust next-stage design

Reuse current Session, public CA and IPC; no separate CA generator or settings format. Trust status is independent of local link health. Query exact fingerprint in the user's native trust store, distinguish absent/present/trusted/unverified/unknown. Do not infer trust from presence or command success. macOS user keychain and trust settings; Windows current-user Root store and certificate chain policy. Scope and ownership must be verified before any mutation; Linux adapters are deferred.

First implement read-only assessment and explicit public PEM export with existing native save UI. Trust install/remove is a separate explicitly confirmed action bound to the exact current CA fingerprint and store. No arbitrary certificate bytes, paths, shell command arguments, or private keys from IPC. No silent elevation or installation on startup/TUN toggle/import/recovery. Remove only app-managed exact certificate; never remove a pre-existing CA automatically. Re-check trust independently. An unsupported or ambiguous operation must report unknown or provide manual instructions, not success.

Before enabling mutation: verify Windows private directory/key ACLs, macOS private file ownership and symlink behavior, service runtime credential copies, exact certificate identity/validity, consent and ownership record. Use an isolated test account/store for actual trust changes; do not alter the user's existing trust store for automated tests. No production trust mutation is implemented here.

## Three-dimensional static review

- Functionality: same existing tests and validations preserved on priority platforms; Linux can still run via manual input. Moving Unix fixture and generated contract requires successful CI.
- Architecture/reuse: same workflow, same Core tests and existing Specta generator; no new platform-specific manager or duplicated test suite.
- Security/stability: no CA trust changes, no new privileged operation, no disabled Windows/macOS checks. Linux is explicitly deferred, not reported as verified for this revision.

Gate: pending new CI and generated contract review; next trust code must not advance until priority-platform baseline is accepted. Final Linux verification is a separate milestone.
