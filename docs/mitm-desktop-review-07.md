# MITM review 07: native read-only certificate assessment and export

Accepted baseline: 39f841f, run 45340604215, both priority platforms checked/tested and generated contract typechecked; previous three network lab jobs passed. The exact generated bindings diff was synchronized as a04d3a3 and its blob matches CI fb9312ae.

## Functionality
New native trust query uses exact public DER, never a subject-name match. Windows opens read-only existing logical CurrentUser and LocalMachine Root and Disallowed stores; denial takes precedence and inaccessible stores are unknown. Root membership is present_unverified, not a successful TLS evaluation or proof of ownership. macOS checks User and Admin trust settings and performs an offline basic X.509 root policy evaluation with Security.framework. A root-policy result is not leaf/hostname trust. Linux reports unsupported for this stage. Queries are single-flight, bounded for the caller, and checked against current CA identity. Export uses an explicit native save dialog, only current verified public PEM, no overwrite, no arbitrary frontend filesystem input. The latest API bindings must be regenerated in CI and committed before frontend usage.

## Architecture/reuse
Reuse current public snapshot, existing Tauri/Specta registry, existing locked security-framework dependency and windows-sys binding; no shell commands or separate certificate generator. Existing rfd native save dialog. Linux is deferred. Native store access is isolated in core/mitm/trust.rs. Windows logical CurrentUser may inherit machine certificates; macOS trust domain membership is not all keychain membership. Do not use the results to decide ownership or deletion.

## Security/stability
No install, remove, elevation, private-key export, arbitrary trust-store arguments or system mutation. Native store inspection never returns other certificates or their details. macOS network retrieval disabled for trust evaluation; Windows only store enumeration. Unknown/unsupported never map to trusted. Export does not replace an existing file; certificate identity is checked again after dialog. Tests cover denial precedence, unknown, and invalid export. Still need actual OS positive/negative trust scenarios with isolated test stores, Windows ACLs and service credential copies, root-to-leaf validation and actual desktop TUN; no trust mutation until those prerequisites and explicit consent/ownership are addressed.

Gate: static three-dimensional review complete, compilation and focused tests, network and generated contract pending. Do not advance to trust installation or release based only on this commit.
