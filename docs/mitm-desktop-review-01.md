# MITM desktop backend: three-dimensional review 01

Reviewed candidate: [0b5e92a](https://github.com/dompling/NetVerge/commit/0b5e92a7c1c76f31ab922c7979f3d1d1095764b0).
Scope: first opt-in Rust runtime integration, the worker and the changed test/CI paths. No UI or certificate-store implementation is in scope. This is a static review plus existing CI evidence, not independent desktop runtime certification.

## Evidence

- [Network lab 45317973737](https://github.com/dompling/NetVerge/actions/runs/45317973737): Windows, both macOS architectures and Linux CONNECT passed; actual isolated Linux TUN also passed. The test uses a controlled origin and a separate Mihomo configuration, not the desktop runtime generator.
- [Cargo check 45318056573](https://github.com/dompling/NetVerge/actions/runs/45318056573): Windows passed; macOS was still running at review time; Ubuntu failed in glib-sys because pkg-config could not find glib-2.0.pc. The build had not reached the MITM code on Ubuntu. The original CI did not install Linux native libraries.
- No desktop executable run, no system CA installed, no actual Windows/macOS TUN test yet.

## Dimension 1: functional correctness — BLOCKED

F01 (P1, CI): install native GTK/GLib/WebKitGTK/AppIndicator development packages before Linux Cargo checks. Pin Ubuntu 24.04 rather than inheriting the newly changed ubuntu-latest image. Run the focused Rust overlay unit tests on Linux after Cargo check. Repair included in this review's commit; result pending.

F02 (P0, regression): core/mitm.rs overlay() checks only existing top-level listener ports; config/config.rs generate_with_profiles() previously applied the session mixed-port fallback after prepare(). A fallback could introduce a collision after the check. Move prepare() after existing sanitization and fallback. Repair included; compile and runtime verification pending. Existing custom listeners and external-controller/DNS listener conflicts still require validation.

F03 (P0, mode transitions): feat/clash.rs change_clash_mode() PATCHes Mihomo directly before persisting settings, so the generator's rule-mode check does not prevent an active MITM runtime switching to global/direct mode. Global mode may bypass the named-return guard, and the generated proxy may also become visible in GLOBAL. A comment telling developers not to change modes is not a control. Before enabling a user-facing switch, serialize this transition with the existing config-write owner, either remove MITM atomically before changing mode or reject unsupported modes. Test concurrent changes and return routing. Open.

F04 (P0, real desktop behavior): the isolated lab uses a handwritten equivalent config, not output from Rust overlay(). It does not validate existing profile switches, TUN enable/disable, direct runtime patch paths, actual policy selection, fake-IP filter/hosts exceptions, or desktop startup. Add a test with generated overlay bytes and the real Mihomo, then actual desktop integration tests. Open.

## Dimension 2: architecture and reuse — BLOCKED

A01 (positive): generated runtime overlay is small, leaves subscriptions unchanged and reuses CVR's existing config validation/apply path. Whistle and Mihomo are unmodified. System proxy and certificate trust remain untouched.

A02 (P0, transaction ownership): core/mitm.rs prepare_sync() starts a process during configuration generation, before validation or commit. feat/executor.rs rolls back draft/files after failure but does not roll back this process effect. A failed enable may leave an idle worker; the old and new configurations can diverge. Move process preparation and commit/rollback into an explicit effect/lifecycle boundary while preserving the old worker until a successful transition. Reuse existing configuration-write and lifecycle lock ordering. Open.

A03 (P1, redundant runtime state): the development env flag, static Worker settings and generated config are separate sources of truth. They intentionally avoid persistent product settings now, but cannot become the UI's authoritative state. Design one settings owner plus separate desired/applied/health state; don't build a second general proxy manager. Open.

## Dimension 3: security and stability — BLOCKED

S01 (P0, readiness/exit): start_worker() accepts a stdout sentinel only; it doesn't prove listener ownership or successful authenticated return after the core applies. A worker crash can leave active rules targeting a dead or subsequently reused port. Implement authenticated forward ingress and post-apply chain health, then reconcile failure without silently bypassing the selected policy. Test child exit, occupied ports, core restart, app quit, and recovery. Open.

S02 (P0, fail behavior): config/config.rs generate_and_validate() can fall back to the default core configuration on generation/validation errors. For a requested MITM development session this can start without its rules or lose the explicit policy; that is not evidence of a safe fail-closed transition. Resolve startup failures with an explicit blocked/degraded state and user-visible error, and define whether normal non-MITM operation is permitted by the user's intent. Open.

S03 (P0, local trust boundary): the return inbound has a session credential, but the forward Whistle listener is not authenticated and the credential is serialized into runtime YAML. Loopback is not user identity. Verify access controls and redaction for runtime config, backups, API views, temporary files, and CA/private-key permissions on Windows/macOS/Linux. Do not enable global OS CA trust yet. Open.

S04 (P1, routing semantics): first-match MITM rules intentionally override the original selected-domain route with an explicitly chosen policy; this can override a profile REJECT/PROCESS rule. This is a documented dev-mode behavior, not transparent preservation. Require explicit user policy and authorization and test reject/blocked destinations before allowing general production use. No QUIC bypass or certificate pinning circumvention is part of this change. Open.

## Gate decision

All three dimensions are blocked. This round repairs F01 and the confirmed F02 ordering defect only; remaining issues are not marked fixed. No UI, certificate installation, new feature expansion, merge or release. Re-run CI, then address P0 lifecycle and routing invariants, re-review the repaired revision and verify actual desktop behavior before proceeding.
