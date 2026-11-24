# CI cache optimization review

Scope: Cross Platform Cargo Check on the NetVerge integration branch. No business code, release settings, TUN fixture or MITM assertions changed.

Evidence: Linux job [138199869510](https://github.com/dompling/NetVerge/actions/runs/45321192205/job/138199869510) reported `No cache found` after `save-if: false`. Cargo check started 03:42:07 UTC, focused test started 03:45:10, and tests finished 03:48:03 (two passed). The old cache pointed at src-tauri rather than the root Cargo workspace target directory. These observations concern that completed run; no live runner log was available for the current slow job.

Three-dimensional review:
- Correctness: retain all three OS/target entries, all-workspace/all-feature check with warnings denied, Linux native packages and the same Linux test command. Add missing workspace manifests/crates/toolchain paths to push triggers. The separate MITM laboratory workflow remains unchanged. New CI results required.
- Architecture/reuse: use existing Swatinem/rust-cache action and root workspace path, distinct cache prefix and OS/target key. Save dependency artifacts on the integration branch, not workspace-specific build products. Keep the Linux check and test in the same job to reuse available artifacts without a second setup. Dev/test debug symbols and incremental build are disabled only in this workflow; release profiles unchanged.
- Security/stability: no secrets, runtime YAML, certificates or app data in the configured cache. Cache writes are limited to the integration branch and isolated from upstream workflow cache namespaces. Cargo fingerprints still validate inputs; caches do not skip checks/tests. Do not cancel the earlier running verification. A successful first new run populates the cache; compare a subsequent cache-hit run before claiming a speedup.

Gate: static review complete for the CI-only change; execution and measured improvement pending. The previous desktop lifecycle gate remains separate and blocked until its required tests and findings are resolved.
