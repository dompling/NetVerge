# MITM review 14: Whistle over an already selected connection

Baseline 7f35e78 passed all three platforms in run 45351244950. This increment is an isolated real Whistle 2.10.15 test, not desktop activation.

## Functional correctness
- Reuse pinned Mihomo resolver and actual HTTP outbound adapter fixtures from review 13. Two distinct original process-rule decisions for the same hostname, each selects a real different proxy endpoint. Verify ordinary TLS baseline with isolated origin CA and exact origin leaf.
- Start existing unmodified desktop worker with a separate temporary data directory, native Node 22.23.3, and one already-dialed route lease as its sole return proxy. The 192-bit random lease secret uses the existing worker's 32-character credential format. Go client trusts only that worker's verified public CA, verifies hostname, observes a different leaf and receives the actual HTTPS origin response. Check exact lease consumption and dial counts, cross-worker ingress credentials, changed authority, internal header leakage, consumed/revoked lease and REJECT.
- CI runs prior seven fixtures independently, then new integration. Windows and both macOS architectures. No system trust changes, external origin, OS proxy or TUN.

## Architecture and reuse
Reuse existing worker, CA integrity checks, real upstream core and existing single-use lease. Separate workers per original lease are deliberate test isolation, NOT a recommended production design. This experiment cannot establish concurrent same-host isolation inside a single shared Whistle instance or support multi-request/pooling/retry semantics. Need examine per-tunnel upstream routing hook and connection pooling key before production work. Dynamic strategy groups and lazy handshakes remain separate blockers, not silently unwrapped or replaced.

## Security and stability
Loopback fixtures only; credentials supplied through child environment, never printed; distinct ingress and return credentials, no arbitrary caller egress selection. Strict client CA and origin TLS configuration, ephemeral private files, bounded timeouts, child cleanup and fail-closed tests. A successful HTTP CONNECT from worker is not sufficient: require actual TLS response and original lease counter. Existing desktop activation gate remains closed. Static three-dimensional review complete; new CI pending. Do not claim routing equivalence beyond covered fixtures.
