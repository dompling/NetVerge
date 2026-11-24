# MITM desktop review 05: authenticated local health

Baseline 7ad8ef6 passed network lab 45325512341 (CONNECT on four runners, actual isolated Linux TUN), and Rust 45325459307 (four focused tests). This increment does not modify Clash profile syntax, UI, CA trust or release packaging.

## Correctness
The local health challenge enters the Whistle listener with both the forward proxy credential and a random challenge proof. Whistle opens a CONNECT through the real Mihomo authenticated return listener to its own fixed loopback HTTP listener, verifies the return response and emits a challenge-bound proof. The Rust monitor verifies that proof and requires a successful HTTP status. No external host or selected user's hostname is accessed. A positive result means the local authenticated round trip works; it does not certify external TLS, policy-provider health, real desktop TUN interception, or each selected domain. The lab verifies the same route and rejection of forged diagnostic requests before and after worker restart; regression results pending.

## Architecture/reuse
Reuse the existing Session and generation-scoped recovery supervisor. State values are Inactive, Checking, LocalLinkHealthy, Degraded, Recovering, Failed; state changes are logged without credentials. No extra port, external health service, independent configuration owner or dependency. Running child with failed local diagnostic becomes Degraded, not automatically terminated, because the failed hop could be Mihomo rather than Whistle. Confirmed child exit still uses the bounded recovery budget. The two-second polling period includes a bounded local probe; contention with lifecycle changes needs review.

## Security/stability
The only new route exception is the named return inbound, TCP, loopback IP and exact worker port. The worker admits only fixed diagnostic paths with an independent session secret challenge and forward credential, rejects arbitrary HTTP, and permits no arbitrary host from probe input. Secret stays in the worker environment payload and session memory, not generated YAML or diagnostic output. Health requests are intercepted before Whistle data processing; diagnostic headers are not sent to origin sites. The round trip has size and time limits and single-flight forward handling. Private listener isolation, runtime credential files/backups, cancellation and actual desktop lifecycle verification remain open.

**Gate:** blocked pending CI and additional review. The local probe is not a claim of full production end-to-end health. No UI, CA installation or merge/release yet.
