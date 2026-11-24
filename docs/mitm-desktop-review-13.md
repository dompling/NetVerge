# MITM review 13: original routing decision laboratory

Baseline 2a19ab3: all five priority-platform tests succeeded (45349708965 and 45349708959). The legacy fixed-return transport test is not route-inheritance acceptance. The desktop activation gate stays closed.

## New discovery
Pinned Mihomo v1.19.34 resolves the original proxy and rule in tunnel/tunnel.go, then uses proxy.DialContext. Selector, URLTest, fallback and load-balance adapters may select dynamically at dial time. Retaining a rule or group name is insufficient; unwrapping a group in advance can alter selection, chain attribution, failure tracking and retry behavior. In particular a rejected adapter may return a nopConn with nil error. Never treat successful DialContext alone as an allowed origin connection. Preserve upstream reject semantics without showing a forged certificate to the rejected client.

## First experiment
CI checks out exact upstream commit 0455d0d28c4526937380505153e65a843d8612e8, copies a test-only Go file into the upstream tunnel package, and compiles/tests against the actual upstream types, rule resolver and adapters. No distributed core patch and no user config or system trust changes. Uses only controlled local HTTPS origin and two real HTTP outbound adapter fixtures. Compares ordinary dial vs a private authenticated one-use CONNECT lease of an already dialed connection. Tests domain, original process fields, source IP, destination IP, DIRECT and REJECT/REJECT-DROP priority; verifies actual observed proxy dials and TLS origin response; rejects invalid credential, changed authority and replay. Exact selected proxy object, not a string or second routing lookup. The lease does not dial any new target. Test source is injected only into isolated CI checkout and never into application startup. Windows and both macOS architectures first.

## Limits and next gate
This proves (if CI passes) only the bounded transport handoff in the actual core's test package. OS process fields are fixture inputs, not OS lookup. No live handleTCPConn hook, no TUN, no Whistle integration, no group/lazy-adapter admission, no proof of reload lifetime or statistics. The lab explicitly restricts single eager Direct/HTTP adapters and excludes Reject/RejectDrop; it is not a production broker. A one-shot stream cannot be assumed sufficient for Whistle's upstream pooling/retry behavior. Before deciding a production approach, test actual Whistle 2.10.15 request/CONNECT hooks and determine if it can consume a unique route lease without shared pools or cross-tunnel credentials. Verify group behavior at the actual dial boundary, first-write handshakes, retry, revocation, failure isolation and original statistics before opening the gate.

## Three-dimensional review
- Functionality: real resolver/adapter and local TLS transport test, route fixtures are differentiated by observed network connections, not just names; actual end-to-end MITM inheritance remains unproved.
- Architecture/reuse: use existing core resolver and dial implementations; no duplicate rules engine or route policy user setting. Small independent test file and workflow, no runtime fork shipped.
- Security/stability: test-only loopback listener, random credential, authority-bound single-use admission, bounded header/deadline, cleanup, no arbitrary destination selection or system changes. Production ownership, token transport, admission and resource budgets remain blockers. Static review complete; CI pending.

## Build correction

Run 45350736773: Windows and macOS Intel failed before executing assertions. The in-package test imported adapter/outbound -> dns -> tunnel, creating a Go test import cycle. Move the integration fixtures to external `tunnel_test`; a tiny internal `_test.go` bridge calls the real unexported resolver and snapshots/restores global state. Both files are copied only into the isolated pinned upstream test checkout. No production API, dependency or rule changes, and no removal of assertions. macOS ARM was still queued when the failure was diagnosed. Static review complete; replacement CI required.
