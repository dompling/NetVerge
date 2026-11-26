# NetVerge Stage 8: Rewrite, module and script compatibility plan

Status: development design and 8.1a implementation. Baseline 3f7e0b7 passed all four Windows workflows.
Do not interpret planned formats or examples as already supported.

## 8.1a: one original-request match plan

Keep current v2 rule JSON files and 16-per-type limits unchanged. Build one plan only after
the route-worker verifies admission and the local MITM scope. The admitted exact hostname,
HTTPS port 443 and original normalized path are the match boundary. A rewrite never expands
MITM admission, changes an original lease, or selects a different Mihomo policy.
All header and body matches use the original request path, not a rewritten path. Header
rules accumulate in list order; last matching same-name header wins. The first matching URL
path rule wins. Preserve the raw query without reparsing. No implicit recursive matching.
Response wrappers retain their existing order. Recent request flags and counters retain their
existing semantics. This change does not introduce wildcard, method or regex matching.

Next 8.1b: typed rule model with stable IDs, explicit source and revision, request/response
match phases, bounded URL patterns, method conditions and per-rule diagnostics. Keep the
outer MITM admission allowlist exact until a separate reviewed scope change. Prefer a
linear-time regex subset (evaluate RE2 compatibility); never run unbounded arbitrary JS
regex in the network worker. Reject unsupported syntax explicitly. Keep migration and
rollback fixtures for the existing JSON lists.

## Module source format: Surge-compatible subset

Reference: https://manual.nssurge.com/profile/module.html
Reference: https://manual.nssurge.com/scripting/overview.html
Reference: https://manual.nssurge.com/scripting/api.html
Reference: https://manual.nssurge.com/http/body-rewrite.html

Use .sgmodule INI-style source as an interchange format, not an executable config.
Preserve original text for export and show line-numbered diagnostics. Normalize parsed
rules to a typed NetVerge model with source module ID, rule ID, stable order, activation
state and revision. Never eval module text. Initial import is preview-only and disabled.
No unsupported line can silently become a more general rule.

Illustrative target syntax (NOT executable in this increment):
```ini
#!name=API Debug
#!desc=Example API module
#!version=1.0.0
#!arguments=host:api.example.test
[MITM]
hostname = %APPEND% {{{host}}}
[Script]
debug = type=http-response,pattern=^https://api\.example\.test/,requires-body=true,script-path=debug.js,timeout=5
```

Planned support: metadata name/desc/version/author, comments, MITM hostname proposals,
URL Rewrite, Header Rewrite, Body Rewrite, Map Local and Script sections, then arguments
and explicit append/insert semantics. A module hostname is a proposal only; approval uses
the existing MITM scope transaction. No wildcard expansion without separate approval.
Unrecognized sections, platform requirements and arguments must be reported, not ignored.
[Rule] integration is separate and needs existing Mihomo policy validation. Do not allow
General, Proxy, Proxy Group, CA replacement, certificate-verification disable, or implicit
outbound changes through the first module implementation.

Source import: local file first, later HTTPS source with size limits, no automatic execution,
review diff before update/activation, snapshot content digest and last-known approved
version, rollback. Relative script paths and Map Local files must resolve inside an
approved module directory; reject traversal, symlinks/reparse escape and arbitrary OS
paths. Remote script downloads are a separate user-approved action with a pinned digest.
Resolve cross-module order explicitly; no silent conflict resolution across source
priorities. Module disable removes only its rules, not unrelated local configuration.

## Script syntax and execution contract

Target compatibility first: named [Script] entries with type=http-request or http-response,
pattern, script-path, requires-body, max-size, timeout, argument. First matching enabled
script per phase, explicit ordering. Later consider generic/cron; routing, event and system
control APIs are outside this stage.

Minimum globals: read-only copies of $request and $response (phase-specific), $argument,
console.log, and $done(result). Support $done() as unchanged, header/body changes only
after validating output, same-authority URL changes only when explicitly allowed,
and later explicit local synthetic responses. Exactly one completion; reject unknown
result fields; bounded output. Never expose process, require, filesystem, raw sockets,
route lease credentials, worker credentials, CA private keys, or host application IPC.
No implicit $httpClient or persistent storage; future brokered permissions only.
Do not claim complete Surge compatibility: NetVerge admits traffic after Mihomo chooses
a route, so scripts cannot change the upstream authority or routing policy in-place.
Reject attempts to do so. Cross-host redirects, if added, must create a new client
request rather than reusing the original connection lease.

Use a separate constrained execution process, not Whistle main thread or Node vm as a
security boundary. Evaluate restricted JS runtimes with no native modules or network
bindings. Require OS-level resource and process-tree limits, wall-clock deadline,
concurrency quota, bounded IPC input/output, sanitized logs and cancellation. Suggested
initial ceilings: 1s execution deadline (configurable downward; hard upper cap 5s),
256 KiB body and output, 4 concurrent invocations, 64 MiB per runner; validate experimentally
before promising these limits. Body-free scripts should not buffer bodies. On failure,
discard all script mutations and pass the original admitted request/response unchanged
if no output has been committed. Never retry a partially transmitted request or silently
bypass the original MITM scope. Explicit blocking actions need separate validation.

## Delivery sequence and exit criteria

- 8.1: centralized matching plan, typed model, bounded matcher and migration.
- 8.2: header operations, query and URL rewrite; same-authority only; redirect separate.
- 8.3: bounded request and response body operations; encoding/framing correctness,
  invalid data and oversize pass-through, no stream buffering.
- 8.4: Mock / Map Local, scoped local file access and terminal-action precedence;
  prove local response does not send application request upstream (the original lease may
  already have opened a connection under the existing architecture).
- 8.5: inspector detail, optional bounded body preview, redacted HAR/cURL, explicit replay.
- 8.6: isolated script runner, compatibility APIs, timeout/crash tests, permission review.
- 8.7: module parser preview, activation, migration, source update and rollback.
- 8.8: Windows real TUN/TLS, route identity, existing service/Sidecar lifecycle,
  packaging/rollback, stress and safety tests. macOS follows as Stage 9.

Maintain existing development-only gate and Windows-first testing. No production release
or broad third-party script execution until these gates pass. 8.1a only changes match
planning; module parser, script runner, UI changes and new rule syntax remain planned.
