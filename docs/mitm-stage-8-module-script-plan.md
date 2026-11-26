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

8.1b increment 1: add an optional exact HTTP method condition to the existing four
rule types and shared editor, preserving legacy JSON and same original-path semantics.
Absent/null means any method. Supported explicit values: GET, HEAD, POST, PUT, PATCH,
DELETE, OPTIONS. Unknown values fail validation; no widening to an unrestricted match.
Validate via Rust round trip, JavaScript planner/file tests and native Windows TLS
GET positive/negative method-condition probes. No regex engine in this increment.

8.1c: add optional bounded linear-time URL regex (`regex`) across the four existing
rule types and shared editor using an explicit RE2-compatible ASCII Thompson NFA subset
(1..=256 printable ASCII bytes, <= 128 NFA states, group nesting <= 8, counted repeats
<= 16, matched original `https://<host><path>[?<query>]` URL <= 2048 bytes). Reject
backreferences, lookarounds, inline flags, word boundaries, empty groups/branches,
nullable quantifiers and chained quantifiers in both Rust and the Whistle worker.
Keep exact `host` and `allowedHosts` admission unchanged; allow `path: ""` only when
`regex` is present, and AND `path`, `method`, and `regex` against the original URL.

8.1d: normalize all four rewrite phases into typed rule descriptors with stable `id`
(explicit unique `^[a-z0-9][a-z0-9._:-]{0,63}$` or deterministic `<source>:<phase>:<n>`),
validated `source` (`local` or `module:<reverse-domain>`), positive `revision` metadata,
per-phase worker diagnostics (`revision`, `activeRules`, `error`, per-rule `ruleHits`),
and matched rule IDs on recent requests while preserving legacy v1/v2 JSON rollback.

## Native module format: NetVerge YAML (module.yaml)

Decision: NetVerge owns its module syntax. Script API compatibility is independent
of module syntax. Surge .sgmodule is a future import/conversion format, never the
native runtime configuration format. No runtime INI interpreter or mandatory
Surge module compatibility. Preserve original imported source when available.

Use a single UTF-8 YAML document named module.yaml, with kind: netverge-module,
explicit integer schema version, unique stable
reverse-domain module ID, independent module version, name, optional description/author,
optional typed parameters, proposed MITM scope, ordered rewrite and script lists,
and explicit permissions. Store activation and approved content digest in separate
local state, not in downloadable module text. Normalize the validated manifest to the
same typed intermediate rule model used by the local editor. No eval, YAML custom
tags, aliases, merge keys, duplicate keys or unknown fields. Bound file size, nesting,
scalar length and list counts before activation. Reject unsupported schema versions.
Show line-numbered diagnostics; do not silently broaden conditions or drop actions.

Illustrative native schema target (not implemented or accepted by the current runtime):
```yaml
kind: netverge-module
schema: 1
id: com.example.api-debug
name: API debug
description: Inspect and modify a test API
version: 1.0.0
author: NetVerge
mitm:
  hostnames:
    - api.example.com
rewrite:
  - id: redirect-api
    type: url
    match:
      host: api.example.com
      path: /v1
    action:
      replace: /v2
  - id: add-header
    type: request-header
    match:
      host: api.example.com
    action:
      set:
        X-Custom-Debug: "true"
scripts:
  - id: modify-response
    type: http-response
    match:
      host: api.example.com
    script: modules/api-debug/debug.js
    requires-body: true
    timeout: 5
```

Proposed semantics:
- A match may contain an exact host, exact path, bounded pattern, method or other
  typed conditions supported by the selected request/response phase. Conditions are
  ANDed; omitted path means any path for the explicit admitted host. No implicit
  unrestricted host or scope expansion. Wildcards require a separately reviewed
  MITM admission design.
- List order is explicit. Stable rule identity is module ID plus local rule ID.
  Header conflicts retain last matching assignment within a phase; URL replacement
  takes the first matching terminal URL action. Match the original admitted request,
  without recursively matching the rewritten URL. Define local/module priority before
  enabling cross-source conflicts. Do not silently override local rules.
- Typed parameters with defaults and validation are proposed. Expand only permitted
  scalar value positions after parsing; never splice arbitrary YAML syntax or executable
  code. Permissions are declarations, not grants. User approval remains separate.
- Module enable/disable affects only that module's rules. Hostnames are proposals;
  activation requiring wider MITM scope goes through the existing consent transaction.
  [Rule] equivalent routing additions, if developed, use a separately reviewed Mihomo
  integration. Do not allow proxy/core settings, CA replacement, disabled TLS verification
  or arbitrary egress selection from the module.

## Active-profile discovery and path resolution

Decision: use ordinary YAML files named exactly module.yaml, no .nvmodule extension.
Identify manifests by kind: netverge-module and supported schema. Discover all
module.yaml manifests recursively beneath the active configuration's dedicated root,
including a root-level module.yaml if present. The modules/ subdirectory is a
recommended convention, not a mandatory discovery boundary. Do not scan the
application home, shared profiles/ parent, or another profile's root.

Current source (config/profiles.rs and utils/dirs.rs) stores profile files under a
shared profiles directory and resolves the current profile by UID. Before enabling
module discovery, introduce a dedicated profile workspace keyed by stable validated
profile UID. Proposed layout:

```text
profiles/
  <profile-uid>/
    config.yaml
    modules/
      api-debug/
        module.yaml
        debug.js
      rewrite/
        module.yaml
    scripts/
      common.js
    assets/
      mock.json
```

The directory containing the active profile's source config.yaml is the only base
for module asset references, regardless of the declaring manifest's nesting.
For example, modules/api-debug/debug.js, scripts/common.js, and assets/mock.json
all resolve from the configuration root, not from the module.yaml directory,
the process working directory, or the generated runtime configuration location.
Use forward-slash relative paths in manifests on all platforms. Reject absolute
paths, drive-relative paths, UNC paths, traversal components, symlinks/reparse
points and canonical paths escaping the profile root. Shared scripts within a
profile are allowed, but the approved digest must include every referenced asset.
Use bounded directory scanning with deterministic normalized relative-path order;
user-defined module order takes precedence, duplicate IDs are errors. Skip links
and application-owned staging/backup locations. Bound depth, number and aggregate
size of manifests/assets. Do not activate unknown or malformed manifests.

Maintain a migration plan for flat legacy profile files without losing stable UID,
subscription metadata, existing selected proxy state or rollback. A remote
subscription refresh updates only the owned config file, not adjacent local modules.
Do not treat a remote profile URL or its text as permission to download/execute
neighboring files. Keep module activation and approved revisions per profile UID.
On a validated profile switch, commit the new profile's approved module snapshot
with the configuration transition, remove the prior profile's module rules and
reject stale generation work; rollback restores both profile and module snapshot.
Discovery is automatic, activation remains explicit; imports and changed assets
are disabled/pending approval until validated and accepted. Preserve last-known
approved bytes rather than silently executing edited assets. No global module loading
in this phase; consider explicit global opt-in separately if requested.

Asset and lifecycle plan: local manifests plus profile-relative JS/data files first;
later portable profile/module bundles and HTTPS subscriptions. Remote script downloads
are a separate user-approved action with pinned digest. Import and update are
preview-only until explicitly approved. Validate complete manifests and assets,
review diff, commit atomically, retain last-known approved version and support rollback.
Asset hashes identify the exact reviewed bytes. No automatic execution after import.

Future compatibility adapters may parse a supported subset of .sgmodule, Loon or
Quantumult X into native YAML/typed rules, with an explicit list of unsupported entries
and a user-reviewed conversion. Never treat imported INI directives as trusted
configuration or permission grants. Initial stage prioritizes the native manifest,
not compatibility adapters.

## Script syntax and execution contract

Keep Surge-style JavaScript runtime APIs, independently of the native module format.
Native scripts entries use type: http-request or http-response, typed match conditions,
script (relative to active configuration root), requires-body, max-size, timeout
(seconds), and argument.
First matching enabled script per phase, explicit ordering. Later consider generic/cron;
routing, event and system control APIs are outside this stage. For script API reference:
https://manual.nssurge.com/scripting/overview.html and https://manual.nssurge.com/scripting/api.html.

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

Work in small independently reviewed increments, reusing existing production code
and tests. Verify actual GitHub Actions results for the exact tested source revision
and artifact before claiming completion or starting the next increment. Documentation-only
commits do not invalidate source-code CI evidence; note the tested code SHA separately.
A failed or cancelled relevant run is not a pass. Fix/revalidate the current gate first.
Do not create unused alternative implementations, speculative adapters or duplicate helpers.

- 8.1: centralized matching plan, typed rule model, bounded matcher and migration.
8.2: isolate `local` and `remote` profiles into dedicated `profiles/<profile-uid>/config.yaml`
workspaces (`config::workspace`), automatically migrating flat legacy profile files after
persisting `profiles.yaml` while preserving UID, subscription metadata, proxy selection,
companion chains, backup/restore, generation-checked profile switching and rollback, and
config-root-relative asset boundary checks (rejecting traversal, symlinks and reparse points).
8.3: recursively discover `module.yaml` (`kind: netverge-module`, `schema: 1`) inside the
active profile workspace (`core::mitm::module_manifest` + `module_manager`), rejecting YAML
anchors/aliases/tags/merge keys/duplicate keys/unknown fields with line-numbered diagnostics,
verifying and hashing profile-root-relative script assets into `contentSha256`, storing
per-profile explicit approvals (`module-approvals/<uid>.json`) that preserve last-known
approved rules on unapproved edits, and compiling active module rewrites to
`compiled-module-rules.json` with local-wins precedence and atomic profile-switch sync.
- 8.4: approved modules support `action: { remove: [X-Custom-Debug] }` for
  request headers and the same action with `X-*` names for response headers.
  Each action names one to four headers, uses case-insensitive names, and applies
  in rule order. Local assignments retain precedence. Native module URL rules can
  use `action: { remove-query: [debug] }` to remove all occurrences of up to eight
  case-sensitive names. Names use unreserved ASCII and match percent-encoded forms.
  Surviving query pairs retain their original bytes and order. The first matching
  URL rule takes precedence. Advanced body operations follow.
- 8.5: Mock / Map Local, scoped asset access and terminal-action precedence;
  prove no application request goes upstream for local responses (the original lease
  may already have opened a connection under the existing architecture).
- 8.6: inspector, optional bounded body preview, redacted HAR/cURL, explicit replay.
- 8.7: isolated script runner and Surge-compatible APIs, timeout/crash tests,
  permission review.
- 8.8: module subscriptions, reviewed updates and rollback; foreign-format import
  adapters only after native semantics are stable.
- 8.9: Windows real TUN/TLS, route identity, existing service/Sidecar lifecycle,
  packaging/rollback, stress and safety tests. macOS follows as Stage 9.

Maintain existing development-only gate and Windows-first testing. No production release
or broad third-party script execution until these gates pass. 8.1a only changes match
planning; module parser, script runner, UI changes and new rule syntax remain planned.
