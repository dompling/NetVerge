# MITM review repair 02: authenticated TLS bridge

Candidate 88b6c9e network lab [45321192275](https://github.com/dompling/NetVerge/actions/runs/45321192275) failed on all four platforms. Linux log: unauthorized forward/return and non-target checks passed; authenticated CONNECT succeeded; decrypted HTTP received 403. Whistle's SNI implementation uses h2Handlers/toHttp1 even when HTTP/2 negotiation is disabled, creating a new loopback HTTP connection (lib/https/index.js:943, 1013, 1058, 1280). The previous socket identity gate therefore rejects legitimate decrypted traffic.

Repair: use the existing Whistle tunnel-data propagation (getTunnelData, addReqInfo, setTunnelHeaders) to carry a random per-CONNECT capability from an authenticated tunnel. Bind it to the admitted authority, expire it when that tunnel closes, strip it before processing, reject missing/mismatched capabilities and upgrades. Cap the number of active capabilities. Do not permit arbitrary localhost HTTP requests. No upstream source changes.

Three-dimensional re-review:
- Correctness: identified the actual 403 regression; new test result pending. HTTP/1.1 only; upgrade intentionally unsupported.
- Architecture: uses an upstream tunnel-data mechanism instead of another proxy stack. The custom server event gate is still an adapter relying on Whistle implementation behavior, so its contract must be tested with pinned versions.
- Security/stability: public ingress continues to require separate forward credentials; internal re-entry requires a per-tunnel capability, not a source address or a fixed marker. Test unauthorized HTTP and invalid capability, and ensure capability/credentials do not reach the origin. Private TLS listeners, all possible header paths, runtime secrets and process lifecycle remain open. This is not production authorization certification.

The review gate remains BLOCKED. Do not begin UI, CA trust, packaging or claim that all dimensions pass until regression tests and remaining P0 findings are resolved.

Configuration decision (owner confirmed): retain Clash YAML and existing profile/merge/script pipeline. Add locally owned NetVerge extension settings using YAML, consumed by the adapter and not passed verbatim to Mihomo. No Surge syntax, Surge modules, or Surge scripting compatibility layer. Remote subscriptions must not be able to activate MITM or install trust. Migrate the development JSON only after the current network regression is resolved; runtime credentials and executable paths are not subscription fields.
