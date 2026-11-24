# Desktop MITM development integration

The first desktop backend increment is opt-in and intended only for authorized development traffic. No upstream profile files are changed, no system proxy or certificate trust is changed, and no automatic update channel is added. The desktop runtime generator invokes the MITM adapter after the normal profile enhancement pipeline and before the existing core validation and application path.

## Development activation

Install the existing Whistle package in engines/whistle (Node 22+, npm install --ignore-scripts). Launch a locally built NetVerge with NETVERGE_MITM_DEV_CONFIG pointing to an absolute JSON file:

```json
{
  "node": "/absolute/path/to/node",
  "worker": "/absolute/path/to/NetVerge/engines/whistle/mitm-worker.cjs",
  "hosts": ["api.example.test"],
  "port": 18899,
  "return_port": 18900,
  "policy": "DIRECT"
}
```

Use an authorized real test domain and explicitly select an existing proxy/group or DIRECT. The selection overrides the original routing decision **only for selected TUN TCP/443 domains**. It does not preserve original process-based routing for those domains. No wildcard, IP, QUIC, or arbitrary Whistle rules are accepted in this increment. Existing ordinary rules are appended unchanged. The return inbound is loopback-only, uses session authentication, only accepts the selected domains and TCP/443, and rejects all other traffic. The current generated runtime contains the return credential; protect the app data directory and do not distribute runtime YAML.

The existing TUN switch and fake-IP DNS must be enabled, and the profile must use rule mode. Do not change modes directly through the core API during the test. Without the environment flag or with TUN disabled, runtime generation leaves the original profile unchanged. The worker stays idle while TUN is disabled so a failed core reload cannot cut a live upstream; parent stdin closure ends the desktop worker on app exit. Restart the desktop to change the development settings. The CA is generated inside the isolated Whistle data directory under app_home_dir/netverge-mitm-dev. It is not trusted by the OS; use a dedicated test client with that CA only.

## Current limitations

- This is the runtime config and process-management entry point, not a packaged or UI-accessible release.
- Rust compilation and the new desktop startup path still require verification. The updated lab validates authenticated return routing and TUN-specific rules, not the Tauri executable.
- Worker startup readiness only confirms the listening worker; the core return listener must be validated after the existing core applies the configuration. Worker loss fails selected connections while the MITM rule remains active; no automatic direct bypass is introduced. Re-generation can restart the worker.
- No live session toggle, persistent MITM UI settings, explicit post-apply health reconciliation, system CA installation, or bundled Node runtime yet. Existing CVR startup validation/fallback behavior remains unchanged. Do not enable this experimental setting for a production profile.
- Static hosts, fake-IP filter exceptions, incompatible profile rules, listener conflicts, and actual macOS/Windows TUN routing require further validation. Avoid profiles with custom routing features until verified.

## Review repair increment

Development sessions reject GUI Global/Direct transitions and default-config fallback. Forward and return proxy legs use different session credentials. The Whistle custom HTTP server guards the public CONNECT listener before dispatch; only configured exact host and TCP port are admitted. HTTP/2 interception is disabled in this increment because Whistle's internal HTTP/2-to-HTTP/1 conversion can re-enter the public server. This is not an audit of Whistle's private TLS listeners or all core API mutation paths. The worker still starts during config generation; lifecycle ownership remains open.
