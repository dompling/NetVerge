# NetVerge HTTP engine prototype

This is an opt-in development sidecar, not yet wired into the Tauri application.
It binds to loopback and forwards matching traffic to the existing Mihomo HTTP/mixed port.
The process runs in the foreground and emits a JSON readiness event on stdout.
No OS proxy settings or trust-store certificates are changed.

## Windows development (PowerShell)

From this directory with Node.js 22+ installed:

```powershell
npm install --ignore-scripts
npm test
$env:NETVERGE_MIHOMO_PORT = "7897" # use the actual live mixed port
$env:NETVERGE_HTTP_PORT = "8899"
$env:NETVERGE_HTTP_DATA = Join-Path $env:LOCALAPPDATA "NetVerge-http-dev"
npm start
```

Use the explicit proxy for authorized test traffic; do not turn on TUN for this prototype.
Whistle UI: http://127.0.0.1:8899. Stop the foreground process with Ctrl+C.
Optional NETVERGE_HTTP_RULES points to a trusted local Whistle rule file.
The default upstream rule is a fallback, not an enforced egress policy: other
Whistle rules can change routing. Do not use it as a security boundary.

The smoke test uses a loopback stand-in for Mihomo and an invalid test domain to
check the rewrite and upstream path without depending on an external service.
HTTPS CONNECT, selective TLS interception, real Mihomo integration and Windows
packaging require separate verification. Do not install a CA until explicitly
enabled by the user. Keep the data directory private.

## Desktop integration boundary

- Use the existing MixedPort::effective() resolver and the existing system-proxy
  owner, rather than a second OS proxy writer.
- Bundle a pinned Node runtime and a locked Whistle dependency tree before release.
- Start and verify the sidecar before switching the system proxy. Restore the
  previous working target before stopping it; reconcile crashes and mixed-port changes.
- Keep TUN integration out of the first system-proxy milestone until loop
  prevention and DNS behavior are verified.
- Do not ship with the upstream updater identity or signing configuration.
