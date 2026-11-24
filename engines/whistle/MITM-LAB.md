# Isolated MITM experiment

This experiment tests the proposed Mihomo-first TCP/CONNECT topology before enabling TUN. It does not integrate with the Tauri application, install a system certificate, change a system proxy, or use a public target.

- Mihomo entry: ordinary HTTP CONNECT proxy, not TUN.
- Authorized target: mitm.netverge.test, mapped to a temporary loopback HTTPS server.
- Bypass: bypass.netverge.test, mapped to the same server.
- Whistle: loopback-only, shadow rules, WebUI disabled, no external plugins, global HTTPS capture disabled, strict upstream TLS mode.
- Return: named Mihomo HTTP inbound, matching only the authorized test domain and rejecting other traffic.
- Trust: temporary origin CA used by the Whistle child; temporary Whistle CA used only by the test client. No OS trust changes.

Prerequisites: Node.js 22+, npm, a trusted actual Mihomo binary. In this directory:

```powershell
npm install --ignore-scripts
$env:NETVERGE_MIHOMO_BIN = "C:\path\to\mihomo.exe"
npm run test:mitm
```

A pass requires the origin response on both routes, the original TLS certificate on the bypass route, a different verified certificate issued by Whistle on the selected route, and an observed decrypted URL/method. The named return listener is separately probed. Test subprocesses and temporary certificate/config files are cleaned up.

This remains a hypothesis until the experiment actually passes. TUN capture, original process rule semantics, arbitrary proxy groups, QUIC, invalid upstream certificate rejection, and failure recovery are separate tests. The fixture uses a dedicated local Mihomo configuration and does not touch the user's existing configuration.

## First CI failure and next experiment

Windows and Linux both reached the named return listener but received an IP-based CONNECT and REJECT. Mihomo v1.19.34's tunnel/tunnel.go uses Metadata.Pure() for static hosts, stripping the hostname before the outbound handshake. Replace the static hosts fixture with an isolated UDP DNS server, preserve strict domain-based return routing, and log the actual Whistle CONNECT authority. This is a fixture correction, not a production DNS policy or proof of TUN compatibility.

## macOS (Intel and Apple Silicon)

The same isolated CONNECT test runs on both macOS architectures without sudo or changes to Keychain, system proxy, or TUN. Use Node.js 22+ and a trusted native Mihomo executable:

```sh
npm install --ignore-scripts
NETVERGE_MIHOMO_BIN="/absolute/path/to/mihomo" npm run test:mitm
```

CI downloads the pinned v1.19.34 binaries, verifies their SHA-256 hashes, and selects the architecture using uname. This is not a test of macOS TUN or installation of a trusted system CA. The user's existing network tooling should be left untouched.
