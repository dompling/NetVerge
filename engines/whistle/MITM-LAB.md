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

## Actual TUN lab (Linux only)

The CONNECT experiment passed on Windows, Ubuntu and both macOS architectures in run [45317061236](https://github.com/dompling/NetVerge/actions/runs/45317061236). The new TUN experiment is independent of that result.

On a disposable Linux machine or GitHub runner, after installing dependencies and setting NETVERGE_MIHOMO_BIN, run:

```sh
sudo modprobe tun || test -c /dev/net/tun
sudo env "PATH=$PATH" "NETVERGE_MIHOMO_BIN=$NETVERGE_MIHOMO_BIN" "NETVERGE_TUN_LAB_HOST_NS=$(readlink /proc/self/ns/net)" unshare --net -- bash -euc 'ip link set lo up; node mitm-lab.cjs --tun'
```

The namespace has no default route. Mihomo creates a gVisor TUN device; the test installs only the lab fake-IP range route inside the namespace. The test DNS client explicitly queries Mihomo's local fake-IP DNS listener. The TLS client then connects directly to the fake IP with the original SNI, without HTTP proxy settings. It verifies the actual route points at the TUN device and compares the TLS peer certificates of selected and bypass domains, the origin response, decrypted URL and CONNECT authority. The named return inbound prevents the selected request from re-entering the MITM rule. The namespace is destroyed on exit. No system certificate is installed.

Scope: this verifies real TUN packets and fake-IP domain recovery, not automatic platform routing, DNS hijack, redir-host, actual VPN coexistence, or arbitrary production rules. Windows/macOS TUN and desktop integration remain unverified. The test fails rather than silently falling back to CONNECT when TUN is unavailable.
