# NetVerge custom core integration (development only)

Upstream: MetaCubeX/mihomo @ 0455d0d28c4526937380505153e65a843d8612e8. CI builds a separate executable; it is not the desktop's distributed core. No test fixtures are linked into the binary.

The core controller is disabled unless NETVERGE_CORE_CONTROL_PORT (1024..65535) and NETVERGE_CORE_CONTROL_SECRET (32 base64url characters from 24 random bytes) are provided at process launch. Both are consumed from the environment. Bind is fixed to 127.0.0.1. Use Authorization: Bearer <core secret>, exact local Host, and no Origin header. No subscription or external Mihomo API can enable it.

| Method | Path | Behavior |
|---|---|---|
| GET | /v1/mitm | protocol, enabled, hosts; no secrets |
| PUT | /v1/mitm | JSON hosts (exact lowercase DNS names), workerPort (loopback only), workerSecret (independent 32-character secret); ready worker must authorize every host |
| DELETE | /v1/mitm | disables handoff and cancels prior generation |

PUT returns 204 on success; 503 if worker readiness fails (previous generation unchanged). Authentication failures return 401. An enabled status means a generation was configured, not continuous worker health. Keep all launch settings and control secrets local to the desktop supervisor. This development core is not intended for installation or production traffic yet. The worker supports only one decrypted request per lease and bounded lifetime. Only native TCP/443 TUN traffic and the explicitly admitted adapter types are handled. No automatic certificate trust, updater change, Linux build or UI integration.

Workflow netverge-custom-core.yml uploads the versioned binary as an Actions artifact after smoke tests; netverge-route-lease-lab.yml verifies the real worker/controller combination and protocol regressions.
