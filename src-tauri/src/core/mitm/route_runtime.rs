//! Original-route MITM development adapter. Reuses the existing process,
//! CA verification, health snapshots, and generation-scoped recovery budget.
//! It does not reopen the legacy YAML overlay or expose a product UI switch.
use super::{Health, MitmPublicCa, PUBLIC_STATE, PublicState, RecoveryBudget, MAX_RECOVERY_ATTEMPTS, valid_host};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Child,
    time::{Duration, Instant},
};

const ENV: &str = "NETVERGE_MITM_ROUTE_DEV_CONFIG";
const API: &str = "/v1/mitm";
static ROUTE: Mutex<Option<RouteSession>> = Mutex::new(None);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct LocalSettings {
    node: PathBuf,
    worker: PathBuf,
    hosts: Vec<String>,
}

pub(crate) struct Launch {
    settings: LocalSettings,
    core_port: u16,
    worker_port: u16,
    core_secret: String,
    worker_secret: String,
    data: PathBuf,
}

impl Launch {
    pub(crate) const fn port(&self) -> u16 { self.core_port }
    pub(crate) fn secret(&self) -> &str { &self.core_secret }
}

pub(super) fn requested() -> bool {
    std::env::var_os(ENV).is_some()
}

fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("MITM random source unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn read_settings(path: &Path) -> Result<LocalSettings> {
    ensure!(path.is_absolute(), "original-route MITM development config must be absolute");
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(metadata.is_file() && metadata.len() <= 65536, "invalid original-route local configuration");
    let mut raw = Vec::new();
    std::fs::File::open(path)?.take(65537).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 65536, "original-route configuration too large");
    let settings: LocalSettings = serde_yaml_ng::from_slice(&raw).context("invalid original-route configuration")?;
    validate(&settings)?;
    Ok(settings)
}

fn validate(s: &LocalSettings) -> Result<()> {
    ensure!(s.node.is_absolute() && s.worker.is_absolute() && s.node.is_file() && s.worker.is_file(), "MITM Node and worker must be existing absolute files");
    ensure!(s.worker.file_name().is_some_and(|name| name == "route-worker.cjs"), "original-route worker required");
    ensure!(!s.hosts.is_empty() && s.hosts.len() <= 64 && s.hosts.iter().all(|h| valid_host(h)), "invalid original-route hostnames");
    ensure!(s.hosts.iter().collect::<BTreeSet<_>>().len() == s.hosts.len(), "duplicate original-route hostname");
    Ok(())
}

pub(crate) async fn prepare_sidecar() -> Result<Option<Launch>> {
    let Some(path) = std::env::var_os(ENV) else { return Ok(None); };
    ensure!(cfg!(windows), "original-route sidecar development is currently Windows only");
    ensure!(crate::core::runstate::RUN_STATE.state().is_admin, "original-route MITM requires an elevated TUN-capable sidecar");
    let runtime = crate::config::Config::runtime().await.latest_arc();
    let config = runtime.config.as_ref().context("original-route MITM requires a runtime profile")?;
    ensure!(super::enabled_block(config, "tun"), "original-route MITM requires TUN");
    ensure!(config.get("mode").and_then(serde_yaml_ng::Value::as_str).is_none_or(|mode| mode.eq_ignore_ascii_case("rule")), "original-route MITM requires rule mode");
    drop(runtime);
    tokio::task::spawn_blocking(move || {
        let settings = read_settings(&PathBuf::from(path))?;
        let core = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let worker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let launch = Launch {
            settings, core_port: core.local_addr()?.port(), worker_port: worker.local_addr()?.port(),
            core_secret: random_secret()?, worker_secret: random_secret()?,
            data: crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev"),
        };
        // Release the reservations immediately before the sidecar launch.
        // The subsequent authenticated readiness probes detect port races.
        Ok(Some(launch))
    }).await?
}

#[derive(Deserialize)]
struct CoreState {
    protocol: u32,
    enabled: bool,
    hosts: Vec<String>,
}
#[derive(Deserialize)]
struct WorkerState {
    protocol: u32,
    hosts: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Apply<'a> {
    hosts: &'a [String],
    worker_port: u16,
    worker_secret: &'a str,
}

// Same bounded direct loopback HTTP transport as the existing local health
// probe. No proxy environment, redirects, DNS or external URL is involved.
// The pinned Go and Node endpoints return short Content-Length responses.
fn request(port: u16, method: &str, path: &str, auth_name: &str, auth: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_secs(2))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth_name}: {auth}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(body)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut response = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "MITM control timeout");
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut buffer)?;
        if n == 0 { break; }
        response.extend_from_slice(&buffer[..n]);
        ensure!(response.len() <= 65536, "MITM control response too large");
    }
    let separator = response.windows(4).position(|w| w == b"\r\n\r\n").context("invalid MITM control response")?;
    let headers = std::str::from_utf8(&response[..separator])?;
    let mut lines = headers.lines();
    let status = lines.next().context("missing MITM status")?;
    ensure!(status.starts_with("HTTP/1.1 ") || status.starts_with("HTTP/1.0 "), "invalid MITM HTTP status");
    let code = status.split_whitespace().nth(1).context("missing MITM status code")?.parse::<u16>()?;
    ensure!(!lines.any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:")), "unsupported MITM response framing");
    Ok((code, response[separator + 4..].to_vec()))
}

impl Launch {
    fn core(&self, method: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        request(self.core_port, method, API, "Authorization", &format!("Bearer {}", self.core_secret), body)
    }

    fn core_state(&self) -> Result<CoreState> {
        let (code, body) = self.core("GET", &[])?;
        ensure!(code == 200, "custom Mihomo controller authentication failed");
        let state: CoreState = serde_json::from_slice(&body)?;
        ensure!(state.protocol == 1, "custom Mihomo controller protocol mismatch");
        Ok(state)
    }

    fn worker_ready(&self) -> Result<()> {
        let auth = format!("Basic {}", STANDARD.encode(format!("netverge:{}", self.worker_secret)));
        let (code, body) = request(self.worker_port, "GET", "/__netverge_routes", "Proxy-Authorization", &auth, &[])?;
        ensure!(code == 200, "original-route worker authentication failed");
        let state: WorkerState = serde_json::from_slice(&body)?;
        ensure!(state.protocol == 1 && same_hosts(&state.hosts, &self.settings.hosts), "original-route worker scope mismatch");
        Ok(())
    }

    fn apply(&self) -> Result<()> {
        let body = serde_json::to_vec(&Apply { hosts: &self.settings.hosts, worker_port: self.worker_port, worker_secret: &self.worker_secret })?;
        ensure!(self.core("PUT", &body)?.0 == 204, "custom Mihomo refused MITM activation");
        self.verify()
    }

    fn verify(&self) -> Result<()> {
        self.worker_ready()?;
        let state = self.core_state()?;
        ensure!(state.enabled && same_hosts(&state.hosts, &self.settings.hosts), "original-route core configuration mismatch");
        Ok(())
    }
}

fn same_hosts(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().collect::<BTreeSet<_>>() == b.iter().collect::<BTreeSet<_>>()
}

struct RouteSession {
    launch: Launch,
    child: Option<Child>,
    ca: Option<MitmPublicCa>,
    recovery: RecoveryBudget,
}

impl RouteSession {
    fn publish(&self, health: Health) {
        *PUBLIC_STATE.lock() = PublicState {
            health, generation: self.recovery.generation, attempts: self.recovery.attempts, ca: self.ca.clone(),
        };
    }

    fn start(&mut self) -> Result<()> {
        let payload = serde_json::json!({
            "dataDir": self.launch.data, "port": self.launch.worker_port,
            "hosts": self.launch.settings.hosts, "targetPort": 443, "controlSecret": self.launch.worker_secret
        });
        let (mut child, ca) = super::start_worker_payload(&self.launch.settings.node, &self.launch.settings.worker, &self.launch.data, &payload)?;
        if self.ca.as_ref().is_some_and(|old| old.sha256_fingerprint != ca.sha256_fingerprint) {
            super::stop(&mut child);
            anyhow::bail!("original-route worker CA changed");
        }
        if self.launch.worker_ready().is_err() {
            super::stop(&mut child);
            anyhow::bail!("original-route worker failed authenticated readiness");
        }
        self.ca = Some(ca);
        self.child = Some(child);
        Ok(())
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            super::stop(&mut child);
        }
    }

    fn recover(&mut self, generation: u64) {
        if self.recovery.generation != Some(generation) {
            self.stop();
            self.publish(Health::Degraded);
            return;
        }
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(None) => {
                    self.publish(if self.launch.verify().is_ok() { Health::LocalLinkHealthy } else { Health::Degraded });
                    return;
                }
                Ok(Some(_)) => self.child = None,
                Err(_) => { self.publish(Health::Degraded); return; }
            }
        }
        if !self.recovery.claim(generation) {
            self.publish(Health::Failed);
            return;
        }
        self.publish(Health::Recovering);
        // Same port, same worker secret, same CA: the original core
        // generation stays configured while the child is unavailable.
        if self.start().is_ok() && self.launch.verify().is_ok() {
            self.publish(Health::LocalLinkHealthy);
        } else {
            self.stop();
            self.publish(if self.recovery.attempts >= MAX_RECOVERY_ATTEMPTS { Health::Failed } else { Health::Degraded });
        }
    }
}

pub(crate) async fn activate(launch: Launch, generation: u64) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut guard = ROUTE.lock();
        ensure!(guard.is_none(), "original-route session already active");
        let mut session = RouteSession { launch, child: None, ca: None, recovery: RecoveryBudget::default() };
        session.recovery.activate(generation);
        session.publish(Health::Checking);
        let result = (|| {
            let state = session.launch.core_state()?;
            ensure!(!state.enabled, "new custom core must start with MITM disabled");
            session.start()?;
            session.launch.apply()
        })();
        if result.is_err() {
            session.stop();
            session.publish(Health::Failed);
            // The caller terminates this unready sidecar, including any
            // ambiguous PUT outcome. No stock-core fallback is introduced.
            return result;
        }
        session.publish(Health::LocalLinkHealthy);
        *guard = Some(session);
        Ok(())
    }).await??;
    super::start_monitor();
    Ok(())
}

pub(super) async fn monitor(generation: u64) -> bool {
    tokio::task::spawn_blocking(move || {
        let mut guard = ROUTE.lock();
        let Some(session) = guard.as_mut() else { return false; };
        session.recover(generation);
        true
    }).await.unwrap_or(false)
}

// Existing CoreManager invokes this after the associated core exits.
pub(super) async fn stop_worker() {
    let _ = tokio::task::spawn_blocking(|| {
        if let Some(mut session) = ROUTE.lock().take() {
            session.stop();
            *PUBLIC_STATE.lock() = PublicState { health: Health::Inactive, generation: None, attempts: 0, ca: session.ca };
        }
    }).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    #[test]
    fn original_route_settings_exclude_fixed_policy() -> Result<()> {
        let path = std::env::current_exe()?;
        let config = serde_json::json!({"node": path, "worker": path, "hosts": ["api.example.test"], "policy": "DIRECT"});
        assert!(serde_json::from_value::<LocalSettings>(config).is_err());
        assert!(same_hosts(&["a.test".into(), "b.test".into()], &["b.test".into(), "a.test".into()]));
        assert!(!same_hosts(&["a.test".into()], &["b.test".into()]));
        let secret = random_secret()?;
        assert_eq!(URL_SAFE_NO_PAD.decode(secret)?.len(), 24);
        Ok(())
    }

    #[test]
    fn original_route_control_uses_direct_authenticated_http() -> Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let server = std::thread::spawn(move || -> Result<()> {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut reader = BufReader::new(&mut socket);
            let mut lines = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line)? == 0 || line == "\r\n" { break; }
                lines.push_str(&line);
            }
            assert!(lines.starts_with("GET /v1/mitm HTTP/1.1\r\n"));
            assert!(lines.contains("Authorization: Bearer sample\r\n"));
            assert!(lines.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
            let body = r#"{"protocol":1,"enabled":false,"hosts":[]}"#;
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
            Ok(())
        });
        let (status, body) = request(port, "GET", API, "Authorization", "Bearer sample", &[])?;
        let state: CoreState = serde_json::from_slice(&body)?;
        assert_eq!(status, 200);
        assert_eq!(state.protocol, 1);
        assert!(!state.enabled);
        server.join().map_err(|_| anyhow::anyhow!("test server panicked"))??;
        Ok(())
    }
}
