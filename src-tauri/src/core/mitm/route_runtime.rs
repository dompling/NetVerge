//! Original-route MITM development adapter. Reuses the existing process,
//! CA verification, health snapshots, and generation-scoped recovery budget.
//! It does not reopen the legacy YAML overlay or ordinary product activation.
use super::{Health, MitmPublicCa, MitmSettings, PUBLIC_STATE, PublicState, RecoveryBudget, MAX_RECOVERY_ATTEMPTS, valid_host, controller_state::{CoreState, same_hosts}};
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
const SELECTION_FILE: &str = "route-selection.yaml";
static ROUTE: Mutex<Option<RouteSession>> = Mutex::new(None);
#[cfg(all(windows, feature = "verge-dev"))]
pub(crate) mod installed_service;

static SERVICE_FAILURE: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn service_requested() -> bool {
    #[cfg(all(windows, feature = "verge-dev"))]
    return installed_service::requested();
    #[cfg(not(all(windows, feature = "verge-dev")))]
    false
}

pub(super) fn service_preference() -> Option<bool> {
    #[cfg(all(windows, feature = "verge-dev"))]
    return installed_service::next_start();
    #[cfg(not(all(windows, feature = "verge-dev")))]
    None
}

pub(crate) async fn set_service_preference(enabled: bool) -> Result<()> {
    #[cfg(all(windows, feature = "verge-dev"))]
    return installed_service::set_next_start(enabled).await;
    #[cfg(not(all(windows, feature = "verge-dev")))]
    {
        let _ = enabled;
        anyhow::bail!("guarded MITM service mode requires a NetVerge Windows development build")
    }
}

pub(super) fn service_failure() -> Option<String> {
    SERVICE_FAILURE.lock().clone()
}

pub(crate) fn report_service_failure(error: &anyhow::Error) {
    *SERVICE_FAILURE.lock() = Some(format!("{error:#}"));
    PUBLIC_STATE.lock().health = Health::Failed;
}

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
    bootstrap_sha256: String,
    restore_enabled: bool,
    expected_ca: Option<String>,
}

impl Launch {
    pub(crate) const fn port(&self) -> u16 { self.core_port }
    pub(crate) fn secret(&self) -> &str { &self.core_secret }
}

pub(crate) fn requested() -> bool {
    std::env::var_os(ENV).is_some()
}

fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("MITM random source unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn read_settings(path: &Path) -> Result<(LocalSettings, String)> {
    ensure!(path.is_absolute(), "original-route MITM development config must be absolute");
    let raw = super::settings::read_bounded(path)?;
    let settings: LocalSettings = serde_yaml_ng::from_slice(&raw).context("invalid original-route configuration")?;
    validate(&settings)?;
    Ok((settings, super::settings::digest(&raw)))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SavedRoute {
    version: u32,
    bootstrap_sha256: String,
    pending: bool,
    enable: bool,
    hosts: Vec<String>,
    ca_fingerprint: Option<String>,
}

impl SavedRoute {
    fn selection(&self) -> MitmSettings {
        MitmSettings { enable: self.enable, hostname: self.hosts.clone(), policy: None }
    }

    fn validate(&self, bootstrap: &str) -> Result<()> {
        ensure!(self.version == 1 && self.bootstrap_sha256 == bootstrap, "MITM bootstrap changed; review the saved original-route selection");
        ensure!(!self.pending, "MITM selection has an incomplete transaction; review the private local selection before restarting");
        validate_candidate(&self.selection())?;
        if let Some(fingerprint) = &self.ca_fingerprint {
            ensure!(fingerprint.len() == 64 && fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid saved MITM CA fingerprint");
        }
        ensure!(!self.enable || self.ca_fingerprint.is_some(), "enabled MITM selection has no verified CA fingerprint");
        Ok(())
    }
}

fn decode_saved(raw: &[u8], bootstrap: &str) -> Result<SavedRoute> {
    let saved: SavedRoute = serde_yaml_ng::from_slice(raw).context("invalid saved original-route selection")?;
    saved.validate(bootstrap)?;
    Ok(saved)
}

fn read_saved(data: &Path, bootstrap: &str) -> Result<Option<SavedRoute>> {
    let path = data.join(SELECTION_FILE);
    match super::settings::read_bounded(&path) {
        Ok(raw) => Ok(Some(decode_saved(&raw, bootstrap)?)),
        Err(err) if err.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => Ok(None),
        Err(err) => Err(err),
    }
}

fn private_data(data: &Path) -> Result<()> {
    std::fs::create_dir_all(data)?;
    ensure!(std::fs::symlink_metadata(data)?.is_dir(), "MITM private data directory must not be a symbolic link");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn write_saved(data: &Path, saved: &SavedRoute) -> Result<()> {
    private_data(data)?;
    let yaml = serde_yaml_ng::to_string(saved)?;
    ensure!(yaml.len() <= 65536, "MITM selection exceeds size limit");
    crate::utils::help::save_yaml_str_private(&data.join(SELECTION_FILE), &yaml, Some("# NetVerge original-route MITM local selection; never imported from a profile")).await
}

fn validate(s: &LocalSettings) -> Result<()> {
    ensure!(s.node.is_absolute() && s.worker.is_absolute() && s.node.is_file() && s.worker.is_file(), "MITM Node and worker must be existing absolute files");
    ensure!(s.worker.file_name().is_some_and(|name| name == "route-worker.cjs"), "original-route worker required");
    ensure!(s.hosts.len() <= 64 && s.hosts.iter().all(|h| valid_host(h)), "invalid original-route hostnames");
    ensure!(s.hosts.iter().collect::<BTreeSet<_>>().len() == s.hosts.len(), "duplicate original-route hostname");
    Ok(())
}

pub(crate) async fn prepare_sidecar() -> Result<Option<Launch>> {
    let Some(path) = std::env::var_os(ENV) else { return Ok(None); };
    ensure!(cfg!(windows), "original-route sidecar development is currently Windows only");
    ensure!(crate::core::runstate::RUN_STATE.state().is_admin, "original-route MITM requires an elevated TUN-capable sidecar");
    Ok(Some(prepare_launch(PathBuf::from(path), false).await?))
}

async fn prepare_launch(path: PathBuf, require_committed: bool) -> Result<Launch> {
    let runtime = crate::config::Config::runtime().await.latest_arc();
    let config = runtime.config.as_ref().context("original-route MITM requires a runtime profile")?;
    require_tun_rule(config)?;
    drop(runtime);
    tokio::task::spawn_blocking(move || {
        let (mut settings, bootstrap_sha256) = read_settings(&path)?;
        let data = crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev");
        private_data(&data)?;
        let saved = read_saved(&data, &bootstrap_sha256)?;
        ensure!(!require_committed || saved.is_some(), "save an explicit MITM selection before starting the guarded service");
        let restore_enabled = saved.as_ref().is_some_and(|s| s.enable);
        let expected_ca = saved.as_ref().and_then(|s| s.ca_fingerprint.clone());
        if let Some(saved) = saved {
            settings.hosts = saved.hosts;
        }
        let core = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let worker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let launch = Launch {
            settings, core_port: core.local_addr()?.port(), worker_port: worker.local_addr()?.port(),
            core_secret: random_secret()?, worker_secret: random_secret()?,
            data, bootstrap_sha256, restore_enabled, expected_ca,
        };
        // Release the reservations immediately before the sidecar launch.
        // The subsequent authenticated readiness probes detect port races.
        Ok(launch)
    }).await?
}

static REWRITE_HITS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);
pub(crate) fn response_header_hits() -> Option<u32> {
    let value = REWRITE_HITS.load(std::sync::atomic::Ordering::Relaxed);
    (value != u32::MAX && matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy)).then_some(value)
}

static REQUEST_REWRITE_HITS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);
pub(crate) fn request_header_hits() -> Option<u32> {
    let value = REQUEST_REWRITE_HITS.load(std::sync::atomic::Ordering::Relaxed);
    (value != u32::MAX && matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy)).then_some(value)
}

static PATH_HITS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);
pub(crate) fn url_path_hits() -> Option<u32> {
    let value = PATH_HITS.load(std::sync::atomic::Ordering::Relaxed);
    (value != u32::MAX && matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy)).then_some(value)
}

static BODY_HITS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);
pub(crate) fn response_body_hits() -> Option<u32> {
    let value = BODY_HITS.load(std::sync::atomic::Ordering::Relaxed);
    (value != u32::MAX && matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy)).then_some(value)
}

#[derive(Clone, Deserialize, serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RecentRequest {
    id: u32,
    method: String,
    host: String,
    path: String,
    request_rule: bool,
    response_rule: bool,
    path_rule: bool,
    body_rule: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    local_rule: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    matched_rule_ids: Option<Vec<String>>,
    status: u16,
    completed_at: String,
    duration_ms: u32,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
}

#[derive(Clone, Deserialize, serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RewritePhaseDiagnostic {
    phase: String,
    revision: u32,
    active_rules: u32,
    error: Option<String>,
    rule_hits: std::collections::BTreeMap<String, u32>,
}

static RECENT_REQUESTS: Mutex<Vec<RecentRequest>> = Mutex::new(Vec::new());
static REWRITE_DIAGNOSTICS: Mutex<Vec<RewritePhaseDiagnostic>> = Mutex::new(Vec::new());
static ACTIVE_WORKER: Mutex<Option<(u16, String)>> = Mutex::new(None);
static CLEAR_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn recent_requests() -> Vec<RecentRequest> {
    if matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy) {
        return RECENT_REQUESTS.lock().clone();
    }
    Vec::new()
}

pub(crate) fn rewrite_diagnostics() -> Vec<RewritePhaseDiagnostic> {
    if matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy) {
        return REWRITE_DIAGNOSTICS.lock().clone();
    }
    Vec::new()
}

pub(crate) async fn clear_recent_requests() -> Result<()> {
    ensure!(matches!(PUBLIC_STATE.lock().health, Health::LocalLinkHealthy), "MITM worker is unavailable");
    let (port, secret) = ACTIVE_WORKER.lock().clone().context("MITM worker is unavailable")?;
    tokio::task::spawn_blocking(move || {
        CLEAR_EPOCH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let auth = format!("Basic {}", STANDARD.encode(format!("netverge:{secret}")));
        let (code, _) = request(port, "DELETE", "/__netverge_recent_requests", "Proxy-Authorization", &auth, &[])?;
        ensure!(code == 204, "MITM worker refused clearing recent requests");
        CLEAR_EPOCH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        RECENT_REQUESTS.lock().clear();
        Ok(())
    }).await?
}

#[derive(Deserialize)]
struct WorkerState {
    #[serde(default, rename = "rewriteHits")]
    rewrite_hits: Option<u32>,
    #[serde(default, rename = "requestRewriteHits")]
    request_rewrite_hits: Option<u32>,
    #[serde(default, rename = "pathHits")]
    path_hits: Option<u32>,
    #[serde(default, rename = "bodyHits")]
    body_hits: Option<u32>,
    #[serde(default)]
    diagnostics: Vec<RewritePhaseDiagnostic>,
    #[serde(default, rename = "recentRequests")]
    recent_requests: Vec<RecentRequest>,
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
        ensure!(n != 0, "MITM control response ended before declared body");
        response.extend_from_slice(&buffer[..n]);
        if let Some((status, body)) = super::control_http::complete(&response)? {
            return Ok((status, body.to_vec()));
        }
    }
}

impl Launch {
    fn core(&self, method: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        request(self.core_port, method, API, "Authorization", &format!("Bearer {}", self.core_secret), body)
    }

    fn core_state(&self) -> Result<CoreState> {
        let (code, body) = self.core("GET", &[])?;
        ensure!(code == 200, "custom Mihomo controller authentication failed");
        let state: CoreState = serde_json::from_slice(&body)?;
        state.verify_protocol()?;
        Ok(state)
    }

    fn worker_ready(&self) -> Result<()> {
        let epoch = CLEAR_EPOCH.load(std::sync::atomic::Ordering::Acquire);
        let auth = format!("Basic {}", STANDARD.encode(format!("netverge:{}", self.worker_secret)));
        let (code, body) = request(self.worker_port, "GET", "/__netverge_routes", "Proxy-Authorization", &auth, &[])?;
        ensure!(code == 200, "original-route worker authentication failed");
        let state: WorkerState = serde_json::from_slice(&body)?;
        ensure!(state.protocol == 1 && same_hosts(&state.hosts, &self.settings.hosts), "original-route worker scope mismatch");
        if CLEAR_EPOCH.load(std::sync::atomic::Ordering::Acquire) == epoch {
            *RECENT_REQUESTS.lock() = state.recent_requests;
        }
        *REWRITE_DIAGNOSTICS.lock() = state.diagnostics;
        BODY_HITS.store(state.body_hits.unwrap_or(u32::MAX), std::sync::atomic::Ordering::Relaxed);
        PATH_HITS.store(state.path_hits.unwrap_or(u32::MAX), std::sync::atomic::Ordering::Relaxed);
        REQUEST_REWRITE_HITS.store(state.request_rewrite_hits.unwrap_or(u32::MAX), std::sync::atomic::Ordering::Relaxed);
        REWRITE_HITS.store(state.rewrite_hits.unwrap_or(u32::MAX), std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn apply(&self) -> Result<()> {
        let body = serde_json::to_vec(&Apply { hosts: &self.settings.hosts, worker_port: self.worker_port, worker_secret: &self.worker_secret })?;
        ensure!(self.core("PUT", &body)?.0 == 204, "custom Mihomo refused MITM activation");
        self.verify()
    }

    fn disable(&self) -> Result<()> {
        ensure!(self.core("DELETE", &[])?.0 == 204, "custom Mihomo refused MITM disable");
        self.verify_disabled()
    }

    fn verify_disabled(&self) -> Result<()> {
        self.core_state()?.verify_selection(false, &[])
    }

    fn verify(&self) -> Result<()> {
        self.worker_ready()?;
        self.core_state()?.verify_selection(true, &self.settings.hosts)
    }
}

struct RouteSession {
    launch: Launch,
    child: Option<Child>,
    ca: Option<MitmPublicCa>,
    recovery: RecoveryBudget,
    enabled: bool,
    revision: String,
}

impl RouteSession {
    fn selection(&self) -> MitmSettings {
        MitmSettings { enable: self.enabled, hostname: self.launch.settings.hosts.clone(), policy: None }
    }

    fn saved(&self, selection: &MitmSettings, pending: bool) -> SavedRoute {
        SavedRoute {
            version: 1,
            bootstrap_sha256: self.launch.bootstrap_sha256.clone(),
            pending,
            enable: selection.enable,
            hosts: selection.hostname.clone(),
            ca_fingerprint: self.ca.as_ref().map(|ca| ca.sha256_fingerprint.clone()).or_else(|| self.launch.expected_ca.clone()),
        }
    }

    fn change(&mut self, candidate: MitmSettings) -> Result<()> {
        validate_candidate(&candidate)?;
        if candidate == self.selection() { return Ok(()); }
        let revision = random_secret()?;
        if !candidate.enable {
            // Only stop the worker after verified core disable.
            if let Err(error) = self.launch.disable() {
                self.publish(Health::Degraded);
                return Err(error);
            }
            self.stop();
            self.enabled = false;
            self.launch.settings.hosts = candidate.hostname;
            self.revision = revision;
            self.recovery.attempts = 0;
            self.publish(Health::Inactive);
            return Ok(());
        }
        let previous = self.selection();
        self.publish(Health::Checking);
        // Keep the old core generation configured during worker replacement.
        // Reuse its local data directory only after the old child has exited.
        self.stop();
        self.launch.settings.hosts = candidate.hostname;
        let result = self.start().and_then(|()| self.launch.apply());
        if result.is_ok() {
            self.enabled = true;
            self.revision = revision;
            self.recovery.attempts = 0;
            self.publish(Health::LocalLinkHealthy);
            return Ok(());
        }
        self.stop();
        self.launch.settings.hosts = previous.hostname;
        self.enabled = previous.enable;
        self.recovery.attempts = 0;
        let restored = if previous.enable {
            self.start().and_then(|()| self.launch.apply())
        } else {
            self.launch.disable()
        };
        if restored.is_ok() {
            self.publish(if self.enabled { Health::LocalLinkHealthy } else { Health::Inactive });
        } else {
            self.stop();
            self.publish(Health::Degraded);
        }
        anyhow::bail!("MITM change failed; previous configuration retained or recovery required")
    }

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
        if self.ca.as_ref().is_some_and(|old| old.sha256_fingerprint != ca.sha256_fingerprint)
            || self.launch.expected_ca.as_ref().is_some_and(|old| old != &ca.sha256_fingerprint) {
            super::stop(&mut child);
            anyhow::bail!("original-route worker CA changed");
        }
        if self.launch.worker_ready().is_err() {
            super::stop(&mut child);
            anyhow::bail!("original-route worker failed authenticated readiness");
        }
        self.launch.expected_ca = Some(ca.sha256_fingerprint.clone());
        self.ca = Some(ca);
        self.child = Some(child);
        *ACTIVE_WORKER.lock() = Some((self.launch.worker_port, self.launch.worker_secret.clone()));
        Ok(())
    }

    fn stop(&mut self) {
        *ACTIVE_WORKER.lock() = None;
        RECENT_REQUESTS.lock().clear();
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
        if !self.enabled {
            let healthy = self.launch.verify_disabled().or_else(|_| self.launch.disable()).is_ok();
            self.publish(if healthy { Health::Inactive } else { Health::Degraded });
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
        if self.start().is_ok() && self.launch.apply().is_ok() {
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
        let mut session = RouteSession { launch, child: None, ca: None, recovery: RecoveryBudget::default(), enabled: false, revision: random_secret()? };
        session.recovery.activate(generation);
        session.publish(Health::Checking);
        let result = (|| {
            // An ordinary sidecar must be confirmed disabled, not an
            // uncommitted service-style generation.
            session.launch.verify_disabled()?;
            if session.launch.restore_enabled {
                let selection = MitmSettings { enable: true, hostname: session.launch.settings.hosts.clone(), policy: None };
                session.change(selection)?;
            }
            Ok(())
        })();
        if result.is_err() {
            session.stop();
            session.publish(Health::Failed);
            // The caller terminates this unready sidecar, including any
            // ambiguous PUT outcome. No stock-core fallback is introduced.
            return result;
        }
        session.publish(if session.enabled { Health::LocalLinkHealthy } else { Health::Inactive });
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

// The existing IPC shape is retained, including policy:null for compatibility.
fn validate_candidate(candidate: &MitmSettings) -> Result<()> {
    ensure!(candidate.policy.is_none(), "MITM always uses original routing");
    ensure!(candidate.hostname.len() <= 64 && candidate.hostname.iter().all(|h| valid_host(h)), "invalid MITM hostnames");
    ensure!(candidate.hostname.iter().collect::<BTreeSet<_>>().len() == candidate.hostname.len(), "duplicate MITM hostname");
    ensure!(!candidate.enable || !candidate.hostname.is_empty(), "enabled MITM requires a hostname");
    Ok(())
}

pub(super) async fn configured_hostnames() -> Result<Vec<String>> {
    #[cfg(all(windows, feature = "verge-dev"))]
    if service_requested() {
        return Ok(installed_service::configured_hostnames().await);
    }
    Ok(inspect().await?.map_or_else(Vec::new, |(selection, _)| selection.hostname))
}

pub(super) async fn inspect() -> Result<Option<(MitmSettings, String)>> {
    let current = crate::core::CoreManager::global().current_core_readiness_generation();
    tokio::task::spawn_blocking(move || {
        let guard = ROUTE.lock();
        Ok(guard.as_ref().filter(|s| s.recovery.generation == current && current.is_some()).map(|s| (s.selection(), s.revision.clone())))
    }).await?
}

pub(super) async fn save(expected: String, candidate: MitmSettings) -> Result<Option<(MitmSettings, String)>> {
    validate_candidate(&candidate)?;
    let (previous, revision) = inspect().await?.context("original-route development core is unavailable")?;
    ensure!(expected == revision, "MITM configuration changed; refresh first");
    if candidate.enable && candidate != previous {
        let answer = rfd::AsyncMessageDialog::new()
            .set_title("Enable or update NetVerge MITM")
            .set_description(format!("Decrypt HTTPS for these exact hostnames?\n\n{}\n\nOriginal routing is preserved. Existing selected connections may be interrupted. Certificate trust is not installed automatically.", candidate.hostname.join(", ")))
            .set_level(rfd::MessageLevel::Warning)
            .set_buttons(rfd::MessageButtons::OkCancel)
            .show().await;
        if answer != rfd::MessageDialogResult::Ok { return Ok(None); }
    }
    let manager = crate::core::CoreManager::global();
    let _life = manager.lifecycle_lock.lock().await;
    ensure!(!crate::core::handle::Handle::global().is_exiting(), "application is exiting");
    let generation = manager.current_core_readiness_generation().context("core is not ready")?;
    if candidate.enable {
        let runtime = crate::config::Config::runtime().await.data_arc();
        let config = runtime.config.as_ref().context("runtime profile is unavailable")?;
        require_tun_rule(config)?;
    }
    // The owner lock spans the complete disk/runtime transaction. Persist a
    // pending intent first; a process crash cannot silently activate an
    // unconfirmed selection on the next launch.
    let (data, before, pending) = {
        let guard = ROUTE.lock();
        let s = guard.as_ref().context("original-route development core is unavailable")?;
        ensure!(s.recovery.generation == Some(generation) && s.revision == expected, "MITM configuration changed; refresh first");
        (s.launch.data.clone(), s.saved(&s.selection(), false), s.saved(&candidate, true))
    };
    write_saved(&data, &pending).await.context("failed to stage MITM configuration; runtime unchanged")?;
    let applied = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut guard = ROUTE.lock();
        let s = guard.as_mut().context("original-route development core is unavailable")?;
        ensure!(s.recovery.generation == Some(generation) && s.revision == expected, "MITM configuration changed; refresh first");
        s.change(candidate)?;
        let selection = s.selection();
        let saved = s.saved(&selection, false);
        saved.validate(&s.launch.bootstrap_sha256)?;
        Ok((selection, s.revision.clone(), saved))
    }).await?;
    let (selection, revision, saved) = match applied {
        Ok(applied) => applied,
        Err(err) => {
            // A failed runtime PUT/DELETE can have reached the controller.
            // Never mark the old selection committed merely because change()
            // returned an error. Keep the pending marker unless the previous
            // scope and its CA/worker have been verified again.
            let restored = tokio::task::spawn_blocking({
                let previous = before.selection();
                let expected_ca = before.ca_fingerprint.clone();
                move || {
                    let mut guard = ROUTE.lock();
                    let Some(session) = guard.as_mut() else { return false; };
                    if session.recovery.generation != Some(generation) || session.selection() != previous {
                        session.publish(Health::Degraded);
                        return false;
                    }
                    let verified = if previous.enable {
                        session.ca.as_ref().is_some_and(|ca| Some(&ca.sha256_fingerprint) == expected_ca.as_ref())
                            && session.child.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)))
                            && session.launch.verify().is_ok()
                    } else {
                        session.launch.verify_disabled().is_ok()
                    };
                    if !verified { session.publish(Health::Degraded); }
                    verified
                }
            }).await?;
            ensure!(restored, "MITM change failed and previous scope could not be verified; pending selection retained, restart blocked until reviewed");
            write_saved(&data, &before).await.context("MITM change failed and previous selection could not be saved; restart is blocked until reviewed")?;
            return Err(err);
        }
    };
    // If final persistence fails, do not silently re-enable a disabled
    // session or change its running scope. Leave the pending marker; the
    // next startup refuses it until the selection is explicitly reviewed.
    write_saved(&data, &saved).await.context("MITM runtime changed but persistence failed; review the local selection before restarting")?;
    Ok(Some((selection, revision)))
}

fn require_tun_rule(config: &serde_yaml_ng::Mapping) -> Result<()> {
    ensure!(super::enabled_block(config, "tun"), "original-route MITM requires TUN");
    ensure!(config.get("mode").and_then(serde_yaml_ng::Value::as_str).is_none_or(|mode| mode.eq_ignore_ascii_case("rule")), "original-route MITM requires rule mode");
    Ok(())
}

// A profile reload must not silently bypass configured interception by
// changing TUN/mode while a development generation is enabled.
pub(super) async fn guard_runtime() -> Result<()> {
    if !requested() && !service_requested() { return Ok(()); }
    let enabled = service_requested() || tokio::task::spawn_blocking(|| ROUTE.lock().as_ref().is_some_and(|s| s.enabled)).await?;
    if enabled {
        let runtime = crate::config::Config::runtime().await.latest_arc();
        require_tun_rule(runtime.config.as_ref().context("MITM runtime profile missing")?)?;
    }
    Ok(())
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
        let mut candidate = MitmSettings { enable: true, hostname: vec!["a.test".into()], policy: None };
        validate_candidate(&candidate)?;
        candidate.hostname.clear();
        assert!(validate_candidate(&candidate).is_err());
        candidate.enable = false;
        validate_candidate(&candidate)?;
        candidate.policy = Some("DIRECT".into());
        assert!(validate_candidate(&candidate).is_err());
        assert!(same_hosts(&["a.test".into(), "b.test".into()], &["b.test".into(), "a.test".into()]));
        assert!(!same_hosts(&["a.test".into()], &["b.test".into()]));
        let secret = random_secret()?;
        assert_eq!(URL_SAFE_NO_PAD.decode(secret)?.len(), 24);
        Ok(())
    }

    #[test]
    fn persisted_selection_is_bootstrap_bound_and_never_contains_runtime_secrets() -> Result<()> {
        let mut saved = SavedRoute {
            version: 1, bootstrap_sha256: "bootstrap-a".into(), pending: false,
            enable: true, hosts: vec!["api.example.test".into()],
            ca_fingerprint: Some("a".repeat(64)),
        };
        let yaml = serde_yaml_ng::to_string(&saved)?;
        let decoded = decode_saved(yaml.as_bytes(), "bootstrap-a")?;
        assert_eq!(decoded.selection(), saved.selection());
        assert!(!yaml.contains("secret") && !yaml.contains("policy") && !yaml.contains("worker"));
        assert!(decode_saved(yaml.as_bytes(), "bootstrap-b").is_err());
        assert!(decode_saved(format!("{yaml}\npolicy: DIRECT").as_bytes(), "bootstrap-a").is_err());
        saved.pending = true;
        assert!(decode_saved(serde_yaml_ng::to_string(&saved)?.as_bytes(), "bootstrap-a").is_err());
        saved.pending = false;
        saved.ca_fingerprint = None;
        assert!(saved.validate("bootstrap-a").is_err());
        saved.enable = false;
        saved.validate("bootstrap-a")?;
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
