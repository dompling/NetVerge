//! Opt-in desktop MITM integration. The normal runtime path is unchanged without the dev flag.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use clash_verge_logging::{Type, logging};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{atomic::{AtomicBool, Ordering}, mpsc},
    time::{Duration, Instant},
};

pub(crate) mod trust;
pub(crate) mod settings;
pub(crate) mod route_runtime;

const PROXY: &str = "NETVERGE-MITM";
const RETURN: &str = "netverge-return";
static SESSION: Mutex<Option<Session>> = Mutex::new(None);
static PUBLIC_STATE: Mutex<PublicState> = Mutex::new(PublicState {
    health: Health::Inactive,
    generation: None,
    attempts: 0,
    ca: None,
});

#[derive(Clone, serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct MitmPublicCa {
    pub(super) sha256_fingerprint: String,
    pub(super) pem: String,
}

#[derive(serde::Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct MitmStatus {
    development_requested: bool,
    state: Health,
    core_generation_current: bool,
    recovery_attempts: u8,
    max_recovery_attempts: u8,
    ca_fingerprint: Option<String>,
}

struct PublicState {
    health: Health,
    generation: Option<u64>,
    attempts: u8,
    ca: Option<MitmPublicCa>,
}

// The status reader never waits for a worker spawn, process exit or network probe.
pub(crate) fn status() -> MitmStatus {
    let current = crate::core::CoreManager::global().current_core_readiness_generation();
    status_from_snapshot(&PUBLIC_STATE.lock(), current, development_requested() || route_runtime::requested())
}

fn status_from_snapshot(snapshot: &PublicState, current: Option<u64>, development_requested: bool) -> MitmStatus {
    let generation_current = snapshot.generation.is_some() && snapshot.generation == current;
    let state = if snapshot.generation.is_some() && !generation_current {
        Health::Degraded
    } else {
        snapshot.health
    };
    MitmStatus {
        development_requested,
        state,
        core_generation_current: generation_current,
        recovery_attempts: snapshot.attempts,
        max_recovery_attempts: MAX_RECOVERY_ATTEMPTS,
        ca_fingerprint: snapshot.ca.as_ref().map(|ca| ca.sha256_fingerprint.clone()),
    }
}

pub(crate) fn public_ca() -> Option<MitmPublicCa> {
    PUBLIC_STATE.lock().ca.clone()
}
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);
const MAX_RECOVERY_ATTEMPTS: u8 = 3;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalConfig {
    mitm: MitmSettings,
    runtime: Option<RuntimeSettings>,
}

#[derive(Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct MitmSettings {
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    hostname: Vec<String>,
    policy: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RuntimeSettings {
    node: PathBuf,
    worker: PathBuf,
    port: u16,
    return_port: u16,
}

impl LocalConfig {
    fn into_settings(self) -> Result<Option<Settings>> {
        settings::validate_selection(&self.mitm)?;
        if !self.mitm.enable {
            return Ok(None);
        }
        let runtime = self.runtime.context("enabled MITM requires local runtime settings")?;
        let settings = Settings {
            node: runtime.node,
            worker: runtime.worker,
            port: runtime.port,
            return_port: runtime.return_port,
            hosts: self.mitm.hostname,
            policy: self.mitm.policy.context("enabled MITM requires an explicit return policy")?,
        };
        settings.validate()?;
        Ok(Some(settings))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Settings {
    node: PathBuf,
    worker: PathBuf,
    hosts: Vec<String>,
    port: u16,
    return_port: u16,
    policy: String,
}

struct Session {
    settings: Settings,
    child: Option<Child>,
    password: String,
    forward_password: String,
    recovery: RecoveryBudget,
    health_secret: String,
    health: Health,
    ca: Option<MitmPublicCa>,
    publish: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Inactive,
    Checking,
    LocalLinkHealthy,
    Degraded,
    Recovering,
    Failed,
}

impl Session {
    fn set_health(&mut self, next: Health) {
        if self.health != next {
            self.health = next;
            logging!(info, Type::Core, "MITM local health: {next:?}");
        }
        if self.publish {
            *PUBLIC_STATE.lock() = PublicState {
                health: self.health,
                generation: self.recovery.generation,
                attempts: self.recovery.attempts,
                ca: self.ca.clone(),
            };
        }
    }

    fn start(&mut self, data: &Path) -> Result<()> {
        let (mut child, ca) = start_worker(&self.settings, data, &self.password, &self.forward_password, &self.health_secret)?;
        if self.ca.as_ref().is_some_and(|previous| previous.sha256_fingerprint != ca.sha256_fingerprint) {
            stop(&mut child);
            bail!("MITM CA changed within the running session; explicit app restart required");
        }
        self.ca = Some(ca);
        self.child = Some(child);
        self.set_health(Health::Checking);
        Ok(())
    }
}

#[derive(Default)]
struct RecoveryBudget {
    generation: Option<u64>,
    attempts: u8,
}

impl RecoveryBudget {
    fn activate(&mut self, generation: u64) {
        self.generation = Some(generation);
        self.attempts = 0;
    }

    fn claim(&mut self, generation: u64) -> bool {
        if self.generation != Some(generation) || self.attempts >= MAX_RECOVERY_ATTEMPTS {
            return false;
        }
        self.attempts += 1;
        true
    }
}

fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl Settings {
    fn validate(&self) -> Result<()> {
        ensure!(self.node.is_absolute() && self.worker.is_absolute(), "MITM executable and worker must use absolute paths");
        ensure!(self.node.is_file() && self.worker.is_file(), "MITM executable or worker is missing");
        ensure!(!self.hosts.is_empty() && self.hosts.len() <= 64 && self.hosts.iter().all(|host| valid_host(host)), "MITM requires exact lowercase DNS hostnames");
        ensure!(self.port >= 1024 && self.return_port >= 1024 && self.port != self.return_port, "invalid MITM ports");
        ensure!(settings::valid_policy(&self.policy), "invalid MITM return policy");
        Ok(())
    }
}

fn named(config: &Mapping, key: &str, name: &str) -> bool {
    config.get(key).and_then(Value::as_sequence).is_some_and(|items| {
        items.iter().any(|item| item.as_mapping().and_then(|map| map.get("name")).and_then(Value::as_str) == Some(name))
    })
}

fn sequence(config: &mut Mapping, key: &str) -> Result<Vec<Value>> {
    match config.remove(key) {
        None => Ok(Vec::new()),
        Some(Value::Sequence(items)) => Ok(items),
        Some(_) => bail!("MITM requires a sequence at {key}"),
    }
}

fn enabled_block(config: &Mapping, key: &str) -> bool {
    config.get(key).and_then(Value::as_mapping).and_then(|map| map.get("enable")).and_then(Value::as_bool) == Some(true)
}

fn overlay(config: &mut Mapping, settings: &Settings, password: &str, forward_password: &str) -> Result<()> {
    ensure!(config.get("mode").and_then(Value::as_str).is_none_or(|mode| mode.eq_ignore_ascii_case("rule")), "MITM requires rule mode");
    let dns = config.get("dns").and_then(Value::as_mapping);
    ensure!(enabled_block(config, "dns") && dns.and_then(|map| map.get("enhanced-mode")).and_then(Value::as_str) == Some("fake-ip"), "MITM requires fake-ip DNS");
    ensure!(!named(config, "proxies", PROXY) && !named(config, "proxy-groups", PROXY) && !named(config, "listeners", RETURN), "reserved MITM name already exists");
    ensure!(settings.policy == "DIRECT" || named(config, "proxy-groups", &settings.policy) || named(config, "proxies", &settings.policy), "MITM return policy does not exist in the current profile");

    for key in ["mixed-port", "port", "socks-port", "redir-port", "tproxy-port"] {
        if let Some(port) = config.get(key).and_then(Value::as_u64) {
            ensure!(port != u64::from(settings.port) && port != u64::from(settings.return_port), "MITM port conflicts with {key}");
        }
    }

    let mut proxies = sequence(config, "proxies")?;
    let mut listeners = sequence(config, "listeners")?;
    let original_rules = sequence(config, "rules")?;
    proxies.push(serde_yaml_ng::to_value(serde_json::json!({
        "name": PROXY, "type": "http", "server": "127.0.0.1", "port": settings.port, "username": "netverge", "password": forward_password
    }))?);
    listeners.push(serde_yaml_ng::to_value(serde_json::json!({
        "name": RETURN, "type": "http", "listen": "127.0.0.1", "port": settings.return_port,
        "users": [{"username": "netverge", "password": password}]
    }))?);
    let mut rules = Vec::new();
    for host in &settings.hosts {
        rules.push(Value::from(format!("AND,((IN-NAME,{RETURN}),(DOMAIN,{host}),(NETWORK,TCP),(DST-PORT,443)),{}", settings.policy)));
    }
    // Only the fixed local diagnostic listener may be reached through this exception.
    rules.push(Value::from(format!("AND,((IN-NAME,{RETURN}),(IP-CIDR,127.0.0.1/32),(NETWORK,TCP),(DST-PORT,{})),DIRECT", settings.port)));
    rules.push(Value::from(format!("IN-NAME,{RETURN},REJECT")));
    for host in &settings.hosts {
        rules.push(Value::from(format!("AND,((IN-TYPE,TUN),(DOMAIN,{host}),(NETWORK,TCP),(DST-PORT,443)),{PROXY}")));
    }
    rules.extend(original_rules);
    config.insert("proxies".into(), Value::Sequence(proxies));
    config.insert("listeners".into(), Value::Sequence(listeners));
    config.insert("rules".into(), Value::Sequence(rules));
    Ok(())
}

fn public_ca_from_der(encoded: &str) -> Result<MitmPublicCa> {
    ensure!(encoded.len() <= 22000, "MITM CA payload too large");
    let der = STANDARD.decode(encoded)?;
    ensure!(!der.is_empty() && der.len() <= 16384, "invalid MITM CA size");
    // Parse the certificate without installing it into any system or TLS trust store.
    let mut parsed = rustls::RootCertStore::empty();
    parsed.add(rustls::pki_types::CertificateDer::from(der.clone())).context("invalid MITM public CA")?;
    let sha256_fingerprint: String = Sha256::digest(&der).iter().map(|byte| format!("{byte:02x}")).collect();
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk)?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(MitmPublicCa { sha256_fingerprint, pem })
}

// Redact only the reserved adapter entries, never modify the applied mapping.
pub(crate) fn redact_runtime_for_ipc(config: &mut Mapping) {
    for (key, name) in [("proxies", PROXY), ("listeners", RETURN)] {
        let Some(Value::Sequence(items)) = config.get_mut(key) else { continue };
        for item in items {
            let Some(map) = item.as_mapping_mut() else { continue };
            if map.get("name").and_then(Value::as_str) != Some(name) { continue; }
            map.remove("password");
            if let Some(Value::Sequence(users)) = map.get_mut("users") {
                for user in users {
                    if let Some(user) = user.as_mapping_mut() {
                        user.remove("password");
                    }
                }
            }
        }
    }
}

pub(crate) fn validate_backup_entry(name: &str, unix_mode: Option<u32>) -> Result<()> {
    ensure!(!name.split(['/', '\\']).any(|part| part.trim_end_matches([' ', '.']).split(':').next().is_some_and(|part| part.eq_ignore_ascii_case("netverge-mitm-dev") || part.eq_ignore_ascii_case(settings::FILE_NAME))), "backup may not contain MITM private data");
    ensure!(!unix_mode.is_some_and(|mode| mode & 0o170000 == 0o120000), "backup may not contain symbolic links");
    Ok(())
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn start_worker(settings: &Settings, data: &Path, password: &str, forward_password: &str, health_secret: &str) -> Result<(Child, MitmPublicCa)> {
    let payload = serde_json::json!({
        "dataDir": data, "port": settings.port, "returnPort": settings.return_port,
        "hosts": settings.hosts, "password": password, "forwardPassword": forward_password, "targetPort": 443, "healthSecret": health_secret
    });
    start_worker_payload(&settings.node, &settings.worker, data, &payload)
}

fn start_worker_payload(node: &Path, worker: &Path, data: &Path, payload: &serde_json::Value) -> Result<(Child, MitmPublicCa)> {
    std::fs::create_dir_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut command = Command::new(node);
    command.arg(worker).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    for (key, _) in std::env::vars_os() {
        let normalized = key.to_string_lossy().to_ascii_uppercase();
        if normalized.starts_with("WHISTLE_") || normalized.starts_with("PFORK_")
            || matches!(normalized.as_str(), "NODE_OPTIONS" | "NODE_PATH" | "NODE_TLS_REJECT_UNAUTHORIZED" | "NODE_EXTRA_CA_CERTS" | "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY")
        {
            command.env_remove(key);
        }
    }
    command.env("HOME", data).env("USERPROFILE", data).env("NETVERGE_MITM_WORKER_CONFIG", payload.to_string());
    let mut child = command.spawn().context("failed to start MITM worker")?;
    let Some(stdout) = child.stdout.take() else {
        stop(&mut child);
        bail!("MITM worker stdout unavailable");
    };
    let (tx, rx) = mpsc::sync_channel(1);
    let _ = std::thread::spawn(move || {
        let mut ready = false;
        for line in BufReader::new(stdout).lines().map_while(std::result::Result::ok) {
            if !ready && let Some(encoded) = line.strip_prefix("NETVERGE_MITM_READY ") {
                ready = true;
                let _ = tx.send(public_ca_from_der(encoded));
            }
        }
    });
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(ca)) => Ok((child, ca)),
        _ => {
            stop(&mut child);
            bail!("MITM worker did not report a valid public CA and readiness");
        }
    }
}

// Planning allocates stable session credentials but never spawns a process.
// The Core's existing validation/application lifecycle owns the external effect.
fn plan_overlay(mut config: Mapping, settings: Option<Settings>, state: &mut Option<Session>) -> Result<Mapping> {
    if let Some(session) = state.as_ref() {
        ensure!(settings.as_ref() == Some(&session.settings), "restart NetVerge to change MITM development settings");
    }
    ensure!(!named(&config, "proxies", PROXY) && !named(&config, "proxy-groups", PROXY) && !named(&config, "listeners", RETURN), "reserved MITM name already exists");
    let Some(settings) = settings else {
        return Ok(config);
    };
    if !enabled_block(&config, "tun") {
        return Ok(config);
    }
    if let Some(session) = state.as_ref() {
        overlay(&mut config, &settings, &session.password, &session.forward_password)?;
        return Ok(config);
    }
    let password = nanoid::nanoid!(32);
    let forward_password = nanoid::nanoid!(32);
    overlay(&mut config, &settings, &password, &forward_password)?;
    *state = Some(Session { settings, child: None, password, forward_password, recovery: RecoveryBudget::default(), health_secret: nanoid::nanoid!(32), health: Health::Inactive, ca: None, publish: false });
    Ok(config)
}

// Product gate: the legacy fixed-return laboratory changes rule semantics.
// Do not expose it through desktop startup, reload or mode guards. Reopen
// only after the core's original routing decision is preserved end to end.
pub(super) const ROUTING_INHERITANCE_READY: bool = false;

pub(super) fn bootstrap_requested() -> bool {
    std::env::var_os("NETVERGE_MITM_DEV_CONFIG").is_some()
}

pub(crate) fn development_requested() -> bool {
    ROUTING_INHERITANCE_READY && bootstrap_requested()
}

pub(crate) async fn prepare(mut config: Mapping) -> Result<Mapping> {
    // Only the explicitly selected local file may authorize interception.
    // Never interpret a subscription or merge/script extension as consent.
    config.remove("mitm");
    if !development_requested() {
        return Ok(config);
    }
    tokio::task::spawn_blocking(move || {
        let settings = settings::boot_settings()?.into_settings()?;
        let mut state = SESSION.lock();
        let planned = plan_overlay(config, settings, &mut state)?;
        if let Some(session) = state.as_mut() {
            session.publish = true;
        }
        Ok(planned)
    }).await?
}

fn runtime_has_overlay(config: &Mapping) -> bool {
    named(config, "proxies", PROXY) || named(config, "listeners", RETURN)
}

pub(crate) async fn runtime_requests_mitm() -> bool {
    development_requested()
        && crate::config::Config::runtime().await.latest_arc().config.as_ref().is_some_and(runtime_has_overlay)
}

fn validate_runtime(config: &Mapping, session: &Session) -> Result<()> {
    ensure!(enabled_block(config, "tun"), "MITM runtime requires TUN");
    ensure!(config.get("mode").and_then(Value::as_str).is_none_or(|mode| mode.eq_ignore_ascii_case("rule")), "MITM runtime requires rule mode");
    // Require the exact generated entries and rule prefix. Direct runtime
    // patches must not silently change the authenticated worker's route.
    let mut expected = config.clone();
    for (key, name) in [("proxies", PROXY), ("listeners", RETURN)] {
        let mut items = sequence(&mut expected, key)?;
        items.retain(|item| item.get("name").and_then(Value::as_str) != Some(name));
        expected.insert(key.into(), Value::Sequence(items));
    }
    let mut rules = sequence(&mut expected, "rules")?;
    let prefix_len = session.settings.hosts.len() * 2 + 2;
    ensure!(rules.len() >= prefix_len, "MITM rule prefix is missing");
    drop(rules.drain(..prefix_len));
    expected.insert("rules".into(), Value::Sequence(rules));
    overlay(&mut expected, &session.settings, &session.password, &session.forward_password)?;
    for key in ["proxies", "listeners", "rules"] {
        ensure!(expected.get(key) == config.get(key), "MITM runtime {key} changed after planning");
    }
    Ok(())
}

pub(crate) async fn ensure_runtime_worker() -> Result<()> {
    route_runtime::guard_runtime().await?;
    if !development_requested() {
        // Never start a stale generated fixed-return overlay when the route
        // inheritance gate is closed, even if a previous runtime is reused.
        let runtime = crate::config::Config::runtime().await.latest_arc();
        ensure!(!runtime.config.as_ref().is_some_and(runtime_has_overlay), "stale MITM overlay; regenerate normal profile before starting the core");
        return Ok(());
    }
    let runtime = crate::config::Config::runtime().await.latest_arc();
    let Some(config) = runtime.config.as_ref().filter(|config| runtime_has_overlay(config)).cloned() else {
        return Ok(());
    };
    drop(runtime);
    let data = crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev");
    tokio::task::spawn_blocking(move || {
        let mut state = SESSION.lock();
        let session = state.as_mut().context("MITM runtime has no local session")?;
        validate_runtime(&config, session)?;
        if let Some(child) = session.child.as_mut() {
            if child.try_wait()?.is_none() {
                return Ok(());
            }
            session.child = None;
        }
        let result = session.start(&data);
        if result.is_err() {
            session.set_health(Health::Failed);
        }
        result
    }).await?
}

// The caller holds CoreManager.lifecycle_lock and has confirmed application.
// Do not infer activation from an uncommitted config draft or a live child alone.
pub(crate) async fn record_applied_runtime(generation: Option<u64>) {
    if !development_requested() {
        return;
    }
    if !runtime_requests_mitm().await {
        stop_worker().await;
        return;
    }
    let Some(generation) = generation else {
        return;
    };
    let activated = tokio::task::spawn_blocking(move || {
        let mut state = SESSION.lock();
        let Some(session) = state.as_mut() else {
            return false;
        };
        session.recovery.activate(generation);
        session.set_health(Health::Checking);
        true
    }).await.unwrap_or(false);
    if activated {
        start_monitor();
    }
}

fn start_monitor() {
    if !MONITOR_STARTED.swap(true, Ordering::AcqRel) {
        let _ = tokio::spawn(monitor_worker());
    }
}

async fn monitor_worker() {
    use crate::core::{CoreManager, handle::Handle};
    let manager = CoreManager::global();
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if Handle::global().is_exiting() {
            break;
        }
        // Use the same owner lock as core start, stop and reload. Never restart a
        // child for an old core generation or while a core transition is running.
        let Ok(_life) = manager.lifecycle_lock.try_lock() else {
            continue;
        };
        if Handle::global().is_exiting() {
            break;
        }
        let Some(generation) = manager.current_core_readiness_generation() else {
            continue;
        };
        if route_runtime::monitor(generation).await {
            continue;
        }
        let Ok(data) = crate::utils::dirs::app_home_dir().map(|dir| dir.join("netverge-mitm-dev")) else {
            continue;
        };
        let _ = tokio::task::spawn_blocking(move || recover_worker(generation, &data)).await;
    }
}

fn health_proof(secret: &str, kind: &str, nonce: &str) -> String {
    let digest = Sha256::digest(format!("netverge-health-v1:{kind}:{nonce}:{secret}").as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// The local synthetic challenge checks both authenticated listeners and a
// round trip through the real return rule. It is not an external TLS/TUN probe.
fn probe_local_link(session: &Session) -> Result<()> {
    let nonce = nanoid::nanoid!(32);
    let authority = format!("127.0.0.1:{}", session.settings.port);
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, session.settings.port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let auth = STANDARD.encode(format!("netverge:{}", session.forward_password));
    let proof = health_proof(&session.health_secret, "forward-request", &nonce);
    write!(stream, "GET /__netverge_health/{nonce} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\nX-NetVerge-Proof: {proof}\r\nConnection: close\r\n\r\n")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "MITM diagnostic timed out");
        stream.set_read_timeout(Some(remaining))?;
        let count = stream.read(&mut buf)?;
        if count == 0 {
            break;
        }
        received.extend_from_slice(&buf[..count]);
        ensure!(received.len() <= 1024, "MITM diagnostic response too large");
    }
    let response = std::str::from_utf8(&received)?;
    let (headers, body) = response.split_once("\r\n\r\n").context("invalid MITM diagnostic response")?;
    ensure!(headers.starts_with("HTTP/1.1 200 ") || headers.starts_with("HTTP/1.0 200 "), "MITM diagnostic rejected");
    ensure!(body == health_proof(&session.health_secret, "forward-response", &nonce), "MITM diagnostic proof mismatch");
    Ok(())
}

fn recover_worker(generation: u64, data: &Path) {
    let mut state = SESSION.lock();
    let Some(session) = state.as_mut() else {
        return;
    };
    recover_session(session, generation, data);
}

fn recover_session(session: &mut Session, generation: u64, data: &Path) {
    if session.recovery.generation != Some(generation) {
        return;
    }
    if let Some(child) = session.child.as_mut() {
        match child.try_wait() {
            Ok(None) => {
                let health = if probe_local_link(session).is_ok() { Health::LocalLinkHealthy } else { Health::Degraded };
                session.set_health(health);
                // A failed round trip does not identify which engine is at fault.
                // Do not terminate a running child or silently change routing.
                return;
            }
            Ok(Some(_)) => session.child = None,
            Err(_) => {
                session.set_health(Health::Degraded);
                return;
            }
        }
    }
    if !session.recovery.claim(generation) {
        session.set_health(Health::Failed);
        return;
    }
    session.set_health(Health::Recovering);
    let attempt = session.recovery.attempts;
    logging!(warn, Type::Core, "MITM worker exited; recovery attempt {attempt}/{MAX_RECOVERY_ATTEMPTS}");
    match session.start(data) {
        Ok(()) => {}
        Err(_) => {
            session.set_health(if attempt == MAX_RECOVERY_ATTEMPTS { Health::Failed } else { Health::Degraded });
            logging!(warn, Type::Core, "MITM worker recovery failed ({attempt}/{MAX_RECOVERY_ATTEMPTS})");
        }
    }
}

// Call only after confirmed core stop or application of a non-MITM runtime.
pub(crate) async fn stop_worker() {
    route_runtime::stop_worker().await;
    if !development_requested() {
        return;
    }
    let _ = tokio::task::spawn_blocking(|| {
        if let Some(session) = SESSION.lock().as_mut() {
            session.recovery = RecoveryBudget::default();
            session.set_health(Health::Inactive);
            if let Some(mut child) = session.child.take() {
                stop(&mut child);
            }
        }
    }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_gate_disables_fixed_return_experiment() {
        assert!(!ROUTING_INHERITANCE_READY);
        assert!(!development_requested());
    }

    #[test]
    fn overlay_preserves_original_rules_and_scopes_interception() -> Result<()> {
        let mut config: Mapping = serde_yaml_ng::from_str("mode: rule\ndns: {enable: true, enhanced-mode: fake-ip}\nproxy-groups: [{name: Work}]\nrules: ['MATCH,Work']\n")?;
        let settings = Settings {
            node: PathBuf::new(), worker: PathBuf::new(), hosts: vec!["example.test".into()],
            port: 18899, return_port: 18900, policy: "Work".into(),
        };
        overlay(&mut config, &settings, "test-password", "forward-password")?;
        let proxy = config.get("proxies").and_then(Value::as_sequence).and_then(|items| items.last()).context("proxy missing")?;
        assert_eq!(proxy.get("password").and_then(Value::as_str), Some("forward-password"));
        let rules = config.get("rules").and_then(Value::as_sequence).context("rules missing")?;
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[0].as_str(), Some("AND,((IN-NAME,netverge-return),(DOMAIN,example.test),(NETWORK,TCP),(DST-PORT,443)),Work"));
        assert_eq!(rules[1].as_str(), Some("AND,((IN-NAME,netverge-return),(IP-CIDR,127.0.0.1/32),(NETWORK,TCP),(DST-PORT,18899)),DIRECT"));
        assert_eq!(rules[2].as_str(), Some("IN-NAME,netverge-return,REJECT"));
        assert_eq!(rules[3].as_str(), Some("AND,((IN-TYPE,TUN),(DOMAIN,example.test),(NETWORK,TCP),(DST-PORT,443)),NETVERGE-MITM"));
        assert_eq!(rules[4].as_str(), Some("MATCH,Work"));
        Ok(())
    }

    #[test]
    fn local_yaml_and_planning_do_not_start_a_worker() -> Result<()> {
        let path = std::env::current_exe()?;
        let yaml = serde_yaml_ng::to_string(&serde_json::json!({
            "mitm": {"enable": true, "hostname": ["example.test"], "policy": "DIRECT"},
            "runtime": {"node": path, "worker": path, "port": 18899, "return-port": 18900}
        }))?;
        let settings = serde_yaml_ng::from_str::<LocalConfig>(&yaml)?.into_settings()?;
        let config: Mapping = serde_yaml_ng::from_str("mode: rule\ntun: {enable: true}\ndns: {enable: true, enhanced-mode: fake-ip}\nrules: ['MATCH,DIRECT']\n")?;
        let mut state = None;
        let first = plan_overlay(config.clone(), settings.clone(), &mut state)?;
        let second = plan_overlay(config, settings, &mut state)?;
        assert_eq!(first, second);
        let session = state.as_ref().context("session was not planned")?;
        assert!(session.child.is_none());
        validate_runtime(&first, session)?;
        let mut altered = first.clone();
        let mut rules = sequence(&mut altered, "rules")?;
        rules[0] = Value::from("MATCH,DIRECT");
        altered.insert("rules".into(), Value::Sequence(rules));
        assert!(validate_runtime(&altered, session).is_err());
        let mut altered = first.clone();
        altered.insert("mode".into(), Value::from("global"));
        assert!(validate_runtime(&altered, session).is_err());
        let disabled: LocalConfig = serde_yaml_ng::from_str("mitm: {enable: false}")?;
        assert!(disabled.into_settings()?.is_none());
        assert!(serde_yaml_ng::from_str::<LocalConfig>("mitm: {enable: true, hostname: [], unexpected: true}").is_err());
        Ok(())
    }

    #[test]
    fn recovery_budget_is_bounded_and_generation_scoped() {
        let mut budget = RecoveryBudget::default();
        assert!(!budget.claim(10));
        budget.activate(10);
        assert!(!budget.claim(11));
        for _ in 0..MAX_RECOVERY_ATTEMPTS {
            assert!(budget.claim(10));
        }
        assert!(!budget.claim(10));
        budget.activate(12);
        assert!(!budget.claim(10));
        assert!(budget.claim(12));
        budget = RecoveryBudget::default();
        assert!(!budget.claim(12));
    }

    #[test]
    fn health_proof_is_scoped_to_role_and_nonce() {
        let nonce = "nonce";
        let secret = "test-secret";
        assert_eq!(health_proof(secret, "forward-request", nonce).len(), 64);
        assert_ne!(health_proof(secret, "forward-request", nonce), health_proof(secret, "return-request", nonce));
        assert_ne!(health_proof(secret, "forward-response", nonce), health_proof(secret, "forward-response", "another"));
        assert_ne!(health_proof(secret, "forward-response", nonce), health_proof("another", "forward-response", nonce));
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_restarts_exited_child_only_for_active_generation() -> Result<()> {
        // Exercise the real process spawning and recovery path, without TUN or
        // a real profile. The separate Node lab exercises actual Mihomo/Whistle.
        let node = Command::new("node").args(["-p", "process.execPath"]).output()?;
        ensure!(node.status.success(), "Node is required for the supervisor integration test");
        let node = PathBuf::from(std::str::from_utf8(&node.stdout)?.trim());
        let data = std::env::temp_dir().join(format!("netverge-supervisor-{}", nanoid::nanoid!(12)));
        std::fs::create_dir_all(&data)?;
        let script = data.join("worker.cjs");
        let cert_path = data.join("fixture.der");
        let key_path = data.join("fixture.key");
        // Use a config file rather than OpenSSL's newer -addext flag:
        // macOS may provide LibreSSL instead of OpenSSL.
        let cert_config = data.join("fixture.cnf");
        std::fs::write(&cert_config, "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca_ext\n[dn]\nCN=NetVerge test CA\n[ca_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")?;
        let output = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config"])
            .arg(&cert_config).args(["-outform", "DER", "-out"])
            .arg(&cert_path).arg("-keyout").arg(&key_path).output()?;
        ensure!(output.status.success(), "OpenSSL test certificate generation failed");
        let encoded = STANDARD.encode(std::fs::read(&cert_path)?);
        std::fs::write(&script, format!("process.stdin.resume(); process.stdout.write('NETVERGE_MITM_READY {encoded}\\n');"))?;
        let mut session = Session {
            settings: Settings {
                node, worker: script, hosts: vec!["example.test".into()],
                port: 18899, return_port: 18900, policy: "DIRECT".into(),
            },
            child: None,
            password: nanoid::nanoid!(32),
            forward_password: nanoid::nanoid!(32),
            health_secret: nanoid::nanoid!(32),
            recovery: RecoveryBudget::default(),
            health: Health::Inactive,
            ca: None,
            publish: false,
        };
        let result = (|| -> Result<()> {
            session.start(&data)?;
            let ca = session.ca.as_ref().context("public certificate missing")?;
            assert!(ca.pem.starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(!ca.pem.contains("PRIVATE KEY"));
            assert_eq!(ca.sha256_fingerprint.len(), 64);
            let child = session.child.as_mut().context("fixture did not start")?;
            child.kill()?;
            child.wait()?;
            session.recovery.activate(42);
            recover_session(&mut session, 41, &data);
            assert_eq!(session.recovery.attempts, 0);
            assert!(session.child.as_mut().context("old child missing")?.try_wait()?.is_some());
            recover_session(&mut session, 42, &data);
            assert_eq!(session.recovery.attempts, 1);
            assert_eq!(session.health, Health::Checking);
            assert!(session.child.as_mut().context("replacement child missing")?.try_wait()?.is_none());
            Ok(())
        })();
        if let Some(mut child) = session.child.take() {
            stop(&mut child);
        }
        let cleanup = std::fs::remove_dir_all(&data);
        result?;
        cleanup?;
        Ok(())
    }

    #[test]
    fn public_ca_and_runtime_redaction_reject_private_material() -> Result<()> {
        assert!(public_ca_from_der("not-base64").is_err());
        assert!(public_ca_from_der(&STANDARD.encode(b"not a certificate")).is_err());
        let mut config: Mapping = serde_yaml_ng::from_str("proxies: [{name: NETVERGE-MITM, password: internal-secret}, {name: Work, password: user-secret}]\nlisteners: [{name: netverge-return, users: [{username: netverge, password: return-secret}]}]\n")?;
        let original = config.clone();
        redact_runtime_for_ipc(&mut config);
        let redacted = serde_yaml_ng::to_string(&config)?;
        assert!(!redacted.contains("internal-secret"));
        assert!(!redacted.contains("return-secret"));
        assert!(redacted.contains("user-secret"));
        assert!(serde_yaml_ng::to_string(&original)?.contains("internal-secret"));
        assert!(validate_backup_entry("NETVERGE-MITM-DEV/root.key", None).is_err());
        assert!(validate_backup_entry("netverge-mitm-dev\\root.key", None).is_err());
        assert!(validate_backup_entry("profiles/link", Some(0o120777)).is_err());
        validate_backup_entry("profiles/ordinary.yaml", Some(0o100644))?;
        Ok(())
    }

    #[test]
    fn public_status_does_not_report_an_old_core_as_healthy() -> Result<()> {
        let snapshot = PublicState {
            health: Health::LocalLinkHealthy, generation: Some(42), attempts: 1, ca: None,
        };
        let current = status_from_snapshot(&snapshot, Some(42), true);
        assert_eq!(current.state, Health::LocalLinkHealthy);
        assert!(current.core_generation_current);
        let stale = status_from_snapshot(&snapshot, Some(43), true);
        assert_eq!(stale.state, Health::Degraded);
        assert!(!stale.core_generation_current);
        let wire = serde_json::to_value(stale)?;
        assert_eq!(wire["state"], "degraded");
        assert_eq!(wire["recoveryAttempts"], 1);
        assert!(wire.get("password").is_none());
        assert!(wire.get("healthSecret").is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_runtime_write_does_not_inherit_old_permissions() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("netverge-private-runtime-{}", nanoid::nanoid!(12)));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("runtime.yaml");
        let result = async {
            std::fs::write(&path, "old: true")?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            crate::utils::help::save_yaml_str_private(&path, "private: true", None).await?;
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::read_to_string(&path)?, "private: true");
            Ok::<(), anyhow::Error>(())
        }.await;
        let cleanup = std::fs::remove_dir_all(dir);
        result?;
        cleanup?;
        Ok(())
    }

    #[test]
    fn exact_domains_only() {
        assert!(valid_host("api.example.test"));
        assert!(!valid_host("*.example.test"));
        assert!(!valid_host("example.test\n/.*/"));
        assert!(!valid_host("127.0.0.1"));
    }
}
