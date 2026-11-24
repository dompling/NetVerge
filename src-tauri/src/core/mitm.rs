//! Opt-in desktop MITM integration. The normal runtime path is unchanged without the dev flag.

use anyhow::{Context, Result, bail, ensure};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_yaml_ng::{Mapping, Value};
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

const PROXY: &str = "NETVERGE-MITM";
const RETURN: &str = "netverge-return";
static SESSION: Mutex<Option<Session>> = Mutex::new(None);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalConfig {
    mitm: MitmSettings,
    runtime: Option<RuntimeSettings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MitmSettings {
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    hostname: Vec<String>,
    policy: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RuntimeSettings {
    node: PathBuf,
    worker: PathBuf,
    port: u16,
    return_port: u16,
}

impl LocalConfig {
    fn into_settings(self) -> Result<Option<Settings>> {
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
        ensure!(!self.policy.is_empty() && !self.policy.contains([',', '(', ')', '\n', '\r']) && self.policy != PROXY, "invalid MITM return policy");
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

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn start_worker(settings: &Settings, data: &Path, password: &str, forward_password: &str) -> Result<Child> {
    std::fs::create_dir_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
    }
    let payload = serde_json::json!({
        "dataDir": data, "port": settings.port, "returnPort": settings.return_port,
        "hosts": settings.hosts, "password": password, "forwardPassword": forward_password, "targetPort": 443
    });
    let mut command = Command::new(&settings.node);
    command.arg(&settings.worker).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
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
            if !ready && line == "NETVERGE_MITM_READY" {
                ready = true;
                let _ = tx.send(());
            }
        }
    });
    if rx.recv_timeout(Duration::from_secs(20)).is_err() {
        stop(&mut child);
        bail!("MITM worker did not report readiness");
    }
    Ok(child)
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
    *state = Some(Session { settings, child: None, password, forward_password });
    Ok(config)
}

pub(crate) fn development_requested() -> bool {
    std::env::var_os("NETVERGE_MITM_DEV_CONFIG").is_some()
}

pub(crate) async fn prepare(mut config: Mapping) -> Result<Mapping> {
    // Only the explicitly selected local file may authorize interception.
    // Never interpret a subscription or merge/script extension as consent.
    config.remove("mitm");
    let Some(path) = std::env::var_os("NETVERGE_MITM_DEV_CONFIG") else {
        return Ok(config);
    };
    let path = PathBuf::from(path);
    ensure!(path.is_absolute(), "NETVERGE_MITM_DEV_CONFIG must be an absolute path");
    tokio::task::spawn_blocking(move || {
        let local: LocalConfig = serde_yaml_ng::from_slice(&std::fs::read(path)?).context("invalid local MITM YAML")?;
        let settings = local.into_settings()?;
        plan_overlay(config, settings, &mut SESSION.lock())
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
    let prefix_len = session.settings.hosts.len() * 2 + 1;
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
    if !development_requested() {
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
        let child = start_worker(&session.settings, &data, &session.password, &session.forward_password)?;
        session.child = Some(child);
        Ok(())
    }).await?
}

// Call only after confirmed core stop or application of a non-MITM runtime.
pub(crate) async fn stop_worker() {
    if !development_requested() {
        return;
    }
    let _ = tokio::task::spawn_blocking(|| {
        if let Some(session) = SESSION.lock().as_mut() {
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
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].as_str(), Some("AND,((IN-NAME,netverge-return),(DOMAIN,example.test),(NETWORK,TCP),(DST-PORT,443)),Work"));
        assert_eq!(rules[1].as_str(), Some("IN-NAME,netverge-return,REJECT"));
        assert_eq!(rules[2].as_str(), Some("AND,((IN-TYPE,TUN),(DOMAIN,example.test),(NETWORK,TCP),(DST-PORT,443)),NETVERGE-MITM"));
        assert_eq!(rules[3].as_str(), Some("MATCH,Work"));
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
    fn exact_domains_only() {
        assert!(valid_host("api.example.test"));
        assert!(!valid_host("*.example.test"));
        assert!(!valid_host("example.test\n/.*/"));
        assert!(!valid_host("127.0.0.1"));
    }
}
