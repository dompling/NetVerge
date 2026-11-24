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
static WORKER: Mutex<Option<Worker>> = Mutex::new(None);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Settings {
    node: PathBuf,
    worker: PathBuf,
    hosts: Vec<String>,
    port: u16,
    return_port: u16,
    policy: String,
}

struct Worker {
    settings: Settings,
    child: Child,
    password: String,
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

fn overlay(config: &mut Mapping, settings: &Settings, password: &str) -> Result<()> {
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
        "name": PROXY, "type": "http", "server": "127.0.0.1", "port": settings.port
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

fn start_worker(settings: &Settings, data: &Path, password: &str) -> Result<Child> {
    std::fs::create_dir_all(data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(data, std::fs::Permissions::from_mode(0o700))?;
    }
    let payload = serde_json::json!({
        "dataDir": data, "port": settings.port, "returnPort": settings.return_port,
        "hosts": settings.hosts, "password": password
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

fn prepare_sync(mut config: Mapping, path: PathBuf, data: PathBuf) -> Result<Mapping> {
    let settings: Settings = serde_json::from_slice(&std::fs::read(path)?).context("invalid MITM development config")?;
    settings.validate()?;
    let mut state = WORKER.lock();
    if let Some(worker) = state.as_mut() {
        ensure!(worker.settings == settings, "restart NetVerge to change MITM development settings");
        overlay(&mut config, &settings, &worker.password)?;
        if worker.child.try_wait()?.is_some() {
            worker.child = start_worker(&settings, &data, &worker.password)?;
        }
        return Ok(config);
    }

    let password = nanoid::nanoid!(32);
    overlay(&mut config, &settings, &password)?;
    let child = start_worker(&settings, &data, &password)?;
    *state = Some(Worker { settings, child, password });
    Ok(config)
}

pub(crate) async fn prepare(config: Mapping) -> Result<Mapping> {
    let Some(path) = std::env::var_os("NETVERGE_MITM_DEV_CONFIG") else {
        return Ok(config);
    };
    if !enabled_block(&config, "tun") {
        // Keep the worker idle until process exit; a failed core reload must not lose its upstream.
        return Ok(config);
    }
    let path = PathBuf::from(path);
    ensure!(path.is_absolute(), "NETVERGE_MITM_DEV_CONFIG must be an absolute path");
    let data = crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev");
    tokio::task::spawn_blocking(move || prepare_sync(config, path, data)).await?
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
        overlay(&mut config, &settings, "test-password")?;
        let rules = config.get("rules").and_then(Value::as_sequence).context("rules missing")?;
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].as_str(), Some("AND,((IN-NAME,netverge-return),(DOMAIN,example.test),(NETWORK,TCP),(DST-PORT,443)),Work"));
        assert_eq!(rules[1].as_str(), Some("IN-NAME,netverge-return,REJECT"));
        assert_eq!(rules[2].as_str(), Some("AND,((IN-TYPE,TUN),(DOMAIN,example.test),(NETWORK,TCP),(DST-PORT,443)),NETVERGE-MITM"));
        assert_eq!(rules[3].as_str(), Some("MATCH,Work"));
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
