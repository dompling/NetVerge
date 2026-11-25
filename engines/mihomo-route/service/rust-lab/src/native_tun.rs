use crate::{free_port, ordinary_directory};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{path::{Path, PathBuf}, process::Stdio, time::Duration};
use tokio::{io::{AsyncBufReadExt, BufReader}, process::{Child, Command}, time::timeout};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ports {
    exit_port: u16,
    upstream_dns_port: u16,
}

pub struct NativeTun {
    script: PathBuf,
    directory: PathBuf,
    dns_port: u16,
    ports: Ports,
    origin: Child,
}

impl NativeTun {
    pub async fn start(worker: &Path, directory: &Path) -> Result<Self> {
        ensure!(std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"), "native TUN fixture requires a disposable Windows CI runner");
        std::fs::create_dir(directory)?;
        let directory = ordinary_directory(directory)?;
        let script = worker.with_file_name("windows-tun-lab.cjs");
        let mut origin = Command::new("node")
            .args([script.as_os_str(), "serve".as_ref(), directory.as_os_str()])
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut output = BufReader::new(origin.stdout.take().context("origin fixture stdout missing")?);
        let mut line = String::new();
        timeout(Duration::from_secs(30), output.read_line(&mut line)).await??;
        let ports = serde_json::from_str(&line).context("missing native TUN origin and exit readiness")?;
        Ok(Self { script, directory, dns_port: free_port()?, ports, origin })
    }

    pub fn origin_ca(&self) -> PathBuf { self.directory.join("origin-ca.pem") }

    pub fn expose_worker_ca(&self, der: &[u8]) -> Result<()> {
        Ok(std::fs::write(self.directory.join("whistle.der"), der)?)
    }

    pub fn runtime(&self) -> String {
        let nameserver = format!("127.0.0.1:{}", self.ports.upstream_dns_port);
        json!({
            "mode": "rule",
            "log-level": "info",
            "mixed-port": 0,
            "allow-lan": false,
            "geo-auto-update": false,
            "ipv6": false,
            "find-process-mode": "off",
            "tun": {
                "enable": true, "device": "NV-MITM-CI", "stack": "gvisor",
                "auto-route": true, "auto-detect-interface": false, "strict-route": false,
                "dns-mode": "disabled", "dns-hijack": [], "route-address": ["198.18.17.0/24"]
            },
            "dns": {
                "enable": true, "ipv6": false, "enhanced-mode": "fake-ip",
                "listen": format!("127.0.0.1:{}", self.dns_port),
                "fake-ip-range": "198.18.17.1/24", "fake-ip-filter": [],
                "use-hosts": false, "use-system-hosts": false,
                "nameserver": [nameserver], "default-nameserver": [nameserver]
            },
            "proxies": [{ "name": "fixture-exit", "type": "http", "server": "127.0.0.1", "port": self.ports.exit_port }],
            "rules": ["DOMAIN,api.example.test,fixture-exit", "DOMAIN,bypass.example.test,fixture-exit", "MATCH,REJECT"]
        }).to_string()
    }

    async fn probe(&self, phase: &str) -> Result<()> {
        let mut child = Command::new("node");
        child.arg(&self.script).arg("probe").arg(&self.directory).arg(self.dns_port.to_string()).arg(phase)
            .kill_on_drop(true);
        let status = timeout(Duration::from_secs(75), child.status()).await.context("native TUN probe timed out")??;
        ensure!(status.success(), "native TUN {phase} probe failed");
        Ok(())
    }

    pub async fn stop(mut self) -> Result<()> {
        self.origin.kill().await.context("stop native TUN origin and exit")?;
        Ok(())
    }
}

pub async fn probe(tun: Option<&NativeTun>, phase: &str) -> Result<()> {
    if let Some(tun) = tun { tun.probe(phase).await?; }
    Ok(())
}
