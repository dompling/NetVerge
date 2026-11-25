//! Generation-bound Windows service MITM recovery transport. The service startup gate is independent.
//! No process-global environment changes, credentials in YAML, or TCP bootstrap.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clash_verge_service_ipc::{OwnerCredentials, OwnerSessionProof, get_status, mihomo_ipc_path};
use super::{control_http, controller_state::CoreState, service_generation::Generation, service_pipe};
use serde_json::json;
use std::{net::{Ipv4Addr, TcpListener}, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::TcpStream, time::timeout};

pub async fn current(credentials: &OwnerCredentials, proof: &OwnerSessionProof) -> Result<Option<Generation>> {
    let reply = get_status(credentials).await?;
    ensure!(reply.code == 0, "service status rejected");
    Generation::from_status(proof.generation, &reply.data.context("service status omitted")?)
}

pub fn secret() -> Result<String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn free_port() -> Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port())
}

// Read only a bounded Content-Length HTTP/1 response; stop at its declared
// body rather than waiting for a named-pipe peer to close the connection.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S, method: &str, path: &str, host: &str, token: Option<&str>, body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    let bearer = token.map(|s| format!("Bearer {s}"));
    exchange_with_auth(stream, method, path, host, bearer.as_deref().map(|s| ("Authorization", s)), body).await
}

async fn exchange_with_auth<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S, method: &str, path: &str, host: &str, authorization: Option<(&str, &str)>, body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    timeout(Duration::from_secs(8), async {
        let auth = authorization.map(|(name, value)| format!("{name}: {value}\r\n")).unwrap_or_default();
        let header = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            ensure!(n != 0, "control response ended before declared body");
            raw.extend_from_slice(&buf[..n]);
            if let Some((status, body)) = control_http::complete(&raw)? {
                return Ok((status, body.to_vec()));
            }
        }
    }).await.context("control exchange timed out")?
}

pub struct BoundController {
    pub generation: Generation,
    pub port: u16,
    pub secret: String,
}

impl BoundController {
    // Allocate once per process generation. If the bootstrap reply is lost,
    // retry with the SAME port and secret; the Go endpoint is idempotent.
    pub fn new(generation: Generation, port: u16) -> Result<Self> {
        ensure!(port >= 1024, "invalid service controller port");
        Ok(Self { generation, port, secret: secret()? })
    }

    pub async fn bootstrap(&self, credentials: &OwnerCredentials, proof: &OwnerSessionProof) -> Result<CoreState> {
        self.confirm_current(credentials, proof).await?;
        let generation = self.generation;
        let pipe = mihomo_ipc_path(&credentials.identity);
        let stream = service_pipe::open_verified(&pipe, generation, Duration::from_secs(8)).await?;
        ensure!(current(credentials, proof).await? == Some(generation), "service generation changed before bootstrap");
        let raw = serde_json::to_vec(&json!({"port":self.port,"secret":self.secret}))?;
        let (code, _) = exchange(stream, "POST", "/__netverge_service_lab/bootstrap", "netverge-local", None, &raw).await?;
        ensure!(code == 204, "service core bootstrap refused ({code})");
        let state = self.state().await?;
        state.verify_protocol()?;
        self.confirm_current(credentials, proof).await?;
        Ok(state)
    }

    pub async fn confirm_current(&self, credentials: &OwnerCredentials, proof: &OwnerSessionProof) -> Result<()> {
        ensure!(current(credentials, proof).await? == Some(self.generation), "service generation changed");
        Ok(())
    }

    pub async fn request(&self, method: &str, token: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let stream = timeout(Duration::from_secs(3), TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))).await??;
        exchange(stream, method, "/v1/mitm", &format!("127.0.0.1:{}", self.port), Some(token), body).await
    }

    pub async fn state(&self) -> Result<CoreState> {
        let (status, body) = self.request("GET", &self.secret, &[]).await?;
        ensure!(status == 200, "controller state refused ({status})");
        Ok(serde_json::from_slice(&body)?)
    }

    // Only restore a previously committed exact selection. A bad worker,
    // unexpected scope or interrupted request never falls back to DELETE.
    // A retry after a lost PUT/DELETE acknowledgement re-reads state first.
    pub async fn restore(
        &self, credentials: &OwnerCredentials, proof: &OwnerSessionProof,
        selection: &CommittedSelection, worker: Option<WorkerLink<'_>>,
    ) -> Result<()> {
        selection.validate()?;
        let before = self.bootstrap(credentials, proof).await?;
        let body = if selection.enabled {
            let worker = worker.context("committed MITM selection requires its worker")?;
            ensure!(selection.ca_fingerprint.as_deref() == Some(worker.ca_fingerprint), "worker CA differs from committed selection");
            worker.verify(&selection.hosts).await?;
            if before.verify_selection(true, &selection.hosts).is_ok() {
                return self.confirm_current(credentials, proof).await;
            }
            before.verify_pending()?;
            serde_json::to_vec(&json!({"hosts":selection.hosts,"workerPort":worker.port,"workerSecret":worker.secret}))?
        } else {
            ensure!(worker.is_none(), "disabled selection must not carry a worker");
            if before.verify_selection(false, &[]).is_ok() {
                return self.confirm_current(credentials, proof).await;
            }
            before.verify_pending()?;
            Vec::new()
        };
        self.confirm_current(credentials, proof).await?;
        let method = if selection.enabled { "PUT" } else { "DELETE" };
        let (status, _) = self.request(method, &self.secret, &body).await?;
        ensure!(status == 204, "controller refused committed selection ({status})");
        self.state().await?.verify_selection(selection.enabled, &selection.hosts)?;
        self.confirm_current(credentials, proof).await
    }
}


/// Contains no runtime credentials. In the desktop this corresponds to the
/// validated, non-pending local selection record, including its pinned CA.
pub struct CommittedSelection {
    pub enabled: bool,
    pub hosts: Vec<String>,
    pub ca_fingerprint: Option<String>,
}

impl CommittedSelection {
    fn validate(&self) -> Result<()> {
        ensure!(!self.enabled || !self.hosts.is_empty(), "enabled selection has no hosts");
        ensure!(self.hosts.len() <= 64 && super::controller_state::same_hosts(&self.hosts, &self.hosts), "invalid selection scope");
        if self.enabled {
            ensure!(self.ca_fingerprint.as_ref().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))), "enabled selection has no pinned CA");
        }
        Ok(())
    }
}

pub struct WorkerLink<'a> {
    pub port: u16,
    pub secret: &'a str,
    pub ca_fingerprint: &'a str,
}

impl WorkerLink<'_> {
    async fn verify(&self, hosts: &[String]) -> Result<()> {
        ensure!(self.port >= 1024, "invalid worker port");
        // Probe the pinned local worker before making any selection change.
        // This request does not use the system proxy or CA trust store.
        let stream = timeout(Duration::from_secs(3), TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))).await??;
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("netverge:{}", self.secret));
        let (status, body) = exchange_with_auth(stream, "GET", "/__netverge_routes", &format!("127.0.0.1:{}", self.port), Some(("Proxy-Authorization", &format!("Basic {auth}"))), &[]).await?;
        ensure!(status == 200, "worker rejected authentication");
        #[derive(serde::Deserialize)]
        struct WorkerState { protocol: u32, hosts: Vec<String> }
        let state: WorkerState = serde_json::from_slice(&body)?;
        ensure!(state.protocol == 1 && super::controller_state::same_hosts(&state.hosts, hosts), "worker selection differs from committed scope");
        Ok(())
    }
}
