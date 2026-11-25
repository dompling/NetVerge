//! Generation-bound native Windows transport for the service integration lab.
//! No process-global environment changes, credentials in YAML, or TCP bootstrap.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clash_verge_service_ipc::{OwnerCredentials, OwnerSessionProof, get_status, mihomo_ipc_path};
use crate::{control_http, service_generation::Generation, service_pipe};
use serde::Deserialize;
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

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct State {
    pub protocol: u32,
    pub enabled: bool,
    pub hosts: Vec<String>,
    #[serde(default, rename = "awaitingSelection")]
    pub awaiting_selection: bool,
}

// Read only a bounded Content-Length HTTP/1 response; stop at its declared
// body rather than waiting for a named-pipe peer to close the connection.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S, method: &str, path: &str, host: &str, token: Option<&str>, body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    timeout(Duration::from_secs(8), async {
        let auth = token.map(|s| format!("Authorization: Bearer {s}\r\n")).unwrap_or_default();
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
    pub async fn connect(
        credentials: &OwnerCredentials, proof: &OwnerSessionProof, generation: Generation, port: u16,
    ) -> Result<Self> {
        ensure!(current(credentials, proof).await? == Some(generation), "service generation not current");
        let pipe = mihomo_ipc_path(&credentials.identity);
        let stream = service_pipe::open_verified(&pipe, generation, Duration::from_secs(8)).await?;
        ensure!(current(credentials, proof).await? == Some(generation), "service generation changed before bootstrap");
        let secret = secret()?;
        let raw = serde_json::to_vec(&json!({"port":port,"secret":secret}))?;
        let (code, _) = exchange(stream, "POST", "/__netverge_service_lab/bootstrap", "netverge-local", None, &raw).await?;
        ensure!(code == 204, "service core bootstrap refused ({code})");
        let control = Self { generation, port, secret };
        let state = control.state().await?;
        ensure!(state.protocol == 1 && !state.enabled && state.awaiting_selection && state.hosts.is_empty(), "fresh core did not confirm guarded startup");
        control.confirm_current(credentials, proof).await?;
        Ok(control)
    }

    pub async fn confirm_current(&self, credentials: &OwnerCredentials, proof: &OwnerSessionProof) -> Result<()> {
        ensure!(current(credentials, proof).await? == Some(self.generation), "service generation changed");
        Ok(())
    }

    pub async fn request(&self, method: &str, token: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let stream = timeout(Duration::from_secs(3), TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))).await??;
        exchange(stream, method, "/v1/mitm", &format!("127.0.0.1:{}", self.port), Some(token), body).await
    }

    pub async fn state(&self) -> Result<State> {
        let (status, body) = self.request("GET", &self.secret, &[]).await?;
        ensure!(status == 200, "controller state refused ({status})");
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn apply(&self, credentials: &OwnerCredentials, proof: &OwnerSessionProof, hosts: &[&str], worker_port: u16, worker_secret: &str) -> Result<()> {
        self.confirm_current(credentials, proof).await?;
        let body = serde_json::to_vec(&json!({"hosts":hosts,"workerPort":worker_port,"workerSecret":worker_secret}))?;
        let (status, _) = self.request("PUT", &self.secret, &body).await?;
        ensure!(status == 204, "controller refused selection ({status})");
        let state = self.state().await?;
        ensure!(state.protocol == 1 && state.enabled && !state.awaiting_selection && state.hosts.iter().map(String::as_str).eq(hosts.iter().copied()), "controller selection differs from expected");
        self.confirm_current(credentials, proof).await
    }
}
