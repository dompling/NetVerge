//! Generation-bound native Windows transport for the service integration lab.
//! No process-global environment changes, credentials in YAML, or TCP bootstrap.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clash_verge_service_ipc::{OwnerCredentials, OwnerSessionProof, ServiceLifecycleState, get_status, mihomo_ipc_path};
use serde::Deserialize;
use serde_json::json;
use std::{net::{Ipv4Addr, TcpListener}, os::windows::io::AsRawHandle, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::{TcpStream, windows::named_pipe::ClientOptions}, time::{sleep, timeout}};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation {
    owner: u64,
    pub pid: u32,
    started_at: u64,
    restarts: u32,
}

impl Generation {
    pub fn is_restart_of(self, previous: Self) -> bool {
        self.owner == previous.owner && self.pid != previous.pid
            && self.restarts > previous.restarts
            && self.started_at >= previous.started_at
    }
}

pub async fn current(credentials: &OwnerCredentials, proof: &OwnerSessionProof) -> Result<Option<Generation>> {
    let reply = get_status(credentials).await?;
    ensure!(reply.code == 0, "service status rejected");
    let state = reply.data.context("service status omitted")?;
    ensure!(state.is_active && state.active_generation == Some(proof.generation), "service owner generation changed");
    ensure!(state.service_state != ServiceLifecycleState::Fatal, "service reported Fatal: pid_present={} restart_count={}", state.core_pid.is_some(), state.restart_count);
    if !state.desired_core_should_be_running || state.service_state != ServiceLifecycleState::Running {
        return Ok(None);
    }
    Ok(match (state.core_pid, state.core_started_at) {
        (Some(pid), Some(started_at)) if pid != 0 => Some(Generation { owner: proof.generation, pid, started_at, restarts: state.restart_count }),
        _ => None,
    })
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
        let (status, body_start, length) = loop {
            let n = stream.read(&mut buf).await?;
            ensure!(n != 0, "control response ended before headers");
            raw.extend_from_slice(&buf[..n]);
            ensure!(raw.len() <= 65536, "control response exceeds limit");
            if let Some(pos) = raw.windows(4).position(|x| x == b"\r\n\r\n") {
                let header = std::str::from_utf8(&raw[..pos])?;
                let mut lines = header.split("\r\n");
                let first = lines.next().context("missing HTTP status")?;
                ensure!(first.starts_with("HTTP/1.1 ") || first.starts_with("HTTP/1.0 "), "unexpected HTTP status");
                let status = first.split_whitespace().nth(1).context("missing HTTP code")?.parse::<u16>()?;
                let mut length = None;
                for line in lines {
                    let (key, value) = line.split_once(':').context("invalid HTTP header")?;
                    ensure!(!key.eq_ignore_ascii_case("transfer-encoding"), "unsupported HTTP framing");
                    if key.eq_ignore_ascii_case("content-length") {
                        ensure!(length.is_none(), "duplicate content length");
                        length = Some(value.trim().parse::<usize>()?);
                    }
                }
                let length = if status == 204 { ensure!(length.unwrap_or(0) == 0, "unexpected body"); 0 } else { length.context("missing content length")? };
                ensure!(length <= 32768, "control body exceeds limit");
                break (status, pos + 4, length);
            }
        };
        while raw.len() < body_start + length {
            let n = stream.read(&mut buf).await?;
            ensure!(n != 0, "truncated response body");
            raw.extend_from_slice(&buf[..n]);
            ensure!(raw.len() <= 65536, "control response exceeds limit");
        }
        ensure!(raw.len() == body_start + length, "unexpected bytes after control response");
        Ok((status, raw[body_start..].to_vec()))
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let stream = loop {
            match ClientOptions::new().open(&pipe) {
                Ok(stream) => break stream,
                Err(error) if matches!(error.raw_os_error(), Some(2 | 231)) && tokio::time::Instant::now() < deadline => sleep(Duration::from_millis(100)).await,
                Err(error) => return Err(error).context("open service core pipe"),
            }
        };
        let mut server_pid = 0u32;
        // SAFETY: the live pipe client owns the handle; the output is a u32.
        let success = unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle() as _, &mut server_pid) };
        ensure!(success != 0 && server_pid == generation.pid, "core pipe server PID differs from the authenticated service sample");
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
