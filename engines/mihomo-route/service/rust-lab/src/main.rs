//! Run on a disposable Windows CI runner only. Uses the actual upstream
//! service IPC and watchdog in test mode (no service registration/elevation).
mod transport;

use anyhow::{Context, Result, ensure};
use clash_verge_service_ipc::{
    CoreWatchdogTestConfig, OwnerCredentials, OwnerSessionProof, RuntimeBundle, StartClashRequest,
    connect, run_ipc_server, set_core_watchdog_config_for_tests, start_clash, stop_clash, stop_ipc_server, test_owner_credentials,
};
use std::{path::{Path, PathBuf}, process::Stdio, time::Duration};
use tokio::{io::{AsyncBufReadExt, BufReader}, process::{Child, Command}, time::{sleep, timeout}};
use transport::{BoundController, Generation, current, free_port, secret};
use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess}};

async fn wait_core(credentials: &OwnerCredentials, proof: &OwnerSessionProof, previous: Option<Generation>) -> Result<Generation> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(generation) = current(credentials, proof).await? {
            if previous.is_none_or(|old| generation != old && generation.pid != old.pid) { return Ok(generation); }
        }
        ensure!(tokio::time::Instant::now() < deadline, "service watchdog did not publish a new generation");
        sleep(Duration::from_millis(150)).await;
    }
}

struct Worker { child: Child, port: u16, secret: String }
impl Worker {
    async fn start(script: &Path, data: &Path) -> Result<Self> {
        std::fs::create_dir_all(data)?;
        let port = free_port()?;
        let secret = secret()?;
        let mut child = Command::new("node")
            .arg(script)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("NETVERGE_MITM_WORKER_CONFIG", serde_json::to_string(&serde_json::json!({
                "dataDir": data, "port": port, "hosts": ["api.example.test"], "targetPort":443,"controlSecret":secret
            }))?)
            .spawn()?;
        let mut lines = BufReader::new(child.stdout.take().context("worker stdout missing")?).lines();
        timeout(Duration::from_secs(30), async {
            loop {
                let line = lines.next_line().await?.context("worker exited before readiness")?;
                if let Some(ca) = line.strip_prefix("NETVERGE_MITM_READY ") {
                    ensure!(!ca.is_empty() && ca.len() <= 22000, "invalid worker CA readiness");
                    return Ok::<_, anyhow::Error>(());
                }
            }
        }).await.context("worker readiness timed out")??;
        tokio::spawn(async move { while matches!(lines.next_line().await, Ok(Some(_))) {} });
        Ok(Self { child, port, secret })
    }
}

fn terminate_fixture(pid: u32) -> Result<()> {
    // SAFETY: this PID comes from the isolated, authenticated service fixture.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    ensure!(!handle.is_null(), "unable to open supervised fixture");
    let killed = unsafe { TerminateProcess(handle, 19) };
    unsafe { CloseHandle(handle) };
    ensure!(killed != 0, "unable to terminate supervised fixture");
    Ok(())
}

async fn scenario(credentials: &OwnerCredentials, proof: &OwnerSessionProof, worker: &Worker) -> Result<()> {
    let first = wait_core(credentials, proof, None).await?;
    let port = free_port()?;
    ensure!(port != worker.port, "fixture ports collide");
    let controller = BoundController::connect(credentials, proof, first, port).await?;
    controller.apply(credentials, proof, &["api.example.test"], worker.port, &worker.secret).await?;
    controller.confirm_current(credentials, proof).await?;
    println!("PASS: Rust owner/PID-bound named-pipe bootstrap and real Whistle selection");
    terminate_fixture(first.pid)?;
    let second = wait_core(credentials, proof, Some(first)).await?;
    ensure!(controller.confirm_current(credentials, proof).await.is_err(), "old generation remained current");
    let fresh = BoundController::connect(credentials, proof, second, port).await?;
    ensure!(fresh.request("DELETE", &controller.secret, &[]).await?.0 == 401, "old controller secret accepted");
    let invalid = secret()?;
    ensure!(fresh.apply(credentials, proof, &["api.example.test"], worker.port, &invalid).await.is_err(), "invalid worker accepted");
    ensure!(fresh.state().await?.awaiting_selection, "failed restoration released startup fence");
    fresh.apply(credentials, proof, &["api.example.test"], worker.port, &worker.secret).await?;
    ensure!(fresh.state().await?.enabled, "new core did not restore MITM");
    println!("PASS: actual service watchdog replaced core, rejected old credentials and restored Whistle scope");
    ensure!(fresh.request("DELETE", &fresh.secret, &[]).await?.0 == 204, "disable rejected");
    let state = fresh.state().await?;
    ensure!(!state.enabled && !state.awaiting_selection, "disable did not settle generation");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let core = PathBuf::from(std::env::args_os().nth(1).context("lab core path required")?).canonicalize()?;
    let script = PathBuf::from(std::env::args_os().nth(2).context("worker path required")?).canonicalize()?;
    ensure!(cfg!(windows), "Windows runner required");
    let fixture = std::env::temp_dir().join(format!("netverge-service-rust-lab-{}", std::process::id()));
    std::fs::create_dir_all(&fixture)?;
    let core_copy = fixture.join("verge-mihomo.exe");
    std::fs::copy(core, &core_copy)?;
    let credentials = test_owner_credentials(&fixture.join("owner"))?;
    let mut worker = Worker::start(&script, &fixture.join("whistle")).await?;
    set_core_watchdog_config_for_tests(Some(CoreWatchdogTestConfig {
        max_restarts: 3, restart_window: Duration::from_secs(60), max_backoff: Duration::ZERO,
    }));
    let server = run_ipc_server().await?;
    let result = async {
        timeout(Duration::from_secs(20), async {
            while connect().await.is_err() { sleep(Duration::from_millis(100)).await; }
        }).await.context("service IPC readiness timeout")?;
        let token = "42".repeat(32);
        let response = start_clash(&credentials, &StartClashRequest {
            runtime: RuntimeBundle {
                yaml: "mode: rule\nlog-level: warning\nmixed-port: 0\nallow-lan: false\ngeo-auto-update: false\nrules:\n  - MATCH,DIRECT\n".into(),
                assets: Vec::new(), remote_providers: Vec::new(), core_path: core_copy.to_string_lossy().into_owned(),
            },
            proposed_session_token: token.clone(), macos_proxy: None,
        }).await?;
        ensure!(response.code == 0, "service start rejected: {}", response.code);
        let proof = OwnerSessionProof { generation: response.data.context("missing service owner session")?.session.generation, token };
        let result = scenario(&credentials, &proof, &worker).await;
        let stopped = stop_clash(&credentials, &proof).await;
        result?;
        ensure!(stopped?.code == 0, "service stop rejected");
        Ok::<_, anyhow::Error>(())
    }.await;
    let _ = stop_ipc_server().await;
    let _ = server.await;
    let _ = worker.child.kill().await;
    let _ = worker.child.wait().await;
    set_core_watchdog_config_for_tests(None);
    let _ = std::fs::remove_dir_all(fixture);
    result
}
