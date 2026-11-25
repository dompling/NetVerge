//! Run on a disposable Windows CI runner only. Uses the actual upstream
//! service IPC and watchdog in test mode (no service registration/elevation).
#[path = "../../../../../src-tauri/src/core/mitm/service_restore.rs"]
mod service_restore;
#[path = "../../../../../src-tauri/src/core/mitm/controller_state.rs"]
mod controller_state;
#[path = "../../../../../src-tauri/src/core/mitm/service_generation.rs"]
mod service_generation;
#[path = "../../../../../src-tauri/src/core/mitm/control_http.rs"]
mod control_http;
#[path = "../../../../../src-tauri/src/core/mitm/service_pipe.rs"]
mod service_pipe;

use anyhow::{Context, Result, ensure};
use clash_verge_service_ipc::{
    CoreWatchdogTestConfig, OwnerCredentials, OwnerSessionProof, RuntimeBundle, StartClashRequest,
    ServiceLifecycleState, connect, run_ipc_supervisor_until_shutdown, service_lifecycle_state,
    set_core_watchdog_config_for_tests, start_clash, stop_clash, test_owner_credentials,
};
use std::{path::{Path, PathBuf}, process::Stdio, time::Duration};
use tokio::{io::{AsyncBufReadExt, BufReader}, process::{Child, Command}, sync::oneshot, time::{sleep, timeout}};
use service_generation::{Generation, GenerationWatch, Transition};
use service_restore::{BoundController, CommittedSelection, WorkerLink, current, free_port, secret};
use windows_sys::Win32::{Foundation::CloseHandle, System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess}};

async fn wait_core(credentials: &OwnerCredentials, proof: &OwnerSessionProof, previous: Option<Generation>) -> Result<Generation> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(generation) = current(credentials, proof).await? {
            if previous.is_none_or(|old| generation.is_restart_of(old)) { return Ok(generation); }
        }
        ensure!(tokio::time::Instant::now() < deadline, "{}", if previous.is_some() {
            "service watchdog did not publish a replacement generation"
        } else {
            "service did not publish an initial running generation"
        });
        sleep(Duration::from_millis(150)).await;
    }
}

// Canonicalize an existing local directory without handing Node a verbatim
// \\?\ drive path. This expands short Windows names and resolves the actual
// CA directory, matching the successful Go fixture's EvalSymlinks.
fn ordinary_directory(path: &Path) -> Result<PathBuf> {
    let resolved = path.canonicalize()?;
    let text = resolved.to_str().context("fixture directory is not UTF-8")?;
    let ordinary = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(text));
    ensure!(ordinary.is_absolute() && ordinary.is_dir(), "fixture directory is not an absolute directory");
    ensure!(matches!(ordinary.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_))), "fixture directory must use an ordinary Windows drive path");
    Ok(ordinary)
}

fn isolated_worker_command(script: &Path, data: &Path) -> Command {
    let mut command = Command::new("node");
    command.arg(script);
    // Whistle's getDataDir() and HTTPS CA module read home-related
    // state at require time, before the baseDir option is applied.
    // Match the existing Go and desktop worker launchers.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("WHISTLE_") || name.starts_with("PFORK_")
            || name.starts_with("NETVERGE_MITM_") || name.starts_with("NETVERGE_LAB_")
            || matches!(name.as_str(), "HOME" | "USERPROFILE" | "NODE_OPTIONS" | "NODE_PATH"
                | "NODE_EXTRA_CA_CERTS" | "NODE_TLS_REJECT_UNAUTHORIZED"
                | "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY") {
            command.env_remove(key);
        }
    }
    command.env("HOME", data).env("USERPROFILE", data);
    command
}

struct Worker { child: Child, port: u16, secret: String, ca_fingerprint: String }
impl Worker {
    async fn start(script: &Path, data: &Path) -> Result<Self> {
        // Each test uses its own fresh data root; never reuse the runner's CA.
        std::fs::create_dir(data)?;
        let data = ordinary_directory(data)?;
        let port = free_port()?;
        let secret = secret()?;
        let mut child = isolated_worker_command(script, &data)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("NETVERGE_MITM_WORKER_CONFIG", serde_json::to_string(&serde_json::json!({
                "dataDir": data, "port": port, "hosts": ["api.example.test"], "targetPort":443,"controlSecret":secret
            }))?)
            .spawn()?;
        let mut lines = BufReader::new(child.stdout.take().context("worker stdout missing")?).lines();
        let ca_fingerprint = timeout(Duration::from_secs(30), async {
            loop {
                let line = lines.next_line().await?.context("worker exited before readiness; inspect sanitized Whistle initialization stage")?;
                if let Some(ca) = line.strip_prefix("NETVERGE_MITM_READY ") {
                    ensure!(!ca.is_empty() && ca.len() <= 22000, "invalid worker CA readiness");
                    use base64::Engine as _;
                    use sha2::{Digest, Sha256};
                    let der = base64::engine::general_purpose::STANDARD.decode(ca)?;
                    ensure!(!der.is_empty() && der.len() <= 16384, "invalid worker CA DER");
                    // sha2 0.11 returns a hybrid-array without LowerHex.
                    // Match the desktop CA fingerprint's byte-wise encoding.
                    let fingerprint: String = Sha256::digest(&der).iter().map(|byte| format!("{byte:02x}")).collect();
                    return Ok::<_, anyhow::Error>(fingerprint);
                }
            }
        }).await.context("worker readiness timed out")??;
        tokio::spawn(async move { while matches!(lines.next_line().await, Ok(Some(_))) {} });
        println!("PASS: isolated Whistle worker initialized and returned its verified CA");
        Ok(Self { child, port, secret, ca_fingerprint })
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
    let mut watch = GenerationWatch::default();
    ensure!(watch.observe(Some(first)) == Transition::Initial && watch.current() == Some(first), "initial service generation not recorded");
    println!("PASS: initial authenticated service core generation {first:?}");
    let port = free_port()?;
    ensure!(port != worker.port, "fixture ports collide");
    let enabled = CommittedSelection { enabled: true, hosts: vec!["api.example.test".into()], ca_fingerprint: Some(worker.ca_fingerprint.clone()) };
    let disabled = CommittedSelection { enabled: false, hosts: enabled.hosts.clone(), ca_fingerprint: enabled.ca_fingerprint.clone() };
    let link = || WorkerLink { port: worker.port, secret: &worker.secret, ca_fingerprint: &worker.ca_fingerprint };
    let controller = BoundController::new(first, port)?;
    controller.bootstrap(credentials, proof).await?.verify_pending()?;
    controller.restore(credentials, proof, &enabled, Some(link())).await?;
    // Replay the same generation and selection, as after an uncertain reply.
    controller.restore(credentials, proof, &enabled, Some(link())).await?;
    println!("PASS: Rust owner/PID-bound bootstrap and idempotent committed selection");
    terminate_fixture(first.pid)?;
    ensure!(watch.observe(None) == Transition::Unavailable && watch.current().is_none(), "lost generation still current");
    let second = wait_core(credentials, proof, Some(first)).await?;
    ensure!(watch.observe(Some(second)) == Transition::Restarted, "replacement service generation rejected");
    ensure!(watch.observe(Some(first)) == Transition::Rejected && watch.current().is_none(), "stale service sample accepted");
    ensure!(watch.observe(Some(second)) == Transition::Reconfirmed && watch.current() == Some(second), "replacement not reconfirmed");
    println!("PASS: service watchdog published replacement core generation {second:?}");
    ensure!(controller.confirm_current(credentials, proof).await.is_err(), "old generation remained current");
    let fresh = BoundController::new(second, port)?;
    fresh.bootstrap(credentials, proof).await?.verify_pending()?;
    // Same credential after a possible lost bootstrap acknowledgement.
    fresh.bootstrap(credentials, proof).await?.verify_pending()?;
    ensure!(fresh.request("DELETE", &controller.secret, &[]).await?.0 == 401, "old controller secret accepted");
    let invalid = secret()?;
    ensure!(fresh.restore(credentials, proof, &enabled, Some(WorkerLink { secret: &invalid, ..link() })).await.is_err(), "invalid worker accepted");
    fresh.state().await?.verify_pending()?;
    let bad_ca = "0".repeat(64);
    ensure!(fresh.restore(credentials, proof, &enabled, Some(WorkerLink { ca_fingerprint: &bad_ca, ..link() })).await.is_err(), "changed worker CA accepted");
    fresh.state().await?.verify_pending()?;
    fresh.restore(credentials, proof, &enabled, Some(link())).await?;
    fresh.restore(credentials, proof, &enabled, Some(link())).await?;
    fresh.state().await?.verify_selection(true, &enabled.hosts)?;
    println!("PASS: actual watchdog restored committed scope; stale credentials and CA mismatch rejected");
    // This is a deliberate owner disable, not an automatic fallback.
    ensure!(fresh.request("DELETE", &fresh.secret, &[]).await?.0 == 204, "disable rejected");
    fresh.state().await?.verify_selection(false, &[])?;
    terminate_fixture(second.pid)?;
    let third = wait_core(credentials, proof, Some(second)).await?;
    let replacement = BoundController::new(third, port)?;
    replacement.bootstrap(credentials, proof).await?.verify_pending()?;
    replacement.restore(credentials, proof, &disabled, None).await?;
    replacement.restore(credentials, proof, &disabled, None).await?;
    replacement.state().await?.verify_selection(false, &[])?;
    println!("PASS: explicitly disabled selection stays disabled after actual watchdog restart");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let core = PathBuf::from(std::env::args_os().nth(1).context("lab core path required")?).canonicalize()?;
    // Node's Windows main-module resolution needs an ordinary drive path.
    // Rust canonicalize() returns a verbatim path (\\\\?\\...) which the
    // Node 22 entry-point resolver on this runner misinterprets.
    let script = PathBuf::from(std::env::args_os().nth(2).context("worker path required")?);
    ensure!(script.is_absolute() && script.is_file(), "worker must be an existing absolute script path");
    ensure!(matches!(script.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_))), "worker must use an ordinary Windows drive path");

    ensure!(cfg!(windows), "Windows runner required");
    let fixture = std::env::temp_dir().join(format!("netverge-service-rust-lab-{}-{}", std::process::id(), secret()?));
    std::fs::create_dir(&fixture)?;
    let fixture = ordinary_directory(&fixture)?;
    let core_copy = fixture.join("verge-mihomo.exe");
    std::fs::copy(core, &core_copy)?;
    let credentials = test_owner_credentials(&fixture.join("owner"))?;
    let mut worker = Worker::start(&script, &fixture.join("whistle")).await?;
    set_core_watchdog_config_for_tests(Some(CoreWatchdogTestConfig {
        max_restarts: 3, restart_window: Duration::from_secs(60), max_backoff: Duration::ZERO,
    }));
    // run_ipc_server() alone leaves the upstream service lifecycle state
    // at Starting. Use the real supervisor, which owns readiness and cleanup.
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let supervisor = tokio::spawn(run_ipc_supervisor_until_shutdown(async move {
        let _ = shutdown_rx.await;
    }));
    let result = async {
        timeout(Duration::from_secs(20), async {
            while service_lifecycle_state() != ServiceLifecycleState::Running || connect().await.is_err() {
                sleep(Duration::from_millis(100)).await;
            }
        }).await.context("service IPC readiness timeout")?;
        println!("PASS: actual upstream IPC supervisor reports Running");
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
    let _ = shutdown_tx.send(());
    let shutdown = timeout(Duration::from_secs(30), supervisor).await;
    // Always stop the local fixture worker, even on service failure.
    let _ = worker.child.kill().await;
    let _ = worker.child.wait().await;
    set_core_watchdog_config_for_tests(None);
    let _ = std::fs::remove_dir_all(fixture);
    result?;
    shutdown.context("service supervisor shutdown timed out")?
        .context("service supervisor task failed")??;
    Ok(())
}
