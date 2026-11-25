//! Run on a disposable Windows CI runner only. Both modes exercise the same
//! recovery scenario against the upstream watchdog.
#[cfg(any(
    all(feature = "in-process", feature = "installed-service"),
    not(any(feature = "in-process", feature = "installed-service"))
))]
compile_error!("select exactly one of in-process or installed-service");

#[cfg(feature = "installed-service")]
mod installed;
mod native_tun;
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
    OwnerCredentials, OwnerSessionProof, RuntimeBundle, StartClashRequest, start_clash, stop_clash,
};
#[cfg(feature = "in-process")]
use clash_verge_service_ipc::{
    CoreWatchdogTestConfig, ServiceLifecycleState, connect, run_ipc_supervisor_until_shutdown, service_lifecycle_state,
    set_core_watchdog_config_for_tests, test_owner_credentials,
};
use std::{
    ffi::OsString,
    os::windows::{ffi::OsStringExt, io::{AsRawHandle, FromRawHandle, OwnedHandle}},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, process::{Child, Command}, time::{sleep, timeout}};
use service_generation::{Generation, GenerationWatch, Transition};
use service_restore::{BoundController, CommittedSelection, WorkerLink, current, free_port, secret};
use windows_sys::Win32::System::{
    JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    },
    Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA,
        PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
    },
};

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
    // Whistle can fork while loading. Hold it behind stdin until the job owns Node.
    const GATE: &str = "process.stdin.once('data', b => { if (b.length !== 1 || b[0] !== 1) process.exit(1); process.stdin.pause(); require(process.argv[1]); }); process.stdin.resume();";
    command.args(["-e", GATE, "--"]).arg(script);
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

struct WorkerJob(OwnedHandle);

impl WorkerJob {
    fn new() -> Result<Self> {
        // SAFETY: null attributes create a non-inheritable handle to an unnamed job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error()).context("create Whistle worker job");
        }
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.0.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::last_os_error()).context("configure Whistle worker job");
        }
        Ok(job)
    }

    fn assign(&self, child: &Child) -> Result<()> {
        let pid = child.id().context("Whistle worker exited before job assignment")?;
        let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if process.is_null() {
            return Err(std::io::Error::last_os_error()).context("open Whistle worker for job assignment");
        }
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        if unsafe { AssignProcessToJobObject(self.0.as_raw_handle(), process.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error()).context("assign Whistle worker to job");
        }
        Ok(())
    }

    async fn stop(self) -> Result<()> {
        let handle = self.0.as_raw_handle();
        if unsafe { TerminateJobObject(handle, 1) } == 0 {
            return Err(std::io::Error::last_os_error()).context("terminate Whistle worker job");
        }
        timeout(Duration::from_secs(5), async {
            loop {
                let mut counts = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                let queried = unsafe {
                    QueryInformationJobObject(
                        self.0.as_raw_handle(),
                        JobObjectBasicAccountingInformation,
                        std::ptr::from_mut(&mut counts).cast(),
                        std::mem::size_of_val(&counts) as u32,
                        std::ptr::null_mut(),
                    )
                };
                if queried == 0 {
                    return Err(std::io::Error::last_os_error()).context("query Whistle worker job");
                }
                if counts.ActiveProcesses == 0 {
                    return Ok(());
                }
                sleep(Duration::from_millis(25)).await;
            }
        }).await.context("Whistle worker descendants did not exit")?
    }
}

struct Worker { child: Child, job: WorkerJob, port: u16, secret: String, ca_fingerprint: String }
impl Worker {
    async fn start(script: &Path, data: &Path, tun: Option<&native_tun::NativeTun>) -> Result<Self> {
        // Each test uses its own fresh data root; never reuse the runner's CA.
        std::fs::create_dir(data)?;
        let data = ordinary_directory(data)?;
        let port = free_port()?;
        let secret = secret()?;
        let job = WorkerJob::new()?;
        let mut command = isolated_worker_command(script, &data);
        if let Some(tun) = tun {
            command.env("NODE_EXTRA_CA_CERTS", tun.origin_ca());
        }
        let mut child = command
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("NETVERGE_MITM_WORKER_CONFIG", serde_json::to_string(&serde_json::json!({
                "dataDir": data, "port": port, "hosts": ["api.example.test"], "targetPort":443,"controlSecret":secret
            }))?)
            .spawn()?;
        job.assign(&child)?;
        child.stdin.as_mut().context("worker stdin missing")?.write_all(&[1]).await?;
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
                    if let Some(tun) = tun { tun.expose_worker_ca(&der)?; }
                    // sha2 0.11 returns a hybrid-array without LowerHex.
                    // Match the desktop CA fingerprint's byte-wise encoding.
                    let fingerprint: String = Sha256::digest(&der).iter().map(|byte| format!("{byte:02x}")).collect();
                    return Ok::<_, anyhow::Error>(fingerprint);
                }
            }
        }).await.context("worker readiness timed out")??;
        tokio::spawn(async move { while matches!(lines.next_line().await, Ok(Some(_))) {} });
        println!("PASS: isolated Whistle worker initialized and returned its verified CA");
        Ok(Self { child, job, port, secret, ca_fingerprint })
    }

    async fn stop(self) -> Result<()> {
        let Self { mut child, job, .. } = self;
        job.stop().await?;
        timeout(Duration::from_secs(5), child.wait()).await.context("Whistle worker did not exit")??;
        println!("PASS: Whistle worker job has no remaining processes");
        Ok(())
    }
}

fn open_fixture(pid: u32, expected_image: &Path, access: u32) -> Result<OwnedHandle> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | access, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error()).context("open supervised fixture");
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut image = vec![0_u16; 32768];
    let mut length = image.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle.as_raw_handle(), PROCESS_NAME_WIN32, image.as_mut_ptr(), &mut length) } == 0 {
        return Err(std::io::Error::last_os_error()).context("identify supervised fixture image");
    }
    let image = PathBuf::from(OsString::from_wide(&image[..length as usize]));
    ensure!(image.canonicalize()?.as_path() == expected_image, "supervised fixture is not the expected core image");
    Ok(handle)
}

fn terminate_fixture(pid: u32, expected_image: &Path) -> Result<()> {
    let handle = open_fixture(pid, expected_image, PROCESS_TERMINATE)?;
    if unsafe { TerminateProcess(handle.as_raw_handle(), 19) } == 0 {
        return Err(std::io::Error::last_os_error()).context("terminate supervised fixture");
    }
    Ok(())
}

async fn scenario(credentials: &OwnerCredentials, proof: &OwnerSessionProof, worker: &Worker, core: &Path, tun: Option<&native_tun::NativeTun>) -> Result<()> {
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
    #[cfg(feature = "installed-service")]
    installed::verify_generation(credentials, first, core).await?;
    controller.bootstrap(credentials, proof).await?.verify_pending()?;
    native_tun::probe(tun, "pending").await?;
    controller.restore(credentials, proof, &enabled, Some(link())).await?;
    native_tun::probe(tun, "enabled").await?;
    // Replay the same generation and selection, as after an uncertain reply.
    controller.restore(credentials, proof, &enabled, Some(link())).await?;
    println!("PASS: Rust owner/PID-bound bootstrap and idempotent committed selection");
    terminate_fixture(first.pid, core)?;
    ensure!(watch.observe(None) == Transition::Unavailable && watch.current().is_none(), "lost generation still current");
    let second = wait_core(credentials, proof, Some(first)).await?;
    ensure!(watch.observe(Some(second)) == Transition::Restarted, "replacement service generation rejected");
    ensure!(watch.observe(Some(first)) == Transition::Rejected && watch.current().is_none(), "stale service sample accepted");
    ensure!(watch.observe(Some(second)) == Transition::Reconfirmed && watch.current() == Some(second), "replacement not reconfirmed");
    println!("PASS: service watchdog published replacement core generation {second:?}");
    ensure!(controller.confirm_current(credentials, proof).await.is_err(), "old generation remained current");
    let fresh = BoundController::new(second, port)?;
    #[cfg(feature = "installed-service")]
    installed::verify_generation(credentials, second, core).await?;
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
    native_tun::probe(tun, "pending").await?;
    fresh.restore(credentials, proof, &enabled, Some(link())).await?;
    fresh.restore(credentials, proof, &enabled, Some(link())).await?;
    fresh.state().await?.verify_selection(true, &enabled.hosts)?;
    native_tun::probe(tun, "enabled").await?;
    println!("PASS: actual watchdog restored committed scope; stale credentials and CA mismatch rejected");
    // This is a deliberate owner disable, not an automatic fallback.
    ensure!(fresh.request("DELETE", &fresh.secret, &[]).await?.0 == 204, "disable rejected");
    fresh.state().await?.verify_selection(false, &[])?;
    terminate_fixture(second.pid, core)?;
    let third = wait_core(credentials, proof, Some(second)).await?;
    let replacement = BoundController::new(third, port)?;
    #[cfg(feature = "installed-service")]
    installed::verify_generation(credentials, third, core).await?;
    replacement.bootstrap(credentials, proof).await?.verify_pending()?;
    replacement.restore(credentials, proof, &disabled, None).await?;
    replacement.restore(credentials, proof, &disabled, None).await?;
    replacement.state().await?.verify_selection(false, &[])?;
    native_tun::probe(tun, "disabled").await?;
    println!("PASS: explicitly disabled selection stays disabled after actual watchdog restart");
    Ok(())
}

async fn start_and_exercise(credentials: &OwnerCredentials, core: &Path, worker: &Worker, tun: Option<&native_tun::NativeTun>) -> Result<()> {
    let mut session_bytes = [0_u8; 32];
    getrandom::fill(&mut session_bytes).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    let token: String = session_bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let response = start_clash(credentials, &StartClashRequest {
        runtime: RuntimeBundle {
            yaml: tun.map_or_else(
                || "mode: rule\nlog-level: warning\nmixed-port: 0\nallow-lan: false\ngeo-auto-update: false\nrules:\n  - MATCH,DIRECT\n".into(),
                native_tun::NativeTun::runtime,
            ),
            assets: Vec::new(), remote_providers: Vec::new(), core_path: core.to_string_lossy().into_owned(),
        },
        proposed_session_token: token.clone(), macos_proxy: None,
    }).await?;
    ensure!(response.code == 0, "service start rejected ({}): {}", response.code, response.message);
    let proof = OwnerSessionProof { generation: response.data.context("missing service owner session")?.session.generation, token };
    let result = scenario(credentials, &proof, worker, core, tun).await;
    let stopped = stop_clash(credentials, &proof).await;
    result?;
    let stopped = stopped?;
    ensure!(stopped.code == 0, "service stop rejected ({}): {}", stopped.code, stopped.message);
    Ok(())
}

#[cfg(feature = "in-process")]
async fn exercise(core: PathBuf, fixture: &Path, worker: &Worker, tun: Option<&native_tun::NativeTun>) -> Result<()> {
    let core_copy = fixture.join("verge-mihomo.exe");
    std::fs::copy(core, &core_copy)?;
    let core_copy = core_copy.canonicalize()?;
    let credentials = test_owner_credentials(&fixture.join("owner"))?;
    set_core_watchdog_config_for_tests(Some(CoreWatchdogTestConfig {
        max_restarts: 3, restart_window: Duration::from_secs(60), max_backoff: Duration::ZERO,
    }));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
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
        start_and_exercise(&credentials, &core_copy, worker, tun).await
    }.await;
    let _ = shutdown_tx.send(());
    let shutdown = timeout(Duration::from_secs(30), supervisor).await;
    set_core_watchdog_config_for_tests(None);
    result?;
    shutdown.context("service supervisor shutdown timed out")?.context("service supervisor task failed")??;
    Ok(())
}

#[cfg(feature = "installed-service")]
async fn exercise(core: PathBuf, _fixture: &Path, worker: &Worker, tun: Option<&native_tun::NativeTun>) -> Result<()> {
    let credentials = installed::owner_credentials()?;
    start_and_exercise(&credentials, &core, worker, tun).await
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
    let tun = if cfg!(feature = "installed-service") {
        Some(native_tun::NativeTun::start(&script, &fixture.join("native-tun")).await?)
    } else {
        None
    };
    let worker = Worker::start(&script, &fixture.join("whistle"), tun.as_ref()).await?;
    let result = exercise(core, &fixture, &worker, tun.as_ref()).await;
    let worker_shutdown = worker.stop().await;
    if let Some(tun) = tun { tun.stop().await?; }
    let cleanup = worker_shutdown.and_then(|()| {
        std::fs::remove_dir_all(fixture).context("remove service fixture directory after shutdown")
    });
    result?;
    cleanup?;
    Ok(())
}
