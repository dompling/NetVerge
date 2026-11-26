use super::{
    ENV, Launch, RouteSession, SERVICE_FAILURE, prepare_launch, private_data, report_service_failure,
};
use crate::core::{
    mitm::{
        Health, MitmSettings, RecoveryBudget,
        service_generation::{GenerationWatch, Transition},
        service_restore::{self, BoundController, CommittedSelection, WorkerLink},
    },
    owner_identity::current_owner_credentials,
    service,
};
use anyhow::{Context, Result, ensure};
use clash_verge_service_ipc::{CoreRequirement, OwnerCredentials, OwnerSessionProof};
use std::{
    path::PathBuf,
    sync::{Arc, OnceLock, atomic::{AtomicBool, Ordering}},
    time::Duration,
};
use tokio::{sync::Mutex, time::timeout};

const CORE_NAME: &str = "netverge-mihomo-service.exe";
const DIGEST_ENV: &str = "NETVERGE_MITM_SERVICE_CORE_SHA256";
const PREFERENCE_FILE: &str = "guarded-service.yaml";
static ROUTE: Mutex<Option<ServiceRoute>> = Mutex::const_new(None);
static STARTUP: OnceLock<Startup> = OnceLock::new();
static WRITE_PREFERENCE: Mutex<()> = Mutex::const_new(());

struct Startup {
    digest: std::result::Result<Option<String>, String>,
    next: AtomicBool,
}

fn preference_path() -> Result<PathBuf> {
    Ok(crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev").join(PREFERENCE_FILE))
}

fn startup() -> &'static Startup {
    STARTUP.get_or_init(|| {
        let digest = (|| -> Result<_> {
            let path = preference_path()?;
            match super::super::settings::read_bounded(&path) {
                Ok(raw) => serde_yaml_ng::from_slice::<Option<String>>(&raw).context("invalid guarded MITM service preference"),
                Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => Ok(None),
                Err(error) => Err(error).context("read guarded MITM service preference"),
            }
        })().map_err(|error| format!("{error:#}"));
        Startup { next: AtomicBool::new(!matches!(digest, Ok(None))), digest }
    })
}

pub(super) fn requested() -> bool {
    !matches!(startup().digest, Ok(None))
}

pub(super) async fn configured_hostnames() -> Vec<String> {
    ROUTE.lock().await.as_ref().map_or_else(Vec::new, |state| {
        state.worker.selection().hostname
    })
}

pub(super) fn next_start() -> Option<bool> {
    let next = startup().next.load(Ordering::Acquire);
    (requested() || next || (std::env::var_os(ENV).is_some() && std::env::var_os(DIGEST_ENV).is_some())).then_some(next)
}

pub(super) async fn set_next_start(enabled: bool) -> Result<()> {
    let _write = WRITE_PREFERENCE.lock().await;
    let preference = startup();
    let digest = if enabled {
        let digest = std::env::var(DIGEST_ENV).context("set NETVERGE_MITM_SERVICE_CORE_SHA256 to the approved core digest")?;
        prepare().await?;
        inspect_core(&digest).await?;
        Some(digest)
    } else {
        None
    };
    let path = preference_path()?;
    private_data(path.parent().context("guarded service preference has no parent directory")?)?;
    let yaml = serde_yaml_ng::to_string(&digest)?;
    crate::utils::help::save_yaml_str_private(&path, &yaml, None).await?;
    preference.next.store(enabled, Ordering::Release);
    Ok(())
}

struct ServiceRoute {
    worker: RouteSession,
    proof: Arc<OwnerSessionProof>,
    watch: GenerationWatch,
    controller: Option<BoundController>,
    restored: bool,
}

pub(crate) async fn approved_core() -> Result<PathBuf> {
    let expected = startup().digest.as_ref().map_err(|error| anyhow::anyhow!("{error}"))?
        .as_deref().context("guarded service core SHA-256 is missing")?;
    inspect_core(expected).await?;
    Ok(clash_verge_service_ipc::service_paths()?.core_dir().join(CORE_NAME))
}

async fn inspect_core(expected: &str) -> Result<()> {
    ensure!(is_sha256(expected), "guarded service core SHA-256 must contain 64 hexadecimal digits");
    let requirements = [CoreRequirement { name: CORE_NAME.into(), sha256: Some(expected.into()) }];
    let status = timeout(Duration::from_secs(8), clash_verge_service_ipc::inspect_installation(&requirements))
        .await.context("timed out verifying the approved guarded core")??;
    ensure!(status.satisfies(&requirements), "approve the matching NetVerge guarded core with the Windows development service installer");
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) async fn prepare() -> Result<Launch> {
    let path = std::env::var_os(ENV).context("local original-route MITM configuration is required for service mode")?;
    prepare_launch(PathBuf::from(path), true).await
}

pub(crate) async fn attach(launch: Launch, generation: u64, proof: Arc<OwnerSessionProof>) {
    // Service startup has already committed. If restoration fails, keep the
    // service-owned startup fence in place and retain the same bootstrap credentials.
    let mut worker = RouteSession {
        enabled: launch.restore_enabled,
        launch,
        child: None,
        ca: None,
        recovery: RecoveryBudget::default(),
        revision: String::new(),
    };
    worker.recovery.activate(generation);
    worker.publish(Health::Checking);
    *ROUTE.lock().await = Some(ServiceRoute {
        worker, proof, watch: GenerationWatch::default(), controller: None, restored: false,
    });
    SERVICE_FAILURE.lock().take();
    super::super::start_monitor();
}

impl ServiceRoute {
    async fn reconcile(&mut self, readiness: u64, credentials: &OwnerCredentials) -> Result<()> {
        let sample = service_restore::current(credentials, &self.proof).await;
        let transition = self.watch.observe(sample.as_ref().ok().copied().flatten());
        sample?;
        match transition {
            Transition::Rejected => anyhow::bail!("service reported a stale MITM core generation"),
            Transition::Unavailable => {
                self.worker.publish(Health::Recovering);
                return Ok(());
            }
            Transition::Initial | Transition::Restarted => {
                // Keep this controller for every retry in its generation.
                self.worker.recovery.activate(readiness);
                self.controller = None;
                self.restored = false;
            }
            Transition::Unchanged | Transition::Reconfirmed => {}
        }
        let generation = self.watch.current().context("guarded service generation is unavailable")?;
        if self.controller.is_none() {
            let port = service_restore::free_port()?;
            ensure!(port != self.worker.launch.worker_port, "guarded controller and worker ports collide");
            self.controller = Some(BoundController::new(generation, port)?);
        }
        let controller = self.controller.as_ref().context("guarded service controller is unavailable")?;
        let MitmSettings { enable, hostname, .. } = self.worker.selection();
        let was_running = match self.worker.child.as_mut() {
            Some(child) => child.try_wait()?.is_none(),
            None => false,
        };
        if self.restored && (!enable || was_running) {
            controller.state().await?.verify_selection(enable, if enable { &hostname } else { &[] })?;
            if enable {
                tokio::task::block_in_place(|| self.worker.launch.worker_ready())?;
            }
            self.worker.publish(if enable { Health::LocalLinkHealthy } else { Health::Inactive });
            return Ok(());
        }
        ensure!(self.worker.recovery.claim(readiness), "guarded service MITM recovery attempts exhausted");
        self.worker.publish(Health::Recovering);
        if enable && !was_running {
            self.worker.child = None;
            tokio::task::block_in_place(|| self.worker.start())?;
        }
        let selection = CommittedSelection {
            enabled: enable,
            hosts: hostname,
            ca_fingerprint: self.worker.launch.expected_ca.clone(),
        };
        let worker = self.worker.ca.as_ref().filter(|_| enable).map(|ca| WorkerLink {
            port: self.worker.launch.worker_port,
            secret: &self.worker.launch.worker_secret,
            ca_fingerprint: &ca.sha256_fingerprint,
        });
        controller.restore(credentials, &self.proof, &selection, worker).await?;
        self.restored = true;
        self.worker.recovery.activate(readiness);
        self.worker.publish(if enable { Health::LocalLinkHealthy } else { Health::Inactive });
        Ok(())
    }
}

pub(in crate::core::mitm) async fn monitor(readiness: u64) -> bool {
    let mut route = ROUTE.lock().await;
    let Some(state) = route.as_mut() else { return false; };
    let current = service::active_service_session().is_ok_and(|proof| Arc::ptr_eq(&proof, &state.proof));
    if state.worker.recovery.generation != Some(readiness) || !current {
        tokio::task::block_in_place(|| state.worker.stop());
        *route = None;
        return false;
    }
    let result = async {
        state.reconcile(readiness, &current_owner_credentials()?).await
    };
    match timeout(Duration::from_secs(20), result).await {
        Ok(Ok(())) => { SERVICE_FAILURE.lock().take(); }
        Ok(Err(error)) => report_service_failure(&error),
        Err(error) => report_service_failure(&anyhow::Error::from(error).context("guarded service MITM recovery timed out")),
    }
    true
}

pub(in crate::core::mitm) async fn stop() {
    if let Some(mut state) = ROUTE.lock().await.take() {
        tokio::task::block_in_place(|| state.worker.stop());
        state.worker.recovery = RecoveryBudget::default();
        state.worker.publish(Health::Inactive);
        SERVICE_FAILURE.lock().take();
    }
}

#[cfg(test)]
mod tests {
    use super::is_sha256;

    #[test]
    fn accepts_only_a_full_hex_digest_for_the_approved_binary() {
        assert!(is_sha256(&"Ab".repeat(32)));
        assert!(!is_sha256(&"ab".repeat(31)));
        assert!(!is_sha256(&"zz".repeat(32)));
    }
}
