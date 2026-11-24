//! Restart-scoped local configuration. Only an explicit developer bootstrap
//! may select executable paths. IPC can stage domains and policy, never paths.
use super::{LocalConfig, MitmSettings, PROXY, RETURN, valid_host};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::{Path, PathBuf}, sync::OnceLock};
use tokio::sync::Semaphore;

pub(super) const FILE_NAME: &str = "netverge-mitm-config.yaml";
const MAX_YAML: u64 = 65536;
static BOOT: OnceLock<std::result::Result<Boot, String>> = OnceLock::new();
static SAVE: Semaphore = Semaphore::const_new(1);

#[derive(Clone)]
struct Boot {
    bootstrap: LocalConfig,
    bootstrap_sha256: String,
    active: LocalConfig,
    saved_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Saved {
    bootstrap_sha256: String,
    mitm: MitmSettings,
}

#[derive(Serialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct MitmConfigView {
    available: bool,
    active: Option<MitmSettings>,
    saved: Option<MitmSettings>,
    revision: Option<String>,
    restart_required: bool,
    policies: Vec<String>,
}

pub(super) fn valid_policy(policy: &str) -> bool {
    !policy.is_empty() && policy.len() <= 256 && policy.trim() == policy
        && !policy.chars().any(|c| c.is_control() || matches!(c, ',' | '(' | ')'))
        && ![PROXY, RETURN, "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"].iter()
            .any(|name| policy.eq_ignore_ascii_case(name))
}

pub(super) fn validate_selection(selection: &MitmSettings) -> Result<()> {
    ensure!(selection.hostname.len() <= 64 && selection.hostname.iter().all(|host| valid_host(host)),
        "MITM requires at most 64 exact lowercase DNS hostnames");
    ensure!(selection.hostname.iter().collect::<BTreeSet<_>>().len() == selection.hostname.len(),
        "duplicate MITM hostname");
    if let Some(policy) = selection.policy.as_deref() {
        ensure!(valid_policy(policy), "invalid MITM return policy");
    }
    if selection.enable {
        ensure!(!selection.hostname.is_empty(), "enabled MITM requires at least one hostname");
        ensure!(selection.policy.is_some(), "enabled MITM requires an explicit return policy");
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let stat = std::fs::symlink_metadata(path)?;
    ensure!(stat.is_file() && stat.len() <= MAX_YAML, "invalid MITM local configuration file");
    let mut file = std::fs::File::open(path)?.take(MAX_YAML + 1);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_YAML, "MITM local configuration exceeds limit");
    Ok(bytes)
}

fn decode_saved(bytes: &[u8], expected_bootstrap: &str) -> Result<MitmSettings> {
    let saved: Saved = serde_yaml_ng::from_slice(bytes).context("invalid saved MITM YAML")?;
    ensure!(saved.bootstrap_sha256 == expected_bootstrap,
        "MITM bootstrap changed; review the local configuration before restarting");
    validate_selection(&saved.mitm)?;
    Ok(saved.mitm)
}

fn read_saved(boot: &Boot) -> Result<MitmSettings> {
    match read_bounded(&boot.saved_path) {
        Ok(bytes) => decode_saved(&bytes, &boot.bootstrap_sha256),
        Err(err) if err.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => Ok(boot.bootstrap.mitm.clone()),
        Err(err) => Err(err),
    }
}

fn load_boot() -> Result<Boot> {
    let path = PathBuf::from(std::env::var_os("NETVERGE_MITM_DEV_CONFIG")
        .context("MITM developer bootstrap is not configured")?);
    ensure!(path.is_absolute(), "NETVERGE_MITM_DEV_CONFIG must be an absolute path");
    let bytes = read_bounded(&path)?;
    let bootstrap: LocalConfig = serde_yaml_ng::from_slice(&bytes).context("invalid local MITM YAML")?;
    validate_selection(&bootstrap.mitm)?;
    let mut boot = Boot {
        active: bootstrap.clone(),
        bootstrap,
        bootstrap_sha256: digest(&bytes),
        saved_path: crate::utils::dirs::app_home_dir()?.join(FILE_NAME),
    };
    boot.active.mitm = read_saved(&boot)?;
    boot.active.clone().into_settings()?;
    Ok(boot)
}

fn boot() -> Result<&'static Boot> {
    match BOOT.get_or_init(|| load_boot().map_err(|err| err.to_string())) {
        Ok(boot) => Ok(boot),
        Err(message) => anyhow::bail!("{message}"),
    }
}

// Immutable within a process, including TUN toggles/profile reloads. Saving a
// future configuration cannot change a live overlay or spawn a new worker.
pub(super) fn boot_settings() -> Result<LocalConfig> {
    Ok(boot()?.active.clone())
}

fn revision(bootstrap_sha256: &str, selection: &MitmSettings) -> Result<String> {
    let bytes = serde_json::to_vec(&(bootstrap_sha256, selection))?;
    Ok(digest(&bytes))
}

fn policy_names(config: Option<&Mapping>) -> Vec<String> {
    let mut names = BTreeSet::from(["DIRECT".to_owned()]);
    if let Some(config) = config {
        for key in ["proxies", "proxy-groups"] {
            if let Some(items) = config.get(key).and_then(Value::as_sequence) {
                for item in items {
                    if let Some(name) = item.get("name").and_then(Value::as_str).filter(|name| valid_policy(name)) {
                        names.insert(name.to_owned());
                    }
                }
            }
        }
    }
    names.into_iter().collect()
}

async fn policies() -> Vec<String> {
    let runtime = crate::config::Config::runtime().await.data_arc();
    policy_names(runtime.config.as_ref())
}

fn view(boot: &Boot, saved: MitmSettings, policies: Vec<String>) -> Result<MitmConfigView> {
    let revision = revision(&boot.bootstrap_sha256, &saved)?;
    Ok(MitmConfigView {
        available: true,
        restart_required: saved != boot.active.mitm,
        active: Some(boot.active.mitm.clone()),
        saved: Some(saved),
        revision: Some(revision),
        policies,
    })
}

pub(crate) async fn inspect() -> Result<MitmConfigView> {
    if !cfg!(any(windows, target_os = "macos")) || !super::development_requested() {
        return Ok(MitmConfigView {
            available: false, active: None, saved: None, revision: None,
            restart_required: false, policies: Vec::new(),
        });
    }
    let names = policies().await;
    tokio::task::spawn_blocking(move || {
        let boot = boot()?;
        view(boot, read_saved(boot)?, names)
    }).await?
}

fn check_candidate(boot: &Boot, candidate: &MitmSettings, names: &[String]) -> Result<()> {
    validate_selection(candidate)?;
    if candidate.enable {
        let mut proposed = boot.bootstrap.clone();
        proposed.mitm = candidate.clone();
        proposed.into_settings()?;
        ensure!(candidate.policy.as_ref().is_some_and(|policy| names.contains(policy)),
            "MITM return policy is not in the current applied profile");
    }
    Ok(())
}

pub(crate) async fn save(expected_revision: String, candidate: MitmSettings) -> Result<Option<MitmConfigView>> {
    ensure!(cfg!(any(windows, target_os = "macos")) && super::development_requested(),
        "MITM developer bootstrap is not configured on this platform");
    let _permit = SAVE.try_acquire().context("MITM settings save already running")?;
    let (boot, previous) = tokio::task::spawn_blocking(|| -> Result<_> {
        let boot = boot()?;
        Ok((boot, read_saved(boot)?))
    }).await??;
    ensure!(revision(&boot.bootstrap_sha256, &previous)? == expected_revision,
        "MITM settings changed; refresh before saving");
    let names = policies().await;
    check_candidate(boot, &candidate, &names)?;
    if previous == candidate {
        return Ok(Some(view(boot, previous, names)?));
    }
    // Confirmation is native, includes the actual scope, and is required for
    // every change. It cannot be bypassed by a frontend boolean.
    let description = format!(
        "Save MITM configuration for the next full NetVerge restart?\n\nEnabled: {}\nHostnames: {}\nReturn policy: {}\n\nSelected HTTPS connections will be decrypted if enabled. The selected policy overrides their original routing rules. Saving does not change the current engine, install trust, or enable TUN.",
        candidate.enable,
        candidate.hostname.join(", "),
        candidate.policy.as_deref().unwrap_or("(none)"),
    );
    let answer = rfd::AsyncMessageDialog::new()
        .set_title("Save NetVerge MITM configuration")
        .set_description(description)
        .set_level(rfd::MessageLevel::Warning)
        .set_buttons(rfd::MessageButtons::OkCancel)
        .show().await;
    if answer != rfd::MessageDialogResult::Ok {
        return Ok(None);
    }
    let names = policies().await;
    check_candidate(boot, &candidate, &names)?;
    let current = tokio::task::spawn_blocking(move || read_saved(boot)).await??;
    ensure!(revision(&boot.bootstrap_sha256, &current)? == expected_revision,
        "MITM settings changed while confirming; refresh before saving");
    let yaml = serde_yaml_ng::to_string(&Saved {
        bootstrap_sha256: boot.bootstrap_sha256.clone(),
        mitm: candidate.clone(),
    })?;
    ensure!(yaml.len() as u64 <= MAX_YAML, "MITM settings exceed size limit");
    crate::utils::help::save_yaml_str_private(&boot.saved_path, &yaml, Some("# NetVerge local MITM configuration; apply on next application start")).await?;
    Ok(Some(view(boot, candidate, names)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection(enable: bool, hosts: &[&str], policy: Option<&str>) -> MitmSettings {
        MitmSettings { enable, hostname: hosts.iter().map(|host| (*host).into()).collect(), policy: policy.map(str::to_owned) }
    }

    #[test]
    fn validates_domains_policy_and_disabled_empty_config() -> Result<()> {
        validate_selection(&selection(false, &[], None))?;
        validate_selection(&selection(true, &["api.example.test"], Some("DIRECT")))?;
        for host in ["*.example.test", "https://example.test", "127.0.0.1", "UPPER.test"] {
            assert!(validate_selection(&selection(true, &[host], Some("DIRECT"))).is_err());
        }
        assert!(validate_selection(&selection(true, &["a.test", "a.test"], Some("DIRECT"))).is_err());
        assert!(validate_selection(&selection(true, &[], Some("DIRECT"))).is_err());
        assert!(validate_selection(&selection(true, &["a.test"], None)).is_err());
        for policy in ["NETVERGE-MITM", "netverge-return", "REJECT", "foo,bar", "foo\nbar"] {
            assert!(validate_selection(&selection(true, &["a.test"], Some(policy))).is_err());
        }
        Ok(())
    }

    #[test]
    fn saved_scope_binds_bootstrap_and_rejects_runtime_injection() -> Result<()> {
        let selected = selection(true, &["a.test"], Some("DIRECT"));
        let yaml = serde_yaml_ng::to_string(&Saved { bootstrap_sha256: "first".into(), mitm: selected.clone() })?;
        assert_eq!(decode_saved(yaml.as_bytes(), "first")?, selected);
        assert!(decode_saved(yaml.as_bytes(), "other").is_err());
        assert!(decode_saved(format!("{yaml}\nruntime: {{node: /tmp/evil}}").as_bytes(), "first").is_err());
        assert_ne!(revision("first", &selected)?, revision("other", &selected)?);
        Ok(())
    }

    #[test]
    fn config_save_does_not_modify_active_snapshot_or_export_runtime() -> Result<()> {
        let path = std::env::current_exe()?;
        let bootstrap: LocalConfig = serde_yaml_ng::from_value(serde_yaml_ng::to_value(serde_json::json!({
            "mitm": {"enable": false},
            "runtime": {"node": path, "worker": path, "port": 18899, "return-port": 18900}
        }))?)?;
        let boot = Boot { active: bootstrap.clone(), bootstrap, bootstrap_sha256: "first".into(), saved_path: PathBuf::new() };
        let candidate = selection(true, &["a.test"], Some("DIRECT"));
        let names = vec!["DIRECT".into()];
        check_candidate(&boot, &candidate, &names)?;
        let state = view(&boot, candidate, names)?;
        assert!(state.restart_required);
        assert!(!boot.active.mitm.enable);
        let wire = serde_json::to_value(state)?;
        assert_eq!(wire["active"]["enable"], false);
        assert_eq!(wire["saved"]["enable"], true);
        assert!(wire.get("runtime").is_none());
        assert!(wire.get("savedPath").is_none());
        Ok(())
    }

    #[test]
    fn policy_choices_exclude_reserved_and_invalid_names() -> Result<()> {
        let mapping: Mapping = serde_yaml_ng::from_str("proxies: [{name: node-a}, {name: NETVERGE-MITM}]\nproxy-groups: [{name: Work}, {name: 'bad,name'}]\n")?;
        assert_eq!(policy_names(Some(&mapping)), vec!["DIRECT", "Work", "node-a"]);
        assert!(super::super::validate_backup_entry(FILE_NAME, None).is_err());
        Ok(())
    }
}
