use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use super::{
    module_discovery::{PinnedScript, VerifiedLiveModule, scan_live_modules},
    module_manifest::{CompiledModuleRewrites, ModuleDiagnostic, sha256_hex, valid_module_id},
    rewrite::{LocalResponseRule, ResponseBodyRule, ResponseHeaderRule, UrlPathRule},
};
use crate::config::workspace::{
    WorkspaceSnapshot, active_workspace_snapshot, ensure_not_symlink_or_reparse, validate_profile_uid,
};

mod script_authorization;
use script_authorization::{ScriptAuthorizations, script_pins_valid};

const MAX_COMPILED_PER_PHASE: usize = 16;
pub(crate) const COMPILED_MODULE_FILE: &str = "compiled-module-rules.json";
const APPROVED_BLOBS_DIR: &str = "approved-blobs";

static SNAPSHOT_REVISION: AtomicU32 = AtomicU32::new(1);
static SCRIPT_AUTHORIZATIONS: parking_lot::Mutex<ScriptAuthorizations> = parking_lot::Mutex::new(ScriptAuthorizations::new());

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum ModuleApprovalState {
    Unapproved,
    Active,
    Disabled,
    UpdatePending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredModulePreview {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub manifest_path: String,
    pub content_sha256: String,
    pub approved_sha256: Option<String>,
    pub enabled: bool,
    pub state: ModuleApprovalState,
    pub proposed_hostnames: Vec<String>,
    pub missing_mitm_hostnames: Vec<String>,
    pub rewrite_count: u32,
    pub script_count: u32,
    pub script_authorization_ready: bool,
    pub script_authorized: bool,
    pub scripts: Vec<ScriptReview>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ScriptReview {
    pub id: String,
    pub phase: String,
    pub host: String,
    pub path: Option<String>,
    pub method: Option<String>,
    pub regex: Option<String>,
    pub source_path: String,
    pub source_sha256: String,
    pub requires_body: bool,
    pub max_size: u32,
    pub timeout: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProfileModulesView {
    pub profile_uid: Option<String>,
    pub modules: Vec<DiscoveredModulePreview>,
    pub diagnostics: Vec<ModuleDiagnostic>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileApprovalStore {
    version: u32,
    #[serde(default)]
    order: Vec<String>,
    #[serde(default)]
    modules: BTreeMap<String, ApprovedModuleEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedModuleEntry {
    enabled: bool,
    approved_sha256: String,
    approved_rewrites: CompiledModuleRewrites,
    // Old stores deserialize with no script pins, requiring a fresh review.
    // These pins do not grant permission to execute scripts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    approved_scripts: Vec<PinnedScript>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CompiledModuleRuleBundle {
    version: u32,
    profile_uid: String,
    revision: u32,
    request: Vec<ResponseHeaderRule>,
    response: Vec<ResponseHeaderRule>,
    path: Vec<UrlPathRule>,
    body: Vec<ResponseBodyRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    local: Vec<LocalResponseRule>,
}

fn approval_file(mitm_dir: &Path, profile_uid: &str) -> Result<PathBuf> {
    validate_profile_uid(profile_uid)?;
    Ok(mitm_dir.join("module-approvals").join(format!("{profile_uid}.json")))
}

fn read_approval_store(mitm_dir: &Path, profile_uid: &str) -> Result<ProfileApprovalStore> {
    let path = approval_file(mitm_dir, profile_uid)?;
    let bytes = match super::settings::read_bounded(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == ErrorKind::NotFound) => {
            return Ok(ProfileApprovalStore { version: 1, ..ProfileApprovalStore::default() });
        }
        Err(err) => return Err(err),
    };
    let parsed: ProfileApprovalStore = serde_json::from_slice(&bytes)?;
    ensure!(parsed.version == 1, "unsupported module approval store version");
    Ok(parsed)
}

fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let rev = SNAPSHOT_REVISION.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".nvmod-{}-{rev}", std::process::id()));
    std::fs::write(&temp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    if let Err(err) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(err.into());
    }
    Ok(())
}

fn valid_hex_sha256(sha: &str) -> bool {
    sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn stage_approved_blobs(mitm_dir: &Path, blobs: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if blobs.is_empty() {
        return Ok(());
    }
    let dir = mitm_dir.join(APPROVED_BLOBS_DIR);
    ensure_not_symlink_or_reparse(mitm_dir)?;
    ensure_not_symlink_or_reparse(&dir)?;
    for (sha, bytes) in blobs {
        ensure!(valid_hex_sha256(sha) && sha256_hex(bytes) == *sha, "invalid approved blob digest");
        let path = dir.join(sha);
        ensure_not_symlink_or_reparse(&path)?;
        write_atomic_private(&path, bytes)?;
    }
    Ok(())
}

fn prune_unreferenced_blobs(mitm_dir: &Path) {
    let blobs_dir = mitm_dir.join(APPROVED_BLOBS_DIR);
    if !blobs_dir.is_dir() {
        return;
    }
    let approvals_dir = mitm_dir.join("module-approvals");
    let mut keep = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir(&approvals_dir) {
        for entry in entries {
            let Ok(entry) = entry else { return };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(raw) = super::settings::read_bounded(&path) else { return };
            let Ok(store) = serde_json::from_slice::<ProfileApprovalStore>(&raw) else { return };
            for rec in store.modules.values() {
                for local in &rec.approved_rewrites.local {
                    keep.insert(local.body_sha256.clone());
                }
                for script in &rec.approved_scripts {
                    keep.insert(script.source_sha256.clone());
                }
            }
        }
    }
    let Ok(blob_entries) = std::fs::read_dir(&blobs_dir) else { return };
    for entry in blob_entries.flatten() {
        let os_name = entry.file_name();
        let Some(name) = os_name.to_str() else { continue };
        if valid_hex_sha256(name) && !keep.contains(name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn order_module_ids<'a>(live: &'a [VerifiedLiveModule], user_order: &[String]) -> Vec<&'a VerifiedLiveModule> {
    let mut ranked: Vec<(usize, &VerifiedLiveModule)> = live
        .iter()
        .map(|m| {
            let pos = user_order.iter().position(|id| id == &m.id).unwrap_or(usize::MAX);
            (pos, m)
        })
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.manifest_path.cmp(&b.1.manifest_path)));
    ranked.into_iter().map(|(_, m)| m).collect()
}

pub(crate) fn write_compiled_snapshot_in_dirs(
    mitm_dir: &Path,
    profile_uid: Option<&str>,
    workspace_root: Option<&Path>,
) -> Result<()> {
    let compiled_path = mitm_dir.join(COMPILED_MODULE_FILE);
    let (Some(uid), Some(ws_root)) = (profile_uid, workspace_root) else {
        match std::fs::remove_file(&compiled_path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    };
    let store = read_approval_store(mitm_dir, uid)?;
    let (live, _) = scan_live_modules(ws_root)?;
    let present_ids: BTreeSet<&str> = live.iter().map(|m| m.id.as_str()).collect();
    let mut ordered_ids: Vec<&str> = store
        .order
        .iter()
        .map(String::as_str)
        .filter(|id| present_ids.contains(id))
        .collect();
    for m in &live {
        if !ordered_ids.contains(&m.id.as_str()) {
            ordered_ids.push(m.id.as_str());
        }
    }

    let mut bundle = CompiledModuleRuleBundle {
        version: 1,
        profile_uid: uid.to_owned(),
        revision: SNAPSHOT_REVISION.fetch_add(1, Ordering::Relaxed),
        request: Vec::new(),
        response: Vec::new(),
        path: Vec::new(),
        body: Vec::new(),
        local: Vec::new(),
    };
    for mod_id in ordered_ids {
        let Some(entry) = store.modules.get(mod_id) else { continue };
        if !entry.enabled {
            continue;
        }
        // Preserve last-known approved rewrites and blobs even if unapproved edits exist on disk.
        let r = &entry.approved_rewrites;
        if bundle.request.len() + r.request.len() <= MAX_COMPILED_PER_PHASE {
            bundle.request.extend(r.request.clone());
        }
        if bundle.response.len() + r.response.len() <= MAX_COMPILED_PER_PHASE {
            bundle.response.extend(r.response.clone());
        }
        if bundle.path.len() + r.path.len() <= MAX_COMPILED_PER_PHASE {
            bundle.path.extend(r.path.clone());
        }
        if bundle.body.len() + r.body.len() <= MAX_COMPILED_PER_PHASE {
            bundle.body.extend(r.body.clone());
        }
        if bundle.local.len() + r.local.len() <= MAX_COMPILED_PER_PHASE {
            bundle.local.extend(r.local.clone());
        }
    }
    if bundle.request.is_empty()
        && bundle.response.is_empty()
        && bundle.path.is_empty()
        && bundle.body.is_empty()
        && bundle.local.is_empty()
    {
        match std::fs::remove_file(&compiled_path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
    write_atomic_private(&compiled_path, &serde_json::to_vec(&bundle)?)
}

pub(crate) fn preview_modules_in_dirs(
    mitm_dir: &Path,
    profile_uid: Option<&str>,
    workspace_root: Option<&Path>,
    active_mitm_hosts: &[String],
) -> Result<ProfileModulesView> {
    let (Some(uid), Some(ws_root)) = (profile_uid, workspace_root) else {
        return Ok(ProfileModulesView {
            profile_uid: profile_uid.map(str::to_owned),
            modules: Vec::new(),
            diagnostics: Vec::new(),
        });
    };
    let store = read_approval_store(mitm_dir, uid)?;
    let (live, diagnostics) = scan_live_modules(ws_root)?;
    let active_set: BTreeSet<&str> = active_mitm_hosts.iter().map(String::as_str).collect();
    let ordered = order_module_ids(&live, &store.order);
    let mut previews = Vec::with_capacity(ordered.len());
    for item in ordered {
        let approved = store.modules.get(&item.id);
        let (enabled, approved_sha256, state) = match approved {
            None => (false, None, ModuleApprovalState::Unapproved),
            Some(rec) if rec.approved_sha256 != item.content_sha256 || rec.approved_scripts != item.scripts => {
                (rec.enabled, Some(rec.approved_sha256.clone()), ModuleApprovalState::UpdatePending)
            }
            Some(rec) if rec.enabled => (true, Some(rec.approved_sha256.clone()), ModuleApprovalState::Active),
            Some(rec) => (false, Some(rec.approved_sha256.clone()), ModuleApprovalState::Disabled),
        };
        let rewrite_total = item.compiled.request.len()
            + item.compiled.response.len()
            + item.compiled.path.len()
            + item.compiled.body.len()
            + item.compiled.local.len();
        let missing = item
            .proposed_hostnames
            .iter()
            .filter(|h| !active_set.contains(h.as_str()))
            .cloned()
            .collect();
        let script_authorization_ready = state == ModuleApprovalState::Active
            && !item.scripts.is_empty()
            && item.scripts.iter().all(|pin| active_set.contains(pin.entry.condition.host.as_str()))
            && script_pins_valid(mitm_dir, &item.scripts);
        previews.push(DiscoveredModulePreview {
            id: item.id.clone(),
            name: item.name.clone(),
            version: item.version.clone(),
            description: item.description.clone(),
            author: item.author.clone(),
            manifest_path: item.manifest_path.clone(),
            content_sha256: item.content_sha256.clone(),
            approved_sha256,
            enabled,
            state,
            proposed_hostnames: item.proposed_hostnames.clone(),
            missing_mitm_hostnames: missing,
            rewrite_count: u32::try_from(rewrite_total).unwrap_or(u32::MAX),
            script_count: u32::try_from(item.scripts.len()).unwrap_or(u32::MAX),
            script_authorization_ready,
            script_authorized: false,
            scripts: item.scripts.iter().map(|pin| ScriptReview {
                id: pin.entry.id.clone(),
                phase: pin.entry.kind.clone(),
                host: pin.entry.condition.host.clone(),
                path: pin.entry.condition.path.clone(),
                method: pin.entry.condition.method.clone(),
                regex: pin.entry.condition.regex.clone(),
                source_path: pin.entry.script.clone(),
                source_sha256: pin.source_sha256.clone(),
                requires_body: pin.entry.requires_body,
                max_size: pin.entry.max_size.unwrap_or(262_144),
                timeout: u32::from(pin.entry.timeout.unwrap_or(1)),
            }).collect(),
        });
    }
    Ok(ProfileModulesView {
        profile_uid: Some(uid.to_owned()),
        modules: previews,
        diagnostics,
    })
}

pub(crate) fn set_module_approval_in_dirs(
    mitm_dir: &Path,
    profile_uid: &str,
    workspace_root: &Path,
    module_id: &str,
    expected_sha256: &str,
    enabled: bool,
    active_mitm_hosts: &[String],
) -> Result<ProfileModulesView> {
    ensure!(valid_module_id(module_id), "invalid module ID");
    let (live, _) = scan_live_modules(workspace_root)?;
    let Some(found) = live.into_iter().find(|m| m.id == module_id) else {
        bail!("module \"{module_id}\" is not present or failed validation");
    };
    ensure!(
        found.content_sha256 == expected_sha256,
        "module files changed since preview; refresh before approving"
    );
    let mut store = read_approval_store(mitm_dir, profile_uid)?;
    store.version = 1;
    if enabled {
        if !store.order.iter().any(|id| id == module_id) {
            store.order.push(module_id.to_owned());
        }
        store.modules.insert(
            module_id.to_owned(),
            ApprovedModuleEntry {
                enabled: true,
                approved_sha256: found.content_sha256,
                approved_rewrites: found.compiled,
                approved_scripts: found.scripts,
            },
        );
    } else {
        // Disabling is not an approval of changed files.
        let entry = store.modules.get_mut(module_id).context("module has no approved revision")?;
        entry.enabled = false;
    }
    let store_bytes = serde_json::to_vec(&store)?;
    ensure!(store_bytes.len() as u64 <= super::settings::MAX_YAML, "module approval store exceeds size limit");
    if enabled {
        stage_approved_blobs(mitm_dir, &found.blobs)?;
    }
    let store_path = approval_file(mitm_dir, profile_uid)?;
    write_atomic_private(&store_path, &store_bytes)?;
    write_compiled_snapshot_in_dirs(mitm_dir, Some(profile_uid), Some(workspace_root))?;
    prune_unreferenced_blobs(mitm_dir);
    preview_modules_in_dirs(mitm_dir, Some(profile_uid), Some(workspace_root), active_mitm_hosts)
}

fn mitm_data_dir() -> Result<PathBuf> {
    ensure!(
        cfg!(all(windows, feature = "verge-dev")) && super::route_runtime::requested(),
        "MITM module management is unavailable"
    );
    Ok(crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev"))
}

pub(crate) fn sync_for_workspace_snapshot(snapshot: &WorkspaceSnapshot) {
    if !cfg!(all(windows, feature = "verge-dev")) || !super::route_runtime::requested() {
        return;
    }
    {
        let mut grants = SCRIPT_AUTHORIZATIONS.lock();
        if active_workspace_snapshot() == *snapshot {
            grants.select(snapshot);
        }
    }
    if let Ok(home) = crate::utils::dirs::app_home_dir() {
        let mitm_dir = home.join("netverge-mitm-dev");
        let _ = write_compiled_snapshot_in_dirs(
            &mitm_dir,
            snapshot.uid.as_deref(),
            snapshot.root.as_deref(),
        );
    }
}

pub async fn get_profile_modules() -> Result<ProfileModulesView> {
    let mitm_dir = mitm_data_dir()?;
    let snap = active_workspace_snapshot();
    let hosts = super::route_runtime::configured_hostnames().await?;
    tokio::task::spawn_blocking(move || {
        let mut grants = SCRIPT_AUTHORIZATIONS.lock();
        ensure!(active_workspace_snapshot() == snap, "active profile changed; reload modules");
        let mut view = preview_modules_in_dirs(&mitm_dir, snap.uid.as_deref(), snap.root.as_deref(), &hosts)?;
        ensure!(active_workspace_snapshot() == snap, "active profile changed; reload modules");
        grants.apply(&snap, &mut view);
        Ok(view)
    })
    .await?
}

pub async fn set_module_approval(
    profile_uid: String,
    module_id: String,
    expected_sha256: String,
    enabled: bool,
) -> Result<ProfileModulesView> {
    let mitm_dir = mitm_data_dir()?;
    let snap = active_workspace_snapshot();
    ensure!(snap.uid.as_deref() == Some(profile_uid.as_str()), "active profile changed; reload modules");
    let hosts = super::route_runtime::configured_hostnames().await?;
    tokio::task::spawn_blocking(move || {
        let mut grants = SCRIPT_AUTHORIZATIONS.lock();
        ensure!(active_workspace_snapshot() == snap, "active profile changed; reload modules");
        let ws_root = snap.root.as_deref().context("active profile has no dedicated workspace")?;
        // Approval/disable is separate from execution consent. Revoke even on
        // an attempted update; approval must never silently carry consent over.
        grants.select(&snap);
        grants.revoke(&module_id);
        let mut view = set_module_approval_in_dirs(
            &mitm_dir,
            &profile_uid,
            ws_root,
            &module_id,
            &expected_sha256,
            enabled,
            &hosts,
        )?;
        ensure!(active_workspace_snapshot() == snap, "active profile changed; reload modules");
        grants.apply(&snap, &mut view);
        Ok(view)
    })
    .await?
}

pub async fn set_script_authorization(
    profile_uid: String,
    module_id: String,
    expected_sha256: String,
    authorized: bool,
) -> Result<ProfileModulesView> {
    let mitm_dir = mitm_data_dir()?;
    ensure!(valid_module_id(&module_id), "invalid module ID");
    let snap = active_workspace_snapshot();
    ensure!(snap.uid.as_deref() == Some(profile_uid.as_str()), "active profile changed; reload modules");
    let hosts = super::route_runtime::configured_hostnames().await?;
    tokio::task::spawn_blocking(move || {
        let mut grants = SCRIPT_AUTHORIZATIONS.lock();
        ensure!(active_workspace_snapshot() == snap, "active profile changed; reload modules");
        grants.select(&snap);
        if !authorized {
            // Revocation does not depend on the current source remaining valid.
            grants.revoke(&module_id);
        }
        let mut view = preview_modules_in_dirs(&mitm_dir, snap.uid.as_deref(), snap.root.as_deref(), &hosts)?;
        ensure!(active_workspace_snapshot() == snap, "active profile changed; reload modules");
        grants.apply(&snap, &mut view);
        if authorized {
            grants.authorize(&snap, &view, &module_id, &expected_sha256)?;
            grants.apply(&snap, &mut view);
        }
        Ok(view)
    })
    .await?
}

#[cfg(test)]
mod tests;
