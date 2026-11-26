use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use super::{
    module_discovery::{VerifiedLiveModule, scan_live_modules},
    module_manifest::{CompiledModuleRewrites, ModuleDiagnostic, valid_module_id},
    rewrite::{ResponseBodyRule, ResponseHeaderRule, UrlPathRule},
};
use crate::config::workspace::{
    WorkspaceSnapshot, active_workspace_snapshot, validate_profile_uid,
};

const MAX_COMPILED_PER_PHASE: usize = 16;
pub(crate) const COMPILED_MODULE_FILE: &str = "compiled-module-rules.json";

static SNAPSHOT_REVISION: AtomicU32 = AtomicU32::new(1);

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
    let mut present_ids: BTreeSet<&str> = BTreeSet::new();
    for m in &live {
        present_ids.insert(m.id.as_str());
    }
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
    };
    for mod_id in ordered_ids {
        let Some(entry) = store.modules.get(mod_id) else { continue };
        if !entry.enabled {
            continue;
        }
        // Preserve last-known approved rewrites even if unapproved edits exist on disk.
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
    }
    if bundle.request.is_empty() && bundle.response.is_empty() && bundle.path.is_empty() && bundle.body.is_empty() {
        match std::fs::remove_file(&compiled_path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
    let json = serde_json::to_vec(&bundle)?;
    write_atomic_private(&compiled_path, &json)
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
            Some(rec) if rec.approved_sha256 != item.content_sha256 => {
                (rec.enabled, Some(rec.approved_sha256.clone()), ModuleApprovalState::UpdatePending)
            }
            Some(rec) if rec.enabled => (true, Some(rec.approved_sha256.clone()), ModuleApprovalState::Active),
            Some(rec) => (false, Some(rec.approved_sha256.clone()), ModuleApprovalState::Disabled),
        };
        let rewrite_total = item.compiled.request.len()
            + item.compiled.response.len()
            + item.compiled.path.len()
            + item.compiled.body.len();
        let missing = item
            .proposed_hostnames
            .iter()
            .filter(|h| !active_set.contains(h.as_str()))
            .cloned()
            .collect();
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
            script_count: item.script_count,
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
    if !store.order.iter().any(|id| id == module_id) {
        store.order.push(module_id.to_owned());
    }
    store.modules.insert(
        module_id.to_owned(),
        ApprovedModuleEntry {
            enabled,
            approved_sha256: found.content_sha256,
            approved_rewrites: found.compiled,
        },
    );
    let store_path = approval_file(mitm_dir, profile_uid)?;
    write_atomic_private(&store_path, &serde_json::to_vec(&store)?)?;
    write_compiled_snapshot_in_dirs(mitm_dir, Some(profile_uid), Some(workspace_root))?;
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
        preview_modules_in_dirs(&mitm_dir, snap.uid.as_deref(), snap.root.as_deref(), &hosts)
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
    let ws_root = snap.root.context("active profile has no dedicated workspace")?;
    let hosts = super::route_runtime::configured_hostnames().await?;
    tokio::task::spawn_blocking(move || {
        set_module_approval_in_dirs(
            &mitm_dir,
            &profile_uid,
            &ws_root,
            &module_id,
            &expected_sha256,
            enabled,
            &hosts,
        )
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_validates_approves_preserves_on_edit_and_switches_profiles() -> Result<()> {
        let rev = SNAPSHOT_REVISION.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("nv-mod-mgr-{}-{rev}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        let result = (|| -> Result<()> {
            let mitm_dir = root.join("mitm");
            let ws_a = root.join("profiles/prof-a");
            let ws_b = root.join("profiles/prof-b");
            std::fs::create_dir_all(ws_a.join("modules/debug"))?;
            std::fs::create_dir_all(ws_a.join("scripts"))?;
            std::fs::create_dir_all(&ws_b)?;
            std::fs::write(ws_a.join("scripts/hook.js"), b"$done({});\n")?;
            std::fs::write(
                ws_a.join("module.yaml"),
                "kind: netverge-module\nschema: 1\nid: com.example.root\nname: Root\nversion: '1.0'\nrewrite:\n  - id: r1\n    type: url\n    match:\n      host: api.example.test\n      path: /old\n    action:\n      replace: /new\n",
            )?;
            std::fs::write(
                ws_a.join("modules/debug/module.yaml"),
                "kind: netverge-module\nschema: 1\nid: com.example.debug\nname: Debug\nversion: '1.0'\nmitm:\n  hostnames:\n    - extra.example.test\nrewrite:\n  - id: h1\n    type: response-header\n    match:\n      host: api.example.test\n      path: /demo\n    action:\n      set:\n        X-Module: v1\nscripts:\n  - id: s1\n    type: http-response\n    match:\n      host: api.example.test\n    script: scripts/hook.js\n",
            )?;

            let preview = preview_modules_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a), &[])?;
            assert!(preview.diagnostics.is_empty());
            assert_eq!(preview.modules.len(), 2);
            assert_eq!(preview.modules[0].id, "com.example.root");
            assert_eq!(preview.modules[1].id, "com.example.debug");
            assert_eq!(preview.modules[1].state, ModuleApprovalState::Unapproved);
            assert_eq!(preview.modules[1].missing_mitm_hostnames, vec!["extra.example.test"]);
            assert!(!mitm_dir.join(COMPILED_MODULE_FILE).exists());

            assert!(set_module_approval_in_dirs(&mitm_dir, "prof-a", &ws_a, "com.example.debug", "stale", true, &[]).is_err());
            let sha = preview.modules[1].content_sha256.clone();
            let active = set_module_approval_in_dirs(&mitm_dir, "prof-a", &ws_a, "com.example.debug", &sha, true, &[])?;
            assert_eq!(active.modules[0].id, "com.example.debug");
            assert_eq!(active.modules[0].state, ModuleApprovalState::Active);

            // Editing the referenced script marks UpdatePending while retaining last approved rules.
            std::fs::write(ws_a.join("scripts/hook.js"), b"$done({ edited: true });\n")?;
            let edited = preview_modules_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a), &[])?;
            assert_eq!(edited.modules[0].state, ModuleApprovalState::UpdatePending);
            write_compiled_snapshot_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a))?;
            let compiled_bytes = std::fs::read_to_string(mitm_dir.join(COMPILED_MODULE_FILE))?;
            assert!(compiled_bytes.contains("\"v1\""));

            // Profile switch to prof-b clears prof-a's compiled module rules; rollback restores them.
            write_compiled_snapshot_in_dirs(&mitm_dir, Some("prof-b"), Some(&ws_b))?;
            assert!(!mitm_dir.join(COMPILED_MODULE_FILE).exists());
            write_compiled_snapshot_in_dirs(&mitm_dir, Some("prof-a"), Some(&ws_a))?;
            assert!(mitm_dir.join(COMPILED_MODULE_FILE).exists());
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&root);
        result
    }
}
