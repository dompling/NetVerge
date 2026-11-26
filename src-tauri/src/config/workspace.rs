use super::IProfiles;
use anyhow::{Context as _, Result, bail, ensure};
use parking_lot::Mutex;
use std::{
    collections::HashSet,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_UID_LEN: usize = 64;
const MAX_ASSET_REL_LEN: usize = 256;
const MAX_ASSET_DEPTH: usize = 8;

static SWITCH_GENERATION: AtomicU64 = AtomicU64::new(1);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);
static ACTIVE_WORKSPACE: Mutex<WorkspaceSnapshot> = Mutex::new(WorkspaceSnapshot {
    generation: 0,
    uid: None,
    root: None,
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WorkspaceSnapshot {
    pub(crate) generation: u64,
    pub(crate) uid: Option<std::string::String>,
    pub(crate) root: Option<PathBuf>,
}

fn is_windows_reserved_stem(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || matches!(
            stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT")),
            Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        )
}

pub(crate) fn validate_profile_uid(uid: &str) -> Result<()> {
    ensure!(
        !uid.is_empty()
            && uid.len() <= MAX_UID_LEN
            && uid != "."
            && uid != ".."
            && !uid.ends_with(['.', ' '])
            && !is_windows_reserved_stem(uid)
            && uid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "invalid profile UID \"{uid}\""
    );
    Ok(())
}

pub(crate) fn workspace_rel_config(uid: &str) -> Result<std::string::String> {
    validate_profile_uid(uid)?;
    Ok(format!("{uid}/config.yaml"))
}

pub(crate) fn ensure_not_symlink_or_reparse(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("failed to inspect \"{}\"", path.display())),
    };
    ensure!(
        !meta.file_type().is_symlink(),
        "refusing symlink in profile workspace: \"{}\"",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        ensure!(
            meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "refusing reparse point in profile workspace: \"{}\"",
            path.display()
        );
    }
    Ok(())
}

fn valid_single_filename(name: &str) -> bool {
    let mut components = Path::new(name).components();
    !name.is_empty()
        && !name.contains(['/', '\\', ':'])
        && !name.ends_with(['.', ' '])
        && !is_windows_reserved_stem(name)
        && matches!((components.next(), components.next()), (Some(Component::Normal(_)), None))
}

pub(crate) fn validate_profile_rel_file(uid: Option<&str>, file: &str) -> Result<()> {
    if let Some(owner_uid) = file.strip_suffix("/config.yaml") {
        validate_profile_uid(owner_uid)?;
        if let Some(expected_uid) = uid {
            ensure!(
                owner_uid == expected_uid,
                "profile workspace file \"{file}\" does not match owner UID \"{expected_uid}\""
            );
        }
        return Ok(());
    }
    ensure!(
        valid_single_filename(file),
        "profile file must be a single filename or <uid>/config.yaml"
    );
    Ok(())
}

pub(crate) fn resolve_profile_file_in_dir(
    profiles_dir: &Path,
    uid: Option<&str>,
    file: &str,
) -> Result<PathBuf> {
    validate_profile_rel_file(uid, file)?;
    ensure_not_symlink_or_reparse(profiles_dir)?;
    if let Some(owner_uid) = file.strip_suffix("/config.yaml") {
        let ws_dir = profiles_dir.join(owner_uid);
        ensure_not_symlink_or_reparse(&ws_dir)?;
        let target = ws_dir.join("config.yaml");
        ensure_not_symlink_or_reparse(&target)?;
        return Ok(target);
    }
    let target = profiles_dir.join(file);
    ensure_not_symlink_or_reparse(&target)?;
    Ok(target)
}

pub(crate) fn write_profile_file_in_dir(
    profiles_dir: &Path,
    uid: Option<&str>,
    file: &str,
    data: &[u8],
) -> Result<PathBuf> {
    let target = resolve_profile_file_in_dir(profiles_dir, uid, file)?;
    let parent = target
        .parent()
        .context("profile file path is missing parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create profile directory \"{}\"", parent.display()))?;
    ensure_not_symlink_or_reparse(parent)?;
    ensure_not_symlink_or_reparse(&target)?;
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(".nvtmp-{}-{nonce}", std::process::id()));
    std::fs::write(&temp, data)
        .with_context(|| format!("failed to write staged profile file \"{}\"", temp.display()))?;
    if let Err(err) = std::fs::rename(&temp, &target) {
        let _ = std::fs::remove_file(&temp);
        return Err(err).with_context(|| format!("failed to commit profile file \"{}\"", target.display()));
    }
    Ok(target)
}

pub(crate) fn remove_profile_workspace_in_dir(profiles_dir: &Path, uid: &str) -> Result<()> {
    validate_profile_uid(uid)?;
    ensure_not_symlink_or_reparse(profiles_dir)?;
    let ws_dir = profiles_dir.join(uid);
    ensure_not_symlink_or_reparse(&ws_dir)?;
    match std::fs::remove_dir_all(&ws_dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove profile workspace \"{}\"", ws_dir.display())),
    }
}

/// Migrates flat `local`/`remote` profile files (`profiles/<file>.yaml`) into dedicated
/// per-UID workspaces (`profiles/<uid>/config.yaml`). Returns `(changed, obsolete_flat_paths)`;
/// the caller persists `profiles.yaml` first before deleting obsolete flat files.
pub(crate) fn migrate_flat_profiles_in_dir(
    profiles_dir: &Path,
    profiles: &mut IProfiles,
) -> Result<(bool, Vec<PathBuf>)> {
    ensure_not_symlink_or_reparse(profiles_dir)?;
    let Some(items) = profiles.items.as_mut() else {
        return Ok((false, Vec::new()));
    };
    let mut changed = false;
    let mut candidates: Vec<(std::string::String, PathBuf)> = Vec::new();
    for item in items.iter_mut() {
        if !matches!(item.itype.as_deref(), Some("local" | "remote")) {
            continue;
        }
        let Some(uid) = item.uid.as_deref().map(str::to_owned) else {
            continue;
        };
        if validate_profile_uid(&uid).is_err() {
            continue;
        }
        let target_rel = format!("{uid}/config.yaml");
        if item.file.as_deref() == Some(target_rel.as_str()) {
            let ws_dir = profiles_dir.join(&uid);
            ensure_not_symlink_or_reparse(&ws_dir)?;
            if !ws_dir.exists() {
                std::fs::create_dir_all(&ws_dir)?;
            }
            continue;
        }
        let Some(old_file) = item.file.as_deref().map(str::to_owned) else {
            continue;
        };
        if !valid_single_filename(&old_file) {
            continue;
        }
        let legacy_path = profiles_dir.join(&old_file);
        ensure_not_symlink_or_reparse(&legacy_path)?;
        let ws_config = resolve_profile_file_in_dir(profiles_dir, Some(&uid), &target_rel)?;
        if legacy_path.is_file() {
            let bytes = std::fs::read(&legacy_path)
                .with_context(|| format!("failed to read legacy profile \"{}\"", legacy_path.display()))?;
            write_profile_file_in_dir(profiles_dir, Some(&uid), &target_rel, &bytes)?;
            item.file = Some(target_rel.into());
            changed = true;
            candidates.push((old_file, legacy_path));
        } else if ws_config.is_file() {
            item.file = Some(target_rel.into());
            changed = true;
        }
    }
    let still_referenced: HashSet<&str> = items
        .iter()
        .filter_map(|item| item.file.as_deref())
        .collect();
    let obsolete = candidates
        .into_iter()
        .filter(|(name, _)| !still_referenced.contains(name.as_str()))
        .map(|(_, path)| path)
        .collect();
    Ok((changed, obsolete))
}

/// Resolves a forward-slash relative asset path strictly inside `workspace_root`
/// (the directory containing the active profile's `config.yaml`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn resolve_workspace_asset(workspace_root: &Path, rel_path: &str) -> Result<PathBuf> {
    ensure!(
        !rel_path.is_empty()
            && rel_path.len() <= MAX_ASSET_REL_LEN
            && !rel_path.starts_with('/')
            && !rel_path.ends_with('/')
            && !rel_path.contains(['\\', ':', '\0']),
        "invalid profile-relative asset path \"{rel_path}\""
    );
    ensure_not_symlink_or_reparse(workspace_root)?;
    let canon_root = dunce::canonicalize(workspace_root)
        .with_context(|| format!("workspace root \"{}\" is unavailable", workspace_root.display()))?;
    let mut current = workspace_root.to_path_buf();
    let mut depth = 0usize;
    for segment in rel_path.split('/') {
        depth += 1;
        ensure!(
            depth <= MAX_ASSET_DEPTH && valid_single_filename(segment),
            "invalid segment in profile-relative asset path \"{rel_path}\""
        );
        current.push(segment);
        ensure_not_symlink_or_reparse(&current)?;
    }
    if current.exists() {
        let canon_target = dunce::canonicalize(&current)?;
        ensure!(
            canon_target.starts_with(&canon_root),
            "asset path escapes active profile workspace"
        );
    } else if let Some(parent) = current.parent()
        && parent.exists()
    {
        let canon_parent = dunce::canonicalize(parent)?;
        ensure!(
            canon_parent.starts_with(&canon_root),
            "asset parent escapes active profile workspace"
        );
    }
    Ok(current)
}

pub(crate) fn begin_workspace_switch() -> u64 {
    SWITCH_GENERATION.fetch_add(1, Ordering::AcqRel) + 1
}

pub(crate) fn sync_active_workspace(
    expected_generation: Option<u64>,
    profiles: &IProfiles,
    profiles_dir: &Path,
) -> Result<WorkspaceSnapshot> {
    let mut guard = ACTIVE_WORKSPACE.lock();
    let current_gen = SWITCH_GENERATION.load(Ordering::Acquire);
    if let Some(expected) = expected_generation {
        ensure!(expected == current_gen, "stale profile workspace switch generation");
    }
    let (uid, root) = match profiles.current.as_deref() {
        Some(active_uid) => {
            let item = profiles.get_item(active_uid)?;
            if matches!(item.itype.as_deref(), Some("local" | "remote")) {
                validate_profile_uid(active_uid)?;
                let ws_root = profiles_dir.join(active_uid);
                ensure_not_symlink_or_reparse(&ws_root)?;
                (Some(active_uid.to_owned()), Some(ws_root))
            } else {
                (Some(active_uid.to_owned()), None)
            }
        }
        None => (None, None),
    };
    let next = WorkspaceSnapshot {
        generation: current_gen,
        uid,
        root,
    };
    *guard = next.clone();
    Ok(next)
}

#[cfg(test)]
pub(crate) fn active_workspace_snapshot() -> WorkspaceSnapshot {
    ACTIVE_WORKSPACE.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PrfExtra, PrfItem, PrfOption, PrfSelected};

    fn temp_profiles_dir(tag: &str) -> Result<PathBuf> {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("nv-ws-{tag}-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn migrates_flat_profiles_and_preserves_metadata_and_adjacent_modules() -> Result<()> {
        let dir = temp_profiles_dir("migrate")?;
        let result = (|| -> Result<()> {
            std::fs::write(dir.join("L100.yaml"), b"proxies: []\n")?;
            std::fs::write(dir.join("R200.yaml"), b"proxies: [{name: old}]\n")?;
            std::fs::write(dir.join("m100.yaml"), b"# merge\n")?;

            let selected = vec![PrfSelected {
                name: Some("PROXY".into()),
                now: Some("node-a".into()),
            }];
            let mut profiles = IProfiles {
                current: Some("R200".into()),
                items: Some(vec![
                    PrfItem {
                        uid: Some("L100".into()),
                        itype: Some("local".into()),
                        name: Some("Local".into()),
                        file: Some("L100.yaml".into()),
                        ..PrfItem::default()
                    },
                    PrfItem {
                        uid: Some("R200".into()),
                        itype: Some("remote".into()),
                        name: Some("Sub".into()),
                        file: Some("R200.yaml".into()),
                        url: Some("https://sub.example.test/clash.yaml".into()),
                        selected: Some(selected.clone()),
                        extra: Some(PrfExtra {
                            upload: 10,
                            download: 20,
                            total: 100,
                            expire: 999,
                        }),
                        option: Some(PrfOption {
                            merge: Some("m100".into()),
                            ..PrfOption::default()
                        }),
                        ..PrfItem::default()
                    },
                    PrfItem {
                        uid: Some("m100".into()),
                        itype: Some("merge".into()),
                        file: Some("m100.yaml".into()),
                        ..PrfItem::default()
                    },
                ]),
            };

            let (changed, obsolete) = migrate_flat_profiles_in_dir(&dir, &mut profiles)?;
            assert!(changed);
            assert_eq!(obsolete.len(), 2);
            for old in &obsolete {
                std::fs::remove_file(old)?;
            }

            assert_eq!(profiles.current.as_deref(), Some("R200"));
            let remote = profiles.get_item("R200")?;
            assert_eq!(remote.file.as_deref(), Some("R200/config.yaml"));
            assert_eq!(remote.url.as_deref(), Some("https://sub.example.test/clash.yaml"));
            assert_eq!(remote.selected, Some(selected));
            assert_eq!(profiles.get_item("m100")?.file.as_deref(), Some("m100.yaml"));
            assert!(dir.join("m100.yaml").is_file());
            assert!(!dir.join("R200.yaml").exists());
            assert_eq!(std::fs::read(dir.join("R200").join("config.yaml"))?, b"proxies: [{name: old}]\n");

            // Adjacent local modules/scripts survive remote subscription refreshes.
            let mod_dir = dir.join("R200").join("modules").join("api-debug");
            std::fs::create_dir_all(&mod_dir)?;
            std::fs::write(mod_dir.join("module.yaml"), b"kind: netverge-module\n")?;
            write_profile_file_in_dir(&dir, Some("R200"), "R200/config.yaml", b"proxies: [{name: refreshed}]\n")?;
            assert_eq!(
                std::fs::read(dir.join("R200").join("config.yaml"))?,
                b"proxies: [{name: refreshed}]\n"
            );
            assert_eq!(
                std::fs::read(mod_dir.join("module.yaml"))?,
                b"kind: netverge-module\n"
            );
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn enforces_workspace_relative_asset_boundaries_and_switch_generations() -> Result<()> {
        let dir = temp_profiles_dir("assets")?;
        let result = (|| -> Result<()> {
            let ws_a = dir.join("prof-a");
            let ws_b = dir.join("prof-b");
            std::fs::create_dir_all(ws_a.join("modules/debug"))?;
            std::fs::create_dir_all(&ws_b)?;
            std::fs::write(ws_a.join("config.yaml"), b"proxies: []\n")?;
            std::fs::write(ws_b.join("config.yaml"), b"proxies: []\n")?;
            std::fs::write(ws_a.join("modules/debug/run.js"), b"$done({});\n")?;

            let resolved = resolve_workspace_asset(&ws_a, "modules/debug/run.js")?;
            assert_eq!(resolved, ws_a.join("modules").join("debug").join("run.js"));

            for invalid in [
                "",
                "/modules/debug/run.js",
                "modules/debug/",
                "../prof-b/config.yaml",
                "modules/../../prof-b/config.yaml",
                "./config.yaml",
                r"modules\debug\run.js",
                "C:config.yaml",
                "CON.js",
            ] {
                assert!(resolve_workspace_asset(&ws_a, invalid).is_err(), "expected rejection for {invalid}");
            }
            assert!(validate_profile_rel_file(Some("prof-a"), "prof-b/config.yaml").is_err());

            let mut profiles = IProfiles {
                current: Some("prof-a".into()),
                items: Some(vec![
                    PrfItem {
                        uid: Some("prof-a".into()),
                        itype: Some("local".into()),
                        file: Some("prof-a/config.yaml".into()),
                        ..PrfItem::default()
                    },
                    PrfItem {
                        uid: Some("prof-b".into()),
                        itype: Some("local".into()),
                        file: Some("prof-b/config.yaml".into()),
                        ..PrfItem::default()
                    },
                ]),
            };

            let gen1 = begin_workspace_switch();
            let snap_a = sync_active_workspace(Some(gen1), &profiles, &dir)?;
            assert_eq!(snap_a.uid.as_deref(), Some("prof-a"));
            assert_eq!(snap_a.root, Some(ws_a.clone()));

            // Newer switch supersedes stale generation; rollback restores prof-a.
            let stale_gen = begin_workspace_switch();
            let current_gen = begin_workspace_switch();
            profiles.current = Some("prof-b".into());
            assert!(sync_active_workspace(Some(stale_gen), &profiles, &dir).is_err());
            let snap_b = sync_active_workspace(Some(current_gen), &profiles, &dir)?;
            assert_eq!(snap_b.uid.as_deref(), Some("prof-b"));
            assert_eq!(snap_b.root, Some(ws_b));

            profiles.current = Some("prof-a".into());
            let rolled_back = sync_active_workspace(None, &profiles, &dir)?;
            assert_eq!(rolled_back.uid.as_deref(), Some("prof-a"));
            assert_eq!(active_workspace_snapshot().root, Some(ws_a));
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}
