use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use super::module_manifest::{
    CompiledModuleRewrites, ModuleDiagnostic, MAX_MANIFEST_BYTES, parse_and_compile_manifest,
};
use crate::config::workspace::{ensure_not_symlink_or_reparse, resolve_workspace_asset};

const MAX_SCAN_DEPTH: usize = 6;
const MAX_MODULES: usize = 32;
const MAX_ASSET_BYTES: usize = 262_144;
const MAX_AGGREGATE_BYTES: usize = 1_048_576;

pub(super) struct VerifiedLiveModule {
    pub(super) manifest_path: String,
    pub(super) id: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) description: Option<String>,
    pub(super) author: Option<String>,
    pub(super) proposed_hostnames: Vec<String>,
    pub(super) script_count: u32,
    pub(super) content_sha256: String,
    pub(super) compiled: CompiledModuleRewrites,
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn collect_manifest_paths(workspace_root: &Path) -> Result<Vec<(String, PathBuf)>> {
    ensure_not_symlink_or_reparse(workspace_root)?;
    if !workspace_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    let mut stack = vec![(workspace_root.to_path_buf(), String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        if depth > MAX_SCAN_DEPTH || ensure_not_symlink_or_reparse(&dir).is_err() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("failed to scan \"{}\"", dir.display())),
        };
        for entry in entries {
            let entry = entry?;
            let os_name = entry.file_name();
            let Some(name) = os_name.to_str() else { continue };
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if ensure_not_symlink_or_reparse(&path).is_err() {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path)?;
            let rel = if prefix.is_empty() { name.to_owned() } else { format!("{prefix}/{name}") };
            if meta.is_dir() {
                stack.push((path, rel, depth + 1));
            } else if meta.is_file() && name == "module.yaml" {
                found.push((rel, path));
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    ensure!(found.len() <= MAX_MODULES, "profile exceeds maximum of {MAX_MODULES} module.yaml files");
    Ok(found)
}

pub(super) fn scan_live_modules(
    workspace_root: &Path,
) -> Result<(Vec<VerifiedLiveModule>, Vec<ModuleDiagnostic>)> {
    let paths = collect_manifest_paths(workspace_root)?;
    let mut total_bytes = 0usize;
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();

    for (rel_path, full_path) in paths {
        let meta = std::fs::symlink_metadata(&full_path)?;
        let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
        if len == 0 || len > MAX_MANIFEST_BYTES {
            diagnostics.push(ModuleDiagnostic {
                manifest_path: rel_path,
                line: None,
                message: format!("module.yaml size must be 1..={MAX_MANIFEST_BYTES} bytes"),
            });
            continue;
        }
        total_bytes = total_bytes.saturating_add(len);
        if total_bytes > MAX_AGGREGATE_BYTES {
            diagnostics.push(ModuleDiagnostic {
                manifest_path: rel_path,
                line: None,
                message: "aggregate module manifest/asset size exceeds 1 MiB".into(),
            });
            break;
        }
        let Ok(raw) = std::fs::read_to_string(&full_path) else {
            diagnostics.push(ModuleDiagnostic {
                manifest_path: rel_path,
                line: None,
                message: "module.yaml must be valid UTF-8".into(),
            });
            continue;
        };
        let (manifest, compiled) = match parse_and_compile_manifest(&rel_path, &raw) {
            Ok(pair) => pair,
            Err(diag) => {
                diagnostics.push(diag);
                continue;
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(b"manifest\0");
        hasher.update(rel_path.as_bytes());
        hasher.update(b"\0");
        hasher.update(raw.as_bytes());

        let mut asset_paths: BTreeSet<String> = BTreeSet::new();
        for script in &manifest.scripts {
            asset_paths.insert(script.script.clone());
        }
        let mut asset_error = None;
        for asset_rel in &asset_paths {
            let resolved = match resolve_workspace_asset(workspace_root, asset_rel) {
                Ok(p) => p,
                Err(err) => {
                    asset_error = Some(err.to_string());
                    break;
                }
            };
            let asset_meta = match std::fs::symlink_metadata(&resolved) {
                Ok(m) if m.is_file() => m,
                _ => {
                    asset_error = Some(format!("referenced script \"{asset_rel}\" does not exist"));
                    break;
                }
            };
            let asset_len = usize::try_from(asset_meta.len()).unwrap_or(usize::MAX);
            if asset_len == 0 || asset_len > MAX_ASSET_BYTES {
                asset_error = Some(format!("script \"{asset_rel}\" must be 1..={MAX_ASSET_BYTES} bytes"));
                break;
            }
            total_bytes = total_bytes.saturating_add(asset_len);
            if total_bytes > MAX_AGGREGATE_BYTES {
                asset_error = Some("aggregate module manifest/asset size exceeds 1 MiB".into());
                break;
            }
            let Ok(asset_text) = std::fs::read_to_string(&resolved) else {
                asset_error = Some(format!("script \"{asset_rel}\" must be valid UTF-8"));
                break;
            };
            hasher.update(b"\0asset\0");
            hasher.update(asset_rel.as_bytes());
            hasher.update(b"\0");
            hasher.update(asset_text.as_bytes());
        }
        if let Some(message) = asset_error {
            diagnostics.push(ModuleDiagnostic {
                manifest_path: rel_path,
                line: None,
                message,
            });
            continue;
        }
        candidates.push(VerifiedLiveModule {
            manifest_path: rel_path,
            id: manifest.id,
            name: manifest.name,
            version: manifest.version,
            description: manifest.description,
            author: manifest.author,
            proposed_hostnames: manifest.mitm.map_or_else(Vec::new, |m| m.hostnames),
            script_count: u32::try_from(manifest.scripts.len()).unwrap_or(u32::MAX),
            content_sha256: hex_lower(&hasher.finalize()),
            compiled,
        });
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for item in &candidates {
        *counts.entry(item.id.as_str()).or_insert(0) += 1;
    }
    let dup_ids: BTreeSet<String> = counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(id, _)| id.to_owned())
        .collect();
    if !dup_ids.is_empty() {
        candidates.retain(|item| {
            if dup_ids.contains(&item.id) {
                diagnostics.push(ModuleDiagnostic {
                    manifest_path: item.manifest_path.clone(),
                    line: None,
                    message: format!("duplicate module ID \"{}\"", item.id),
                });
                return false;
            }
            true
        });
    }
    Ok((candidates, diagnostics))
}
