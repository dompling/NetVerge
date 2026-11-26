use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{ErrorKind, Read as _},
    path::{Path, PathBuf},
};

use super::module_manifest::{
    CompiledManifestOutput, CompiledModuleRewrites, MAX_MANIFEST_BYTES, ModuleDiagnostic,
    parse_and_compile_manifest, sha256_hex,
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
    pub(super) blobs: BTreeMap<String, Vec<u8>>,
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

fn read_bounded_asset(
    workspace_root: &Path,
    asset_rel: &str,
    allow_empty: bool,
    label: &str,
    total_bytes: &mut usize,
) -> std::result::Result<Vec<u8>, String> {
    let resolved = resolve_workspace_asset(workspace_root, asset_rel).map_err(|e| e.to_string())?;
    let meta = match std::fs::symlink_metadata(&resolved) {
        Ok(m) if m.is_file() => m,
        _ => return Err(format!("referenced {label} \"{asset_rel}\" does not exist")),
    };
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if (!allow_empty && len == 0) || len > MAX_ASSET_BYTES {
        let min = usize::from(!allow_empty);
        return Err(format!("{label} \"{asset_rel}\" must be {min}..={MAX_ASSET_BYTES} bytes"));
    }
    *total_bytes = total_bytes.saturating_add(len);
    if *total_bytes > MAX_AGGREGATE_BYTES {
        return Err("aggregate module manifest/asset size exceeds 1 MiB".into());
    }
    let mut bytes = Vec::with_capacity(len);
    let read_res = std::fs::File::open(&resolved)
        .and_then(|f| f.take((MAX_ASSET_BYTES + 1) as u64).read_to_end(&mut bytes));
    if read_res.is_err() || bytes.len() != len {
        return Err(format!("failed to read {label} \"{asset_rel}\" cleanly"));
    }
    Ok(bytes)
}

fn verify_and_hash_assets(
    workspace_root: &Path,
    rel_path: &str,
    raw: &str,
    parsed: &mut CompiledManifestOutput,
    total_bytes: &mut usize,
) -> std::result::Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(b"manifest\0");
    hasher.update(rel_path.as_bytes());
    hasher.update(b"\0");
    hasher.update(raw.as_bytes());

    let script_paths: BTreeSet<&str> = parsed.manifest.scripts.iter().map(|s| s.script.as_str()).collect();
    for script_rel in script_paths {
        let bytes = read_bounded_asset(workspace_root, script_rel, false, "script", total_bytes)?;
        if std::str::from_utf8(&bytes).is_err() {
            return Err(format!("script \"{script_rel}\" must be valid UTF-8"));
        }
        hasher.update(b"\0asset\0");
        hasher.update(script_rel.as_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
    }

    let map_paths: BTreeSet<&str> = parsed.map_local_files.iter().map(|(_, p)| p.as_str()).collect();
    let mut resolved_blobs: BTreeMap<&str, (String, u32)> = BTreeMap::new();
    for file_rel in map_paths {
        let bytes = read_bounded_asset(workspace_root, file_rel, true, "map-local file", total_bytes)?;
        hasher.update(b"\0map-local\0");
        hasher.update(file_rel.as_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
        let sha = sha256_hex(&bytes);
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        if !bytes.is_empty() {
            parsed.inline_blobs.insert(sha.clone(), bytes);
        }
        resolved_blobs.insert(file_rel, (sha, len));
    }
    for (idx, file_rel) in &parsed.map_local_files {
        if let Some((sha, len)) = resolved_blobs.get(file_rel.as_str())
            && let Some(rule) = parsed.rewrites.local.get_mut(*idx)
        {
            rule.body_sha256.clone_from(sha);
            rule.body_len = *len;
        }
    }
    let mut hex = String::with_capacity(64);
    for b in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    Ok(hex)
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
        let mut parsed = match parse_and_compile_manifest(&rel_path, &raw) {
            Ok(out) => out,
            Err(diag) => {
                diagnostics.push(diag);
                continue;
            }
        };
        let content_sha256 = match verify_and_hash_assets(workspace_root, &rel_path, &raw, &mut parsed, &mut total_bytes) {
            Ok(sha) => sha,
            Err(message) => {
                diagnostics.push(ModuleDiagnostic { manifest_path: rel_path, line: None, message });
                continue;
            }
        };
        candidates.push(VerifiedLiveModule {
            manifest_path: rel_path,
            id: parsed.manifest.id,
            name: parsed.manifest.name,
            version: parsed.manifest.version,
            description: parsed.manifest.description,
            author: parsed.manifest.author,
            proposed_hostnames: parsed.manifest.mitm.map_or_else(Vec::new, |m| m.hostnames),
            script_count: u32::try_from(parsed.manifest.scripts.len()).unwrap_or(u32::MAX),
            content_sha256,
            compiled: parsed.rewrites,
            blobs: parsed.inline_blobs,
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
