//! Session-only execution consent. It grants no traffic hook or runner access.
//! A future dispatcher must consult the same gate again before each invocation
//! and before committing any mutation, rather than relying on a UI snapshot.
use super::{
    APPROVED_BLOBS_DIR, ModuleApprovalState, PinnedScript, ProfileModulesView,
    WorkspaceSnapshot, ensure_not_symlink_or_reparse, sha256_hex, valid_hex_sha256,
};
use anyhow::{Context as _, Result, ensure};
use std::{collections::BTreeMap, path::Path};

pub(super) struct ScriptAuthorizations {
    workspace: Option<WorkspaceSnapshot>,
    digests: BTreeMap<String, String>,
}

impl ScriptAuthorizations {
    pub(super) const fn new() -> Self {
        Self { workspace: None, digests: BTreeMap::new() }
    }

    pub(super) fn select(&mut self, snapshot: &WorkspaceSnapshot) {
        if self.workspace.as_ref() != Some(snapshot) {
            self.digests.clear();
            self.workspace = Some(snapshot.clone());
        }
    }

    pub(super) fn revoke(&mut self, module_id: &str) {
        self.digests.remove(module_id);
    }

    pub(super) fn apply(&mut self, snapshot: &WorkspaceSnapshot, view: &mut ProfileModulesView) {
        self.select(snapshot);
        self.digests.retain(|id, digest| {
            view.profile_uid == snapshot.uid && view.modules.iter().any(|module|
                module.id == *id && module.state == ModuleApprovalState::Active
                    && module.script_authorization_ready && module.content_sha256 == *digest)
        });
        for module in &mut view.modules {
            module.script_authorized = self.digests.get(&module.id) == Some(&module.content_sha256);
        }
    }

    pub(super) fn authorize(
        &mut self,
        snapshot: &WorkspaceSnapshot,
        view: &ProfileModulesView,
        module_id: &str,
        expected_sha256: &str,
    ) -> Result<()> {
        self.select(snapshot);
        ensure!(snapshot.root.is_some() && snapshot.uid.is_some() && view.profile_uid == snapshot.uid,
            "active profile changed; reload modules");
        let module = view.modules.iter().find(|module| module.id == module_id)
            .context("module is unavailable or failed validation")?;
        ensure!(module.state == ModuleApprovalState::Active && module.script_authorization_ready,
            "approve the current module, verify script assets and enable its MITM hostnames first");
        ensure!(valid_hex_sha256(expected_sha256) && module.content_sha256 == expected_sha256
            && module.approved_sha256.as_deref() == Some(expected_sha256),
            "module files changed since review; refresh before authorizing");
        self.digests.insert(module_id.to_owned(), expected_sha256.to_owned());
        Ok(())
    }
}

pub(super) fn script_pins_valid(mitm_dir: &Path, pins: &[PinnedScript]) -> bool {
    let dir = mitm_dir.join(APPROVED_BLOBS_DIR);
    if ensure_not_symlink_or_reparse(mitm_dir).is_err() || ensure_not_symlink_or_reparse(&dir).is_err() {
        return false;
    }
    pins.iter().all(|pin| {
        if !valid_hex_sha256(&pin.source_sha256) || !(1..=65_536).contains(&pin.source_len) {
            return false;
        }
        let path = dir.join(&pin.source_sha256);
        if ensure_not_symlink_or_reparse(&path).is_err() {
            return false;
        }
        super::super::settings::read_bounded(&path).is_ok_and(|bytes|
            bytes.len() == pin.source_len as usize && std::str::from_utf8(&bytes).is_ok()
                && sha256_hex(&bytes) == pin.source_sha256)
    })
}
