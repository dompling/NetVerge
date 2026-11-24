use crate::core::mitm::{self, MitmPublicCa, MitmStatus};

/// Read-only MITM state; no configuration or process changes.
#[tauri::command]
#[specta::specta]
pub fn get_mitm_status() -> MitmStatus {
    mitm::status()
}

/// Returns the last verified public CA only. Never installs trust or exports a private key.
#[tauri::command]
#[specta::specta]
pub fn get_mitm_public_ca() -> Option<MitmPublicCa> {
    mitm::public_ca()
}
