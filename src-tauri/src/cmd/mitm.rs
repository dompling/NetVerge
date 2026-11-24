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

/// Inspect the exact public CA in the native stores without modifying trust.
#[tauri::command]
#[specta::specta]
pub async fn get_mitm_trust_status() -> mitm::trust::MitmTrustStatus {
    mitm::trust::inspect().await
}

/// Save the verified public CA using an explicit native save dialog.
#[tauri::command]
#[specta::specta]
pub async fn export_mitm_public_ca() -> super::CmdResult<bool> {
    use super::StringifyErr as _;
    mitm::trust::export().await.stringify_err()
}
