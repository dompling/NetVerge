use crate::core::mitm::{self, MitmPublicCa, MitmStatus};

/// Read-only MITM state; no configuration or process changes.
#[tauri::command]
#[specta::specta]
pub fn get_mitm_status() -> MitmStatus {
    mitm::status()
}

/// Save the guarded service preference for the next complete app start.
#[tauri::command]
#[specta::specta]
pub async fn set_mitm_service_mode(enabled: bool) -> super::CmdResult<()> {
    use super::StringifyErr as _;
    mitm::route_runtime::set_service_preference(enabled).await.stringify_err()
}

#[tauri::command]
#[specta::specta]
pub fn get_response_header_rule() -> super::CmdResult<Option<mitm::rewrite::ResponseHeaderRule>> {
    use super::StringifyErr as _;
    mitm::rewrite::read(mitm::rewrite::Direction::Response).stringify_err()
}

#[tauri::command]
#[specta::specta]
pub async fn save_response_header_rule(expected: Option<mitm::rewrite::ResponseHeaderRule>, rule: Option<mitm::rewrite::ResponseHeaderRule>) -> super::CmdResult<()> {
    use super::StringifyErr as _;
    mitm::rewrite::save(mitm::rewrite::Direction::Response, expected, rule).await.stringify_err()
}

#[tauri::command]
#[specta::specta]
pub fn get_response_header_hits() -> Option<u32> {
    mitm::route_runtime::response_header_hits()
}

#[tauri::command]
#[specta::specta]
pub fn get_request_header_rule() -> super::CmdResult<Option<mitm::rewrite::ResponseHeaderRule>> {
    use super::StringifyErr as _;
    mitm::rewrite::read(mitm::rewrite::Direction::Request).stringify_err()
}

#[tauri::command]
#[specta::specta]
pub async fn save_request_header_rule(expected: Option<mitm::rewrite::ResponseHeaderRule>, rule: Option<mitm::rewrite::ResponseHeaderRule>) -> super::CmdResult<()> {
    use super::StringifyErr as _;
    mitm::rewrite::save(mitm::rewrite::Direction::Request, expected, rule).await.stringify_err()
}

#[tauri::command]
#[specta::specta]
pub fn get_request_header_hits() -> Option<u32> {
    mitm::route_runtime::request_header_hits()
}

#[tauri::command]
#[specta::specta]
pub fn get_url_path_rule() -> super::CmdResult<Option<mitm::rewrite::UrlPathRule>> {
    use super::StringifyErr as _;
    mitm::rewrite::read_path().stringify_err()
}

#[tauri::command]
#[specta::specta]
pub async fn save_url_path_rule(expected: Option<mitm::rewrite::UrlPathRule>, rule: Option<mitm::rewrite::UrlPathRule>) -> super::CmdResult<()> {
    use super::StringifyErr as _;
    mitm::rewrite::save_path(expected, rule).await.stringify_err()
}

#[tauri::command]
#[specta::specta]
pub fn get_url_path_hits() -> Option<u32> {
    mitm::route_runtime::url_path_hits()
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

/// Open the native certificate manager after explicit confirmation; never changes trust.
#[tauri::command]
#[specta::specta]
pub async fn open_mitm_certificate_manager(expected_fingerprint: String) -> super::CmdResult<bool> {
    use super::StringifyErr as _;
    mitm::trust::open_manager(expected_fingerprint).await.stringify_err()
}

/// Read restart-scoped local MITM settings and applied-profile policy choices.
#[tauri::command]
#[specta::specta]
pub async fn get_mitm_config() -> super::CmdResult<mitm::settings::MitmConfigView> {
    use super::StringifyErr as _;
    mitm::settings::inspect().await.stringify_err()
}

/// Stage local MITM configuration after native confirmation; no live activation.
#[tauri::command]
#[specta::specta]
pub async fn save_mitm_config(expected_revision: String, candidate: mitm::MitmSettings) -> super::CmdResult<Option<mitm::settings::MitmConfigView>> {
    use super::StringifyErr as _;
    mitm::settings::save(expected_revision, candidate).await.stringify_err()
}
