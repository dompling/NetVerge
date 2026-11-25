use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{io::ErrorKind, path::PathBuf};
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderRule {
    pub enabled: bool,
    pub host: String,
    pub path: String,
    pub header: String,
    pub value: String,
}

static WRITE: Mutex<()> = Mutex::const_new(());

fn file() -> Result<PathBuf> {
    ensure!(cfg!(all(windows, feature = "verge-dev")) && super::route_runtime::requested(), "MITM rewrite is unavailable");
    Ok(crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev").join("response-header-rule.json"))
}

pub fn read() -> Result<Option<ResponseHeaderRule>> {
    let bytes = match super::settings::read_bounded(&file()?) {
        Ok(bytes) => bytes,
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == ErrorKind::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub async fn save(expected: Option<ResponseHeaderRule>, rule: Option<ResponseHeaderRule>) -> Result<()> {
    let _guard = WRITE.lock().await;
    ensure!(read()? == expected, "Rewrite rule changed. Reopen the MITM page to reload.");
    let path = file()?;
    if let Some(rule) = rule {
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(rule.path.starts_with('/') && !rule.path.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#')), "Expected an exact URL path");
        let name = rule.header.to_ascii_lowercase();
        ensure!(name.strip_prefix("x-").is_some_and(|s| !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')), "Expected an X- response header");
        ensure!(rule.value.chars().count() <= 1024 && rule.value.chars().all(|c| c == '\t' || (' '..='~').contains(&c) || ('\u{80}'..='\u{ff}').contains(&c)), "Invalid HTTP header value");
        let json = serde_json::to_string(&rule)?;
        ensure!(json.len() <= 8192, "Rewrite rule exceeds 8192 bytes");
        crate::utils::help::save_yaml_str_private(&path, &json, None).await?;
    } else if expected.is_some() {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}
