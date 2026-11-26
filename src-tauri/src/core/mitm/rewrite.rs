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

#[derive(Clone, Copy)]
pub enum Direction { Request, Response }

impl Direction {
    fn filename(self) -> &'static str {
        match self { Self::Request => "request-header-rule.json", Self::Response => "response-header-rule.json" }
    }
}

fn file(filename: &str) -> Result<PathBuf> {
    ensure!(cfg!(all(windows, feature = "verge-dev")) && super::route_runtime::requested(), "MITM rewrite is unavailable");
    Ok(crate::utils::dirs::app_home_dir()?.join("netverge-mitm-dev").join(filename))
}

pub fn read(direction: Direction) -> Result<Option<ResponseHeaderRule>> { read_rule(direction.filename()) }

fn read_rule<T: serde::de::DeserializeOwned>(filename: &str) -> Result<Option<T>> {
    let bytes = match super::settings::read_bounded(&file(filename)?) {
        Ok(bytes) => bytes,
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == ErrorKind::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub async fn save(direction: Direction, expected: Option<ResponseHeaderRule>, rule: Option<ResponseHeaderRule>) -> Result<()> {
    if let Some(rule) = &rule {
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(rule.path.starts_with('/') && !rule.path.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#')), "Expected an exact URL path");
        let name = rule.header.to_ascii_lowercase();
        let (prefix, limit) = match direction {
            Direction::Request => ("x-custom-", 91),
            Direction::Response => ("x-", 100),
        };
        ensure!(name.strip_prefix(prefix).is_some_and(|s| !s.is_empty() && s.len() <= limit && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')), "Expected a valid {prefix} header");
        ensure!(rule.value.chars().count() <= 1024 && rule.value.chars().all(|c| c == '\t' || (' '..='~').contains(&c) || ('\u{80}'..='\u{ff}').contains(&c)), "Invalid HTTP header value");
    }
    save_rule(direction.filename(), expected, rule).await
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct UrlPathRule {
    pub enabled: bool,
    pub host: String,
    pub path: String,
    pub target: String,
}
const PATH_FILE: &str = "url-path-rule.json";
pub fn read_path() -> Result<Option<UrlPathRule>> { read_rule(PATH_FILE) }

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._~%-".contains(&b))
        && path.split('%').skip(1).all(|s| s.as_bytes().get(..2).is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit)))
        && !path.split('/').any(|part| matches!(part.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | ".."))
}
pub async fn save_path(expected: Option<UrlPathRule>, rule: Option<UrlPathRule>) -> Result<()> {
    if let Some(rule) = &rule {
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(valid_path(&rule.path) && valid_path(&rule.target), "Expected two same-host URL paths without query or fragment");
    }
    save_rule(PATH_FILE, expected, rule).await
}

async fn save_rule<T: serde::de::DeserializeOwned + Serialize + PartialEq>(filename: &str, expected: Option<T>, rule: Option<T>) -> Result<()> {
    let _guard = WRITE.lock().await;
    ensure!(read_rule::<T>(filename)? == expected, "Rewrite rule changed. Reopen the MITM page to reload.");
    let path = file(filename)?;
    if let Some(rule) = rule {
        let json = serde_json::to_string(&rule)?;
        ensure!(json.len() <= 8192, "Rewrite rule exceeds 8192 bytes");
        crate::utils::help::save_yaml_str_private(&path, &json, None).await?;
    } else if expected.is_some() {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}
