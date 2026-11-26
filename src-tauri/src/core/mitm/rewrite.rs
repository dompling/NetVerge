use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{io::ErrorKind, path::PathBuf};
use tokio::sync::Mutex;

const MAX_RULES: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile<T> {
    version: u32,
    rules: Vec<T>,
}

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

fn decode_rules<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value.get("version").is_some() {
        let parsed: RuleFile<T> = serde_json::from_value(value)?;
        ensure!(parsed.version == 2 && parsed.rules.len() <= MAX_RULES, "Unsupported MITM rewrite rule list");
        return Ok(parsed.rules);
    }
    Ok(vec![serde_json::from_value::<T>(value)?])
}

pub fn read(direction: Direction) -> Result<Vec<ResponseHeaderRule>> { read_rules(direction.filename()) }

fn read_rules<T: serde::de::DeserializeOwned>(filename: &str) -> Result<Vec<T>> {
    let bytes = match super::settings::read_bounded(&file(filename)?) {
        Ok(bytes) => bytes,
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == ErrorKind::NotFound) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    decode_rules(&bytes)
}

pub async fn save(direction: Direction, expected: Vec<ResponseHeaderRule>, rules: Vec<ResponseHeaderRule>) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "At most 16 rewrite rules are supported per type");
    for rule in &rules {
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
    save_rules(direction.filename(), expected, rules).await
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
pub fn read_path() -> Result<Vec<UrlPathRule>> { read_rules(PATH_FILE) }

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._~%-".contains(&b))
        && path.split('%').skip(1).all(|s| s.as_bytes().get(..2).is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit)))
        && !path.split('/').any(|part| matches!(part.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | ".."))
}
pub async fn save_path(expected: Vec<UrlPathRule>, rules: Vec<UrlPathRule>) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "At most 16 rewrite rules are supported per type");
    for rule in &rules {
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(valid_path(&rule.path) && valid_path(&rule.target), "Expected two same-host URL paths without query or fragment");
    }
    save_rules(PATH_FILE, expected, rules).await
}

async fn save_rules<T: serde::de::DeserializeOwned + Serialize + PartialEq>(filename: &str, expected: Vec<T>, rules: Vec<T>) -> Result<()> {
    let _guard = WRITE.lock().await;
    ensure!(read_rules::<T>(filename)? == expected, "Rewrite rule changed. Reopen the MITM page to reload.");
    let path = file(filename)?;
    if !rules.is_empty() {
        let json = serde_json::to_string(&RuleFile { version: 2, rules })?;
        ensure!(json.len() <= 8192, "Rewrite rules exceed 8192 bytes");
        crate::utils::help::save_yaml_str_private(&path, &json, None).await?;
    } else if !expected.is_empty() {
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_single_rule_and_validates_v2_lists() -> Result<()> {
        let single = br#"{"enabled":true,"host":"api.example.test","path":"/demo","header":"X-NetVerge-Test","value":"1"}"#;
        let migrated = decode_rules::<ResponseHeaderRule>(single)?;
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].header, "X-NetVerge-Test");

        let encoded = serde_json::to_vec(&RuleFile { version: 2, rules: migrated.clone() })?;
        assert_eq!(decode_rules::<ResponseHeaderRule>(&encoded)?, migrated);
        assert!(decode_rules::<ResponseHeaderRule>(br#"{"version":1,"rules":[]}"#).is_err());
        assert!(decode_rules::<ResponseHeaderRule>(br#"{"version":2,"rules":[],"extra":true}"#).is_err());
        let oversized = serde_json::to_vec(&RuleFile { version: 2, rules: vec![migrated[0].clone(); MAX_RULES + 1] })?;
        assert!(decode_rules::<ResponseHeaderRule>(&oversized).is_err());
        Ok(())
    }
}
