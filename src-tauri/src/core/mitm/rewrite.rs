use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, io::ErrorKind, path::PathBuf};
use tokio::sync::Mutex;

use super::url_regex::validate_regex;

const MAX_RULES: usize = 16;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile<T> {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<u32>,
    rules: Vec<T>,
}

trait RuleIdentity {
    fn rule_id(&self) -> Option<&str>;
    fn rule_source(&self) -> Option<&str>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub source: Option<String>,
    pub enabled: bool,
    pub host: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub regex: Option<String>,
    pub header: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub remove: Option<bool>,
}

impl RuleIdentity for ResponseHeaderRule {
    fn rule_id(&self) -> Option<&str> { self.id.as_deref() }
    fn rule_source(&self) -> Option<&str> { self.source.as_deref() }
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

fn validate_rule_id(id: Option<&str>) -> Result<()> {
    let Some(raw) = id else { return Ok(()); };
    let mut bytes = raw.bytes();
    let Some(first) = bytes.next() else { anyhow::bail!("Empty MITM rule ID"); };
    ensure!(
        raw.len() <= 64
            && (first.is_ascii_lowercase() || first.is_ascii_digit())
            && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b':' | b'-')),
        "Invalid MITM rule ID"
    );
    Ok(())
}

fn validate_source(source: Option<&str>) -> Result<()> {
    let Some(raw) = source else { return Ok(()); };
    if raw == "local" {
        return Ok(());
    }
    let Some(module_id) = raw.strip_prefix("module:") else {
        anyhow::bail!("Unsupported MITM rule source");
    };
    let valid_module = raw.len() <= 96
        && module_id.contains('.')
        && module_id.split('.').all(|seg| {
            let mut chars = seg.bytes();
            chars.next().is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
                && chars.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !seg.ends_with('-')
        });
    ensure!(valid_module, "Invalid module rule source");
    Ok(())
}

fn validate_identities<T: RuleIdentity>(rules: &[T]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for rule in rules {
        validate_rule_id(rule.rule_id())?;
        validate_source(rule.rule_source())?;
        if let Some(id) = rule.rule_id() {
            ensure!(seen.insert(id), "Duplicate MITM rewrite rule ID");
        }
    }
    Ok(())
}

fn decode_rules<T: serde::de::DeserializeOwned + RuleIdentity>(bytes: &[u8]) -> Result<Vec<T>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value.get("version").is_some() {
        let parsed: RuleFile<T> = serde_json::from_value(value)?;
        ensure!(
            parsed.version == 2
                && parsed.revision.is_none_or(|rev| rev >= 1)
                && parsed.rules.len() <= MAX_RULES,
            "Unsupported MITM rewrite rule list"
        );
        validate_identities(&parsed.rules)?;
        return Ok(parsed.rules);
    }
    let single = vec![serde_json::from_value::<T>(value)?];
    validate_identities(&single)?;
    Ok(single)
}

pub fn read(direction: Direction) -> Result<Vec<ResponseHeaderRule>> { read_rules(direction.filename()) }

fn read_rules<T: serde::de::DeserializeOwned + RuleIdentity>(filename: &str) -> Result<Vec<T>> {
    let bytes = match super::settings::read_bounded(&file(filename)?) {
        Ok(bytes) => bytes,
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == ErrorKind::NotFound) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    decode_rules(&bytes)
}

fn validate_method(method: Option<&str>) -> Result<()> {
    ensure!(method.is_none_or(|value| matches!(value, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS")), "Unsupported HTTP method");
    Ok(())
}

fn valid_exact_or_omitted_path(path: &str, has_regex: bool) -> bool {
    (has_regex && path.is_empty())
        || (path.starts_with('/') && !path.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#')))
}

pub async fn save(direction: Direction, expected: Vec<ResponseHeaderRule>, rules: Vec<ResponseHeaderRule>) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "At most 16 rewrite rules are supported per type");
    validate_identities(&rules)?;
    for rule in &rules {
        ensure!(rule.remove.is_none(), "Header removal is available only in approved modules");
        validate_method(rule.method.as_deref())?;
        validate_regex(rule.regex.as_deref())?;
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(valid_exact_or_omitted_path(&rule.path, rule.regex.is_some()), "Expected an exact URL path or a bounded URL regex");
        let name = rule.header.to_ascii_lowercase();
        let (prefix, limit) = match direction {
            Direction::Request => ("x-custom-", 91),
            Direction::Response => ("x-", 100),
        };
        ensure!(name.strip_prefix(prefix).is_some_and(|s| !s.is_empty() && s.len() <= limit && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')), "Expected a valid {prefix} header");
        ensure!(rule.value.chars().count() <= 1024 && rule.value.chars().all(|c| c == '\t' || (' '..='~').contains(&c) || ('\u{80}'..='\u{ff}').contains(&c)), "Invalid HTTP header value");
    }
    save_rules(direction.filename(), expected, rules, 8192).await
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct UrlPathRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub source: Option<String>,
    pub enabled: bool,
    pub host: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub regex: Option<String>,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub remove_query: Option<Vec<String>>,
}

impl RuleIdentity for UrlPathRule {
    fn rule_id(&self) -> Option<&str> { self.id.as_deref() }
    fn rule_source(&self) -> Option<&str> { self.source.as_deref() }
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
    validate_identities(&rules)?;
    for rule in &rules {
        ensure!(rule.remove_query.is_none(), "Query removal is available only in approved modules");
        validate_method(rule.method.as_deref())?;
        validate_regex(rule.regex.as_deref())?;
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(((rule.regex.is_some() && rule.path.is_empty()) || valid_path(&rule.path)) && valid_path(&rule.target), "Expected valid same-host URL paths without query or fragment");
    }
    save_rules(PATH_FILE, expected, rules, 8192).await
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct ResponseBodyRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub source: Option<String>,
    pub enabled: bool,
    pub host: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub regex: Option<String>,
    pub search: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub match_whole: Option<bool>,
}

impl RuleIdentity for ResponseBodyRule {
    fn rule_id(&self) -> Option<&str> { self.id.as_deref() }
    fn rule_source(&self) -> Option<&str> { self.source.as_deref() }
}

const BODY_FILE: &str = "response-body-rule.json";
pub fn read_body() -> Result<Vec<ResponseBodyRule>> { read_rules(BODY_FILE) }

pub async fn save_body(expected: Vec<ResponseBodyRule>, rules: Vec<ResponseBodyRule>) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "At most 16 rewrite rules are supported per type");
    validate_identities(&rules)?;
    for rule in &rules {
        ensure!(rule.match_whole.is_none(), "Whole-body matching is available only in approved modules");
        validate_method(rule.method.as_deref())?;
        validate_regex(rule.regex.as_deref())?;
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(valid_exact_or_omitted_path(&rule.path, rule.regex.is_some()), "Expected an exact URL path or a bounded URL regex");
        ensure!(!rule.search.is_empty() && rule.search.len() <= 1024, "Expected non-empty search text up to 1024 bytes");
        ensure!(rule.value.len() <= 4096, "Replacement text exceeds 4096 bytes");
    }
    save_rules(BODY_FILE, expected, rules, 16384).await
}

async fn save_rules<T: serde::de::DeserializeOwned + Serialize + PartialEq + RuleIdentity>(filename: &str, expected: Vec<T>, rules: Vec<T>, max_bytes: usize) -> Result<()> {
    let _guard = WRITE.lock().await;
    ensure!(read_rules::<T>(filename)? == expected, "Rewrite rule changed. Reopen the MITM page to reload.");
    let path = file(filename)?;
    if !rules.is_empty() {
        let json = serde_json::to_string(&RuleFile { version: 2, revision: None, rules })?;
        ensure!(json.len() <= max_bytes, "Rewrite rules exceed {max_bytes} bytes");
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
    use crate::core::mitm::url_regex::MAX_REGEX_LEN;

    #[test]
    fn optional_method_conditions_validate_and_round_trip() -> Result<()> {
        for value in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            validate_method(Some(value))?;
        }
        validate_method(None)?;
        for value in ["", "get", "*", "CONNECT", "TRACE", "GET\nPOST"] {
            assert!(validate_method(Some(value)).is_err());
        }
        let rule = br#"{"enabled":true,"host":"api.example.test","path":"/demo","target":"/changed","method":"POST"}"#;
        let decoded = decode_rules::<UrlPathRule>(rule)?;
        assert_eq!(decoded[0].method.as_deref(), Some("POST"));
        let encoded = serde_json::to_vec(&RuleFile { version: 2, revision: None, rules: decoded.clone() })?;
        assert_eq!(decode_rules::<UrlPathRule>(&encoded)?, decoded);
        Ok(())
    }

    #[test]
    fn bounded_url_regex_accepts_re2_subset_and_rejects_unsupported_or_complex_patterns() -> Result<()> {
        validate_regex(None)?;
        for valid in [
            r"^https://api\.example\.test/v[12]/items/[0-9]+(?:\?.*)?$",
            r"/demo/[a-zA-Z0-9_-]{1,8}$",
            r"\?(?:.*?&)?flag=1(?:&|$)",
            r"^https://api\.example\.test/(?:users|teams)/[\d\w.-]+$",
            r"((((((((a))))))))",
        ] {
            validate_regex(Some(valid))?;
        }
        for invalid in [
            "", r"(a)\1", r"\k<id>", r"(?=demo)", r"(?!demo)", r"(?<=demo)", r"(?<!demo)",
            r"(?i)demo", r"(?<name>demo)", r"\bdemo\b", r"\p{L}", r"a++", r"()", r"(?:)",
            r"demo|", r"|demo", r"a||b", r"(a*)+", r"(a?)+", r"(^)+", r"^*", r"$?",
            r"[]", r"[^]", r"[z-a]", r"[\d-z]", r"[abc", r"(abc", r"abc)", r"{1,2}",
            r"a{0}", r"a{0,0}", r"a{3,2}", r"a{17}", r"a}b", r"(((((((((a)))))))))",
            &"a".repeat(MAX_REGEX_LEN + 1), "(abcdefghij){13}",
        ] {
            assert!(validate_regex(Some(invalid)).is_err(), "expected rejection for {invalid}");
        }
        assert!(!valid_exact_or_omitted_path("", false));
        assert!(valid_exact_or_omitted_path("", true));
        let rule = br#"{"enabled":true,"host":"api.example.test","path":"","regex":"^https://api\\.example\\.test/v1/[0-9]+$","search":"old","value":"new"}"#;
        let decoded = decode_rules::<ResponseBodyRule>(rule)?;
        assert_eq!(decoded[0].regex.as_deref(), Some(r"^https://api\.example\.test/v1/[0-9]+$"));
        let encoded = serde_json::to_vec(&RuleFile { version: 2, revision: Some(3), rules: decoded.clone() })?;
        assert_eq!(decode_rules::<ResponseBodyRule>(&encoded)?, decoded);
        Ok(())
    }

    #[test]
    fn validates_stable_ids_sources_revisions_and_preserves_legacy_migration() -> Result<()> {
        for valid_id in ["redirect-v1", "com.example.api:rule_1"] {
            validate_rule_id(Some(valid_id))?;
        }
        for invalid_id in ["", "Upper", "-bad", "bad space", &"a".repeat(65)] {
            assert!(validate_rule_id(Some(invalid_id)).is_err());
        }
        for valid_source in ["local", "module:com.example.api-debug"] {
            validate_source(Some(valid_source))?;
        }
        for invalid_source in ["", "remote", "module:bad", "module:Com.Example", "module:com.example-"] {
            assert!(validate_source(Some(invalid_source)).is_err());
        }

        let single = br#"{"enabled":true,"host":"api.example.test","path":"/demo","header":"X-NetVerge-Test","value":"1"}"#;
        let migrated = decode_rules::<ResponseHeaderRule>(single)?;
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].id, None);
        assert_eq!(migrated[0].source, None);
        assert_eq!(migrated[0].method, None);
        assert_eq!(migrated[0].regex, None);
        let serialized = serde_json::to_value(&migrated[0])?;
        assert!(!serialized.as_object().is_some_and(|obj| {
            ["id", "source", "method", "regex"].iter().any(|k| obj.contains_key(*k))
        }));

        let with_meta = br#"{"version":2,"revision":4,"rules":[{"id":"mod.rule:1","source":"module:com.example.debug","enabled":true,"host":"api.example.test","path":"/demo","header":"X-NetVerge-Test","value":"1"}]}"#;
        let parsed = decode_rules::<ResponseHeaderRule>(with_meta)?;
        assert_eq!(parsed[0].id.as_deref(), Some("mod.rule:1"));
        assert_eq!(parsed[0].source.as_deref(), Some("module:com.example.debug"));

        let dup = br#"{"version":2,"rules":[{"id":"dup","enabled":true,"host":"api.example.test","path":"/a","target":"/b"},{"id":"dup","enabled":false,"host":"api.example.test","path":"/c","target":"/d"}]}"#;
        assert!(decode_rules::<UrlPathRule>(dup).is_err());
        assert!(decode_rules::<UrlPathRule>(br#"{"version":2,"revision":0,"rules":[]}"#).is_err());
        assert!(decode_rules::<ResponseHeaderRule>(br#"{"version":1,"rules":[]}"#).is_err());
        assert!(decode_rules::<ResponseHeaderRule>(br#"{"version":2,"rules":[],"extra":true}"#).is_err());
        let oversized = serde_json::to_vec(&RuleFile { version: 2, revision: None, rules: vec![migrated[0].clone(); MAX_RULES + 1] })?;
        assert!(decode_rules::<ResponseHeaderRule>(&oversized).is_err());
        Ok(())
    }
}
