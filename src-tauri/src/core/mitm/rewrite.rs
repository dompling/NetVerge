use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{io::ErrorKind, path::PathBuf};
use tokio::sync::Mutex;

const MAX_RULES: usize = 16;
const MAX_REGEX_LEN: usize = 256;
const MAX_REGEX_STATES: usize = 128;
const MAX_REGEX_DEPTH: usize = 8;
const MAX_REGEX_REPEAT: usize = 16;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[specta(optional)]
    pub regex: Option<String>,
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

fn validate_method(method: Option<&str>) -> Result<()> {
    ensure!(method.is_none_or(|value| matches!(value, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS")), "Unsupported HTTP method");
    Ok(())
}

struct RegexParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl RegexParser<'_> {
    const fn peek(&self) -> Option<u8> {
        if self.pos < self.bytes.len() { Some(self.bytes[self.pos]) } else { None }
    }

    fn next_byte(&mut self) -> Result<u8> {
        let Some(&byte) = self.bytes.get(self.pos) else {
            bail!("Unexpected end of URL regex");
        };
        self.pos += 1;
        Ok(byte)
    }

    fn parse_alt(&mut self, depth: usize, in_group: bool) -> Result<(bool, usize)> {
        let (mut nullable, mut cost) = self.parse_seq(depth, in_group)?;
        while self.peek() == Some(b'|') {
            self.pos += 1;
            let (branch_null, branch_cost) = self.parse_seq(depth, in_group)?;
            nullable |= branch_null;
            cost = cost.saturating_add(1).saturating_add(branch_cost);
            ensure!(cost < MAX_REGEX_STATES, "URL regex exceeds bounded NFA state limit");
        }
        Ok((nullable, cost))
    }

    fn parse_seq(&mut self, depth: usize, in_group: bool) -> Result<(bool, usize)> {
        let mut nullable = true;
        let mut cost = 0usize;
        let mut has_item = false;
        while let Some(byte) = self.peek() {
            if byte == b'|' || (in_group && byte == b')') {
                break;
            }
            ensure!(in_group || byte != b')', "Unmatched closing parenthesis in URL regex");
            let (atom_null, atom_cost, quantifiable) = self.parse_atom(depth)?;
            let (item_null, item_cost) = self.parse_quantifier(atom_null, atom_cost, quantifiable)?;
            has_item = true;
            nullable &= item_null;
            cost = cost.saturating_add(item_cost);
            ensure!(cost < MAX_REGEX_STATES, "URL regex exceeds bounded NFA state limit");
        }
        ensure!(has_item, "Empty expression in URL regex");
        Ok((nullable, cost))
    }

    fn parse_atom(&mut self, depth: usize) -> Result<(bool, usize, bool)> {
        let byte = self.next_byte()?;
        match byte {
            b'^' | b'$' => Ok((true, 1, false)),
            b'.' => Ok((false, 1, true)),
            b'*' | b'+' | b'?' | b'{' | b'}' => bail!("Unexpected quantifier or brace in URL regex"),
            b'(' => {
                ensure!(depth < MAX_REGEX_DEPTH, "URL regex exceeds group nesting limit");
                if self.peek() == Some(b'?') {
                    self.pos += 1;
                    ensure!(self.next_byte()? == b':', "Unsupported group modifier in URL regex");
                }
                let (nullable, cost) = self.parse_alt(depth + 1, true)?;
                ensure!(self.next_byte()? == b')', "Unclosed group in URL regex");
                Ok((nullable, cost, true))
            }
            b'[' => {
                self.parse_class()?;
                Ok((false, 1, true))
            }
            b'\\' => {
                let esc = self.next_byte()?;
                ensure!(matches!(esc, b'd' | b'D' | b'w' | b'W' | b's' | b'S') || !esc.is_ascii_alphanumeric(), "Unsupported escape in URL regex");
                Ok((false, 1, true))
            }
            _ => Ok((false, 1, true)),
        }
    }

    fn parse_class(&mut self) -> Result<()> {
        if self.peek() == Some(b'^') {
            self.pos += 1;
        }
        ensure!(self.peek().is_some_and(|b| b != b']'), "Empty or unclosed character class in URL regex");
        while self.peek().is_some_and(|b| b != b']') {
            let first = self.read_class_atom()?;
            if self.bytes.get(self.pos) == Some(&b'-') && self.bytes.get(self.pos + 1).is_some_and(|&b| b != b']') {
                self.pos += 1;
                let second = self.read_class_atom()?;
                let (Some(lo), Some(hi)) = (first, second) else {
                    bail!("Character class range requires literal bounds");
                };
                ensure!(lo <= hi, "Reversed character class range in URL regex");
            }
        }
        ensure!(self.next_byte()? == b']', "Unclosed character class in URL regex");
        Ok(())
    }

    fn read_class_atom(&mut self) -> Result<Option<u8>> {
        let byte = self.next_byte()?;
        ensure!(byte != b'[', "Unescaped '[' in character class");
        if byte != b'\\' {
            return Ok(Some(byte));
        }
        let esc = self.next_byte()?;
        if matches!(esc, b'd' | b'D' | b'w' | b'W' | b's' | b'S') {
            return Ok(None);
        }
        ensure!(!esc.is_ascii_alphanumeric(), "Unsupported escape in character class");
        Ok(Some(esc))
    }

    fn parse_quantifier(&mut self, atom_null: bool, atom_cost: usize, quantifiable: bool) -> Result<(bool, usize)> {
        let Some(op) = self.peek() else {
            return Ok((atom_null, atom_cost));
        };
        if !matches!(op, b'*' | b'+' | b'?' | b'{') {
            return Ok((atom_null, atom_cost));
        }
        ensure!(quantifiable && !atom_null, "Cannot quantify anchor or nullable expression in URL regex");
        self.pos += 1;
        let (min, max) = match op {
            b'*' => (0, None),
            b'+' => (1, None),
            b'?' => (0, Some(1)),
            _ => self.parse_counted_repeat()?,
        };
        if self.peek() == Some(b'?') {
            self.pos += 1;
        }
        ensure!(!self.peek().is_some_and(|b| matches!(b, b'*' | b'+' | b'?' | b'{')), "Chained quantifiers are unsupported in URL regex");
        let cost = match max {
            None => min.max(1).saturating_mul(atom_cost).saturating_add(1),
            Some(hi) => hi.saturating_mul(atom_cost).saturating_add(hi - min),
        };
        ensure!(cost < MAX_REGEX_STATES, "URL regex exceeds bounded NFA state limit");
        Ok((min == 0, cost))
    }

    fn parse_counted_repeat(&mut self) -> Result<(usize, Option<usize>)> {
        let min = self.parse_repeat_bound()?;
        match self.next_byte()? {
            b'}' => {
                ensure!(min >= 1, "Zero repetition is unsupported in URL regex");
                Ok((min, Some(min)))
            }
            b',' => {
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok((min, None));
                }
                let max = self.parse_repeat_bound()?;
                ensure!(self.next_byte()? == b'}' && min <= max && max >= 1, "Invalid bounded repetition in URL regex");
                Ok((min, Some(max)))
            }
            _ => bail!("Invalid repetition syntax in URL regex"),
        }
    }

    fn parse_repeat_bound(&mut self) -> Result<usize> {
        let start = self.pos;
        let mut value = 0usize;
        while let Some(digit) = self.peek().filter(u8::is_ascii_digit) {
            self.pos += 1;
            value = value.saturating_mul(10).saturating_add(usize::from(digit - b'0'));
            ensure!(value <= MAX_REGEX_REPEAT, "Repetition bound exceeds 16 in URL regex");
        }
        ensure!(self.pos > start, "Expected integer bound in URL regex");
        Ok(value)
    }
}

fn validate_regex(pattern: Option<&str>) -> Result<()> {
    let Some(raw) = pattern else {
        return Ok(());
    };
    let bytes = raw.as_bytes();
    ensure!(!bytes.is_empty() && bytes.len() <= MAX_REGEX_LEN && bytes.iter().all(|b| (0x20..=0x7e).contains(b)), "URL regex must be 1..=256 printable ASCII bytes");
    let mut parser = RegexParser { bytes, pos: 0 };
    let (_, cost) = parser.parse_alt(0, false)?;
    ensure!(parser.pos == bytes.len() && cost + 1 <= MAX_REGEX_STATES, "Invalid or overly complex URL regex");
    Ok(())
}

fn valid_exact_or_omitted_path(path: &str, has_regex: bool) -> bool {
    (has_regex && path.is_empty())
        || (path.starts_with('/') && !path.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#')))
}

pub async fn save(direction: Direction, expected: Vec<ResponseHeaderRule>, rules: Vec<ResponseHeaderRule>) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "At most 16 rewrite rules are supported per type");
    for rule in &rules {
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
}
const BODY_FILE: &str = "response-body-rule.json";
pub fn read_body() -> Result<Vec<ResponseBodyRule>> { read_rules(BODY_FILE) }

pub async fn save_body(expected: Vec<ResponseBodyRule>, rules: Vec<ResponseBodyRule>) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "At most 16 rewrite rules are supported per type");
    for rule in &rules {
        validate_method(rule.method.as_deref())?;
        validate_regex(rule.regex.as_deref())?;
        ensure!(super::valid_host(&rule.host), "Invalid MITM hostname");
        ensure!(valid_exact_or_omitted_path(&rule.path, rule.regex.is_some()), "Expected an exact URL path or a bounded URL regex");
        ensure!(!rule.search.is_empty() && rule.search.len() <= 1024, "Expected non-empty search text up to 1024 bytes");
        ensure!(rule.value.len() <= 4096, "Replacement text exceeds 4096 bytes");
    }
    save_rules(BODY_FILE, expected, rules, 16384).await
}

async fn save_rules<T: serde::de::DeserializeOwned + Serialize + PartialEq>(filename: &str, expected: Vec<T>, rules: Vec<T>, max_bytes: usize) -> Result<()> {
    let _guard = WRITE.lock().await;
    ensure!(read_rules::<T>(filename)? == expected, "Rewrite rule changed. Reopen the MITM page to reload.");
    let path = file(filename)?;
    if !rules.is_empty() {
        let json = serde_json::to_string(&RuleFile { version: 2, rules })?;
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
        let encoded = serde_json::to_vec(&RuleFile { version: 2, rules: decoded.clone() })?;
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
            "",
            r"(a)\1",
            r"\k<id>",
            r"(?=demo)",
            r"(?!demo)",
            r"(?<=demo)",
            r"(?<!demo)",
            r"(?i)demo",
            r"(?<name>demo)",
            r"\bdemo\b",
            r"\p{L}",
            r"a++",
            r"()",
            r"(?:)",
            r"demo|",
            r"|demo",
            r"a||b",
            r"(a*)+",
            r"(a?)+",
            r"(^)+",
            r"^*",
            r"$?",
            r"[]",
            r"[^]",
            r"[z-a]",
            r"[\d-z]",
            r"[abc",
            r"(abc",
            r"abc)",
            r"{1,2}",
            r"a{0}",
            r"a{0,0}",
            r"a{3,2}",
            r"a{17}",
            r"a}b",
            r"(((((((((a)))))))))",
            &"a".repeat(MAX_REGEX_LEN + 1),
            "(abcdefghij){13}",
        ] {
            assert!(validate_regex(Some(invalid)).is_err(), "expected rejection for {invalid}");
        }
        assert!(!valid_exact_or_omitted_path("", false));
        assert!(valid_exact_or_omitted_path("", true));
        let rule = br#"{"enabled":true,"host":"api.example.test","path":"","regex":"^https://api\\.example\\.test/v1/[0-9]+$","search":"old","value":"new"}"#;
        let decoded = decode_rules::<ResponseBodyRule>(rule)?;
        assert_eq!(decoded[0].regex.as_deref(), Some(r"^https://api\.example\.test/v1/[0-9]+$"));
        let encoded = serde_json::to_vec(&RuleFile { version: 2, rules: decoded.clone() })?;
        assert_eq!(decode_rules::<ResponseBodyRule>(&encoded)?, decoded);
        Ok(())
    }

    #[test]
    fn migrates_legacy_single_rule_and_validates_v2_lists() -> Result<()> {
        let single = br#"{"enabled":true,"host":"api.example.test","path":"/demo","header":"X-NetVerge-Test","value":"1"}"#;
        let migrated = decode_rules::<ResponseHeaderRule>(single)?;
        assert_eq!(migrated.len(), 1);
        assert_eq!(migrated[0].header, "X-NetVerge-Test");
        assert_eq!(migrated[0].method, None);
        assert_eq!(migrated[0].regex, None);
        let serialized = serde_json::to_value(&migrated[0])?;
        assert!(!serialized.as_object().is_some_and(|obj| obj.contains_key("method") || obj.contains_key("regex")));

        let encoded = serde_json::to_vec(&RuleFile { version: 2, rules: migrated.clone() })?;
        assert_eq!(decode_rules::<ResponseHeaderRule>(&encoded)?, migrated);
        assert!(decode_rules::<ResponseHeaderRule>(br#"{"version":1,"rules":[]}"#).is_err());
        assert!(decode_rules::<ResponseHeaderRule>(br#"{"version":2,"rules":[],"extra":true}"#).is_err());
        let oversized = serde_json::to_vec(&RuleFile { version: 2, rules: vec![migrated[0].clone(); MAX_RULES + 1] })?;
        assert!(decode_rules::<ResponseHeaderRule>(&oversized).is_err());
        Ok(())
    }
}
