use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    rewrite::{ResponseBodyRule, ResponseHeaderRule, UrlPathRule},
    url_regex::validate_regex,
};

pub(crate) const MAX_MANIFEST_BYTES: usize = 65_536;
const MAX_LINE_BYTES: usize = 2048;
const MAX_NESTING_INDENT: usize = 24;
const MAX_REWRITE_ENTRIES: usize = 16;
const MAX_SCRIPT_ENTRIES: usize = 8;
const MAX_MITM_PROPOSALS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ModuleDiagnostic {
    pub manifest_path: String,
    pub line: Option<u32>,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawModuleManifest {
    pub(crate) kind: String,
    pub(crate) schema: u32,
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mitm: Option<RawMitmSection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) rewrite: Vec<RawRewriteEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) scripts: Vec<RawScriptEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMitmSection {
    #[serde(default)]
    pub(crate) hostnames: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMatchCondition {
    pub(crate) host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) regex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRewriteEntry {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    #[serde(rename = "match")]
    pub(crate) condition: RawMatchCondition,
    pub(crate) action: serde_yaml_ng::Mapping,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct RawScriptEntry {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    #[serde(rename = "match")]
    pub(crate) condition: RawMatchCondition,
    pub(crate) script: String,
    #[serde(default)]
    pub(crate) requires_body: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) timeout: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) argument: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompiledModuleRewrites {
    pub(crate) request: Vec<ResponseHeaderRule>,
    pub(crate) response: Vec<ResponseHeaderRule>,
    pub(crate) path: Vec<UrlPathRule>,
    pub(crate) body: Vec<ResponseBodyRule>,
}

pub(crate) fn valid_module_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.contains('.')
        && id.split('.').all(|seg| {
            let mut bytes = seg.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !seg.ends_with('-')
        })
}

fn valid_local_entry_id(id: &str) -> bool {
    let mut bytes = id.bytes();
    id.len() <= 32
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn valid_url_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._~%-".contains(&b))
        && path
            .split('%')
            .skip(1)
            .all(|s| s.as_bytes().get(..2).is_some_and(|d| d.iter().all(u8::is_ascii_hexdigit)))
        && !path
            .split('/')
            .any(|part| matches!(part.to_ascii_lowercase().replace("%2e", ".").as_str(), "." | ".."))
}

fn scan_unquoted_yaml_line(line: &str, line_no: u32, seen_content: &mut bool) -> Result<(), (u32, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(());
    }
    if trimmed == "---" || trimmed.starts_with("--- ") {
        if *seen_content {
            return Err((line_no, "multiple YAML documents are unsupported".into()));
        }
        return Ok(());
    }
    if trimmed == "..." {
        return Err((line_no, "YAML document end markers are unsupported".into()));
    }
    *seen_content = true;
    let indent = line.bytes().take_while(|&b| b == b' ').count();
    if line.starts_with('\t') || indent > MAX_NESTING_INDENT {
        return Err((line_no, "invalid indentation or excessive nesting depth".into()));
    }
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    let mut single_q = false;
    let mut double_q = false;
    let mut flow_depth = 0usize;
    while idx < bytes.len() {
        let b = bytes[idx];
        if double_q {
            if b == b'\\' {
                idx += 2;
                continue;
            }
            if b == b'"' {
                double_q = false;
            }
            idx += 1;
            continue;
        }
        if single_q {
            if b == b'\'' {
                if bytes.get(idx + 1) == Some(&b'\'') {
                    idx += 2;
                    continue;
                }
                single_q = false;
            }
            idx += 1;
            continue;
        }
        match b {
            b'#' if idx == 0 || bytes[idx - 1].is_ascii_whitespace() => break,
            b'\'' => single_q = true,
            b'"' => double_q = true,
            b'[' | b'{' => {
                flow_depth += 1;
                if flow_depth > 6 {
                    return Err((line_no, "excessive YAML flow nesting".into()));
                }
            }
            b']' | b'}' => flow_depth = flow_depth.saturating_sub(1),
            b'&' | b'*' | b'!' if idx == 0 || matches!(bytes[idx - 1], b' ' | b':' | b'-' | b'[' | b',') => {
                return Err((line_no, "YAML anchors, aliases and custom tags are forbidden".into()));
            }
            b'<' if bytes.get(idx + 1) == Some(&b'<')
                && bytes.get(idx + 2..).is_some_and(|rest| rest.trim_ascii_start().starts_with(b":")) =>
            {
                return Err((line_no, "YAML merge keys (<<) are forbidden".into()));
            }
            _ => {}
        }
        idx += 1;
    }
    Ok(())
}

fn validate_raw_yaml_safety(raw: &str) -> Result<(), (Option<u32>, String)> {
    if raw.is_empty() || raw.len() > MAX_MANIFEST_BYTES {
        return Err((None, format!("module.yaml must be 1..={MAX_MANIFEST_BYTES} bytes")));
    }
    let mut seen_content = false;
    for (idx, line) in raw.lines().enumerate() {
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if line.len() > MAX_LINE_BYTES || line.chars().any(|c| c.is_control() && c != '\t') {
            return Err((Some(line_no), "line exceeds length limit or contains control characters".into()));
        }
        if let Err((ln, msg)) = scan_unquoted_yaml_line(line, line_no, &mut seen_content) {
            return Err((Some(ln), msg));
        }
    }
    if !seen_content {
        return Err((Some(1), "module.yaml is empty".into()));
    }
    Ok(())
}

fn normalize_match_condition(cond: &RawMatchCondition, is_url_type: bool) -> Result<(String, Option<String>, Option<String>)> {
    ensure!(super::valid_host(&cond.host), "invalid match.host \"{}\"", cond.host);
    if let Some(method) = cond.method.as_deref() {
        ensure!(
            matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"),
            "unsupported match.method \"{method}\""
        );
    }
    validate_regex(cond.regex.as_deref())?;
    match (cond.path.as_deref(), cond.regex.as_deref()) {
        (Some(path), regex) => {
            if is_url_type {
                ensure!(valid_url_path(path), "invalid URL match.path \"{path}\"");
            } else {
                ensure!(
                    path.starts_with('/') && !path.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#')),
                    "invalid match.path \"{path}\""
                );
            }
            Ok((path.to_owned(), cond.method.clone(), regex.map(str::to_owned)))
        }
        (None, Some(regex)) => Ok((String::new(), cond.method.clone(), Some(regex.to_owned()))),
        (None, None) => {
            // Omitted path matches any path on the explicit admitted host:443.
            let host_pattern = format!("^https://{}/", cond.host.replace('.', r"\."));
            validate_regex(Some(&host_pattern))?;
            Ok((String::new(), cond.method.clone(), Some(host_pattern)))
        }
    }
}

fn parse_header_action(action: &serde_yaml_ng::Mapping, prefix: &str, limit: usize) -> Result<Vec<(String, Option<String>)>> {
    ensure!(action.len() == 1, "header rewrite action requires either `set` or `remove`");
    let headers: Vec<(String, Option<String>)> = if let Some(value) = action.get("set") {
        let map: BTreeMap<String, String> = serde_yaml_ng::from_value(value.clone())?;
        map.into_iter().map(|(name, value)| (name, Some(value))).collect()
    } else if let Some(value) = action.get("remove") {
        let names: Vec<String> = serde_yaml_ng::from_value(value.clone())?;
        names.into_iter().map(|name| (name, None)).collect()
    } else {
        bail!("header rewrite action requires either `set` or `remove`");
    };
    ensure!((1..=4).contains(&headers.len()), "header action must specify 1..=4 headers");
    let mut seen = BTreeSet::new();
    for (name, value) in &headers {
        let lower = name.to_ascii_lowercase();
        ensure!(
            lower.strip_prefix(prefix).is_some_and(|rest| {
                !rest.is_empty() && rest.len() <= limit && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
            "unsupported header name "{name}" (expected {prefix}*)"
        );
        if let Some(value) = value {
            ensure!(
                value.chars().count() <= 1024
                    && value.chars().all(|c| c == '\t' || (' '..='~').contains(&c) || ('\u{80}'..='\u{ff}').contains(&c)),
                "invalid header value for "{name}""
            );
        } else {
            ensure!(seen.insert(lower), "duplicate header removal "{name}"");
        }
    }
    Ok(headers)
}

pub(crate) fn parse_and_compile_manifest(
    manifest_path: &str,
    raw: &str,
) -> std::result::Result<(RawModuleManifest, CompiledModuleRewrites), ModuleDiagnostic> {
    if let Err((line, message)) = validate_raw_yaml_safety(raw) {
        return Err(ModuleDiagnostic {
            manifest_path: manifest_path.to_owned(),
            line,
            message,
        });
    }
    let manifest: RawModuleManifest = serde_yaml_ng::from_str(raw).map_err(|err| ModuleDiagnostic {
        manifest_path: manifest_path.to_owned(),
        line: err.location().and_then(|loc| u32::try_from(loc.line()).ok()),
        message: err.to_string(),
    })?;
    compile_validated_manifest(manifest).map_err(|err| ModuleDiagnostic {
        manifest_path: manifest_path.to_owned(),
        line: None,
        message: err.to_string(),
    })
}

fn compile_validated_manifest(manifest: RawModuleManifest) -> Result<(RawModuleManifest, CompiledModuleRewrites)> {
    ensure!(manifest.kind == "netverge-module", "expected kind: netverge-module");
    ensure!(manifest.schema == 1, "unsupported module schema {}", manifest.schema);
    ensure!(valid_module_id(&manifest.id), "invalid reverse-domain module ID \"{}\"", manifest.id);
    ensure!(
        !manifest.name.trim().is_empty() && manifest.name.chars().count() <= 80 && !manifest.name.chars().any(char::is_control),
        "invalid module name"
    );
    ensure!(
        !manifest.version.is_empty()
            && manifest.version.len() <= 32
            && manifest.version.bytes().all(|b| (0x21..=0x7e).contains(&b)),
        "invalid module version"
    );
    ensure!(manifest.description.as_ref().is_none_or(|d| d.chars().count() <= 256 && !d.chars().any(char::is_control)), "invalid module description");
    ensure!(manifest.author.as_ref().is_none_or(|a| a.chars().count() <= 64 && !a.chars().any(char::is_control)), "invalid module author");
    if let Some(mitm) = &manifest.mitm {
        ensure!(mitm.hostnames.len() <= MAX_MITM_PROPOSALS, "too many proposed MITM hostnames");
        let mut seen_hosts = BTreeSet::new();
        for host in &mitm.hostnames {
            ensure!(super::valid_host(host) && seen_hosts.insert(host.as_str()), "invalid or duplicate MITM hostname \"{host}\"");
        }
    }
    ensure!(manifest.rewrite.len() <= MAX_REWRITE_ENTRIES, "at most 16 rewrite entries are supported per module");
    ensure!(manifest.scripts.len() <= MAX_SCRIPT_ENTRIES, "at most 8 script entries are supported per module");

    let source = format!("module:{}", manifest.id);
    let mut seen_ids = BTreeSet::new();
    let mut compiled = CompiledModuleRewrites::default();
    for item in &manifest.rewrite {
        ensure!(valid_local_entry_id(&item.id) && seen_ids.insert(item.id.as_str()), "invalid or duplicate rewrite ID \"{}\"", item.id);
        let is_url = item.kind == "url";
        let (path, method, regex) = normalize_match_condition(&item.condition, is_url)?;
        match item.kind.as_str() {
            "url" => {
                ensure!(item.action.len() == 1, "url action must contain only `replace`");
                let target = item
                    .action
                    .get(serde_yaml_ng::Value::String("replace".into()))
                    .and_then(serde_yaml_ng::Value::as_str)
                    .unwrap_or("");
                ensure!(valid_url_path(target), "invalid url replace target \"{target}\"");
                compiled.path.push(UrlPathRule {
                    id: Some(format!("{}:{}", manifest.id, item.id)),
                    source: Some(source.clone()),
                    enabled: true,
                    host: item.condition.host.clone(),
                    path,
                    method,
                    regex,
                    target: target.to_owned(),
                });
            }
            "request-header" | "response-header" => {
                let is_req = item.kind == "request-header";
                let headers = parse_header_action(&item.action, if is_req { "x-custom-" } else { "x-" }, if is_req { 91 } else { 100 })?;
                let multi = headers.len() > 1;
                for (idx, (header, value)) in headers.into_iter().enumerate() {
                    let rule_id = if multi {
                        format!("{}:{}.{}", manifest.id, item.id, idx + 1)
                    } else {
                        format!("{}:{}", manifest.id, item.id)
                    };
                    let out = ResponseHeaderRule {
                        id: Some(rule_id),
                        source: Some(source.clone()),
                        enabled: true,
                        host: item.condition.host.clone(),
                        path: path.clone(),
                        method: method.clone(),
                        regex: regex.clone(),
                        header,
                        remove: value.is_none().then_some(true),
                        value: value.unwrap_or_default(),
                    };
                    if is_req { compiled.request.push(out); } else { compiled.response.push(out); }
                }
            }
            "response-body" => {
                ensure!(item.action.len() == 2, "response-body action requires `search` and `replace`");
                let search = item
                    .action
                    .get(serde_yaml_ng::Value::String("search".into()))
                    .and_then(serde_yaml_ng::Value::as_str)
                    .unwrap_or("");
                let Some(replace) = item
                    .action
                    .get(serde_yaml_ng::Value::String("replace".into()))
                    .and_then(serde_yaml_ng::Value::as_str)
                else {
                    bail!("response-body action requires string `replace`");
                };
                ensure!(!search.is_empty() && search.len() <= 1024 && replace.len() <= 4096, "invalid response-body search/replace bounds");
                compiled.body.push(ResponseBodyRule {
                    id: Some(format!("{}:{}", manifest.id, item.id)),
                    source: Some(source.clone()),
                    enabled: true,
                    host: item.condition.host.clone(),
                    path,
                    method,
                    regex,
                    search: search.to_owned(),
                    value: replace.to_owned(),
                });
            }
            other => bail!("unsupported rewrite type \"{other}\""),
        }
    }
    ensure!(
        compiled.request.len() <= MAX_REWRITE_ENTRIES && compiled.response.len() <= MAX_REWRITE_ENTRIES,
        "expanded module header rules exceed 16 per phase"
    );

    let mut seen_scripts = BTreeSet::new();
    for script in &manifest.scripts {
        ensure!(valid_local_entry_id(&script.id) && seen_scripts.insert(script.id.as_str()), "invalid or duplicate script ID \"{}\"", script.id);
        ensure!(matches!(script.kind.as_str(), "http-request" | "http-response"), "unsupported script type \"{}\"", script.kind);
        let _ = normalize_match_condition(&script.condition, false)?;
        ensure!(script.max_size.is_none_or(|sz| (1024..=262_144).contains(&sz)), "script max-size must be 1024..=262144");
        ensure!(script.timeout.is_none_or(|t| (1..=5).contains(&t)), "script timeout must be 1..=5 seconds");
        ensure!(script.argument.as_ref().is_none_or(|arg| arg.len() <= 1024), "script argument exceeds 1024 bytes");
    }
    Ok((manifest, compiled))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_removal_compiles_and_checks_names() -> Result<()> {
        let manifest = r#"
kind: netverge-module
schema: 1
id: com.example.remove
name: Remove diagnostic header
version: "1"
rewrite:
  - id: drop-debug
    type: request-header
    match:
      host: api.example.test
      path: /v1
    action:
      remove: [X-Custom-Debug]
"#;
        let (_, compiled) = parse_and_compile_manifest("module.yaml", manifest)
            .map_err(|diag| anyhow::anyhow!(diag.message))?;
        let rule = &compiled.request[0];
        assert_eq!(rule.remove, Some(true));
        assert_eq!(rule.header, "X-Custom-Debug");
        assert!(rule.value.is_empty());

        for headers in ["[]", "[Host]", "[X-Custom-Debug, x-custom-debug]"] {
            let invalid = manifest.replace("[X-Custom-Debug]", headers);
            assert!(parse_and_compile_manifest("module.yaml", &invalid).is_err(), "{headers}");
        }
        let ambiguous = manifest.replace("      remove:", "      set: {X-Custom-Debug: '1'}\n      remove:");
        assert!(parse_and_compile_manifest("module.yaml", &ambiguous).is_err());
        Ok(())
    }

    #[test]
    fn parses_native_manifest_and_rejects_unsafe_yaml_constructs() -> Result<()> {
        let valid = r#"
kind: netverge-module
schema: 1
id: com.example.api-debug
name: API debug
version: "1.0.0"
mitm:
  hostnames:
    - api.example.test
rewrite:
  - id: redirect-v1
    type: url
    match:
      host: api.example.test
      path: /v1
    action:
      replace: /v2
  - id: add-debug
    type: request-header
    match:
      host: api.example.test
    action:
      set:
        X-Custom-Debug: "true"
scripts:
  - id: inspect-res
    type: http-response
    match:
      host: api.example.test
    script: modules/api-debug/debug.js
    requires-body: true
    timeout: 5
"#;
        let (parsed, compiled) = parse_and_compile_manifest("modules/api-debug/module.yaml", valid)
            .map_err(|diag| anyhow::anyhow!(diag.message))?;
        assert_eq!(parsed.id, "com.example.api-debug");
        assert_eq!(compiled.path[0].id.as_deref(), Some("com.example.api-debug:redirect-v1"));
        assert_eq!(compiled.request[0].source.as_deref(), Some("module:com.example.api-debug"));
        assert_eq!(compiled.request[0].path, "");
        assert_eq!(compiled.request[0].regex.as_deref(), Some(r"^https://api\.example\.test/"));

        for bad in [
            "kind: netverge-module\nschema: 2\nid: com.example.a\nname: A\nversion: '1'\n",
            "kind: netverge-module\nschema: 1\nid: com.example.a\nname: &a A\nauthor: *a\nversion: '1'\n",
            "kind: netverge-module\nschema: 1\nid: com.example.a\nname: !custom A\nversion: '1'\n",
            "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nversion: '1'\n<<: {}\n",
            "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nname: B\nversion: '1'\n",
            "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nversion: '1'\nextra: 1\n",
            "kind: netverge-module\nschema: 1\nid: com.example.a\nname: A\nversion: '1'\n---\nkind: netverge-module\n",
        ] {
            let Err(diag) = parse_and_compile_manifest("module.yaml", bad) else {
                bail!("expected rejection for malformed manifest");
            };
            assert!(!diag.message.is_empty());
        }
        Ok(())
    }
}
