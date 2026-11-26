use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    module_yaml::validate_raw_yaml_safety,
    rewrite::{LocalResponseRule, ResponseBodyRule, ResponseHeaderRule, UrlPathRule},
    url_regex::validate_regex,
};

pub(crate) const MAX_MANIFEST_BYTES: usize = 65_536;
const MAX_REWRITE_ENTRIES: usize = 16;
const MAX_SCRIPT_ENTRIES: usize = 8;
const MAX_MITM_PROPOSALS: usize = 32;

mod local_action;
use local_action::{LocalRuleContext, compile_local_action};

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) local: Vec<LocalResponseRule>,
}

pub(crate) struct CompiledManifestOutput {
    pub(crate) manifest: RawModuleManifest,
    pub(crate) rewrites: CompiledModuleRewrites,
    pub(crate) inline_blobs: BTreeMap<String, Vec<u8>>,
    pub(crate) map_local_files: Vec<(usize, String)>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
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

fn normalize_match_condition(
    cond: &RawMatchCondition,
    is_url_type: bool,
) -> Result<(String, Option<String>, Option<String>)> {
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
                    path.starts_with('/')
                        && !path.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#')),
                    "invalid match.path \"{path}\""
                );
            }
            Ok((path.to_owned(), cond.method.clone(), regex.map(str::to_owned)))
        }
        (None, Some(regex)) => Ok((String::new(), cond.method.clone(), Some(regex.to_owned()))),
        (None, None) => {
            let host_pattern = format!("^https://{}/", cond.host.replace('.', r"\."));
            validate_regex(Some(&host_pattern))?;
            Ok((String::new(), cond.method.clone(), Some(host_pattern)))
        }
    }
}

fn validate_header_map(map: BTreeMap<String, String>, prefix: &str, limit: usize) -> Result<Vec<(String, String)>> {
    ensure!((1..=4).contains(&map.len()), "header map must specify 1..=4 headers");
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(map.len());
    for (name, value) in map {
        let lower = name.to_ascii_lowercase();
        ensure!(
            lower.strip_prefix(prefix).is_some_and(|rest| {
                !rest.is_empty() && rest.len() <= limit && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
            "unsupported header name '{name}' (expected {prefix}*)"
        );
        ensure!(seen.insert(lower), "duplicate header name '{name}'");
        ensure!(
            value.chars().count() <= 1024
                && value.chars().all(|c| c == '\t' || (' '..='~').contains(&c) || ('\u{80}'..='\u{ff}').contains(&c)),
            "invalid header value for '{name}'"
        );
        out.push((name, value));
    }
    Ok(out)
}

fn parse_header_action(action: &serde_yaml_ng::Mapping, prefix: &str, limit: usize) -> Result<Vec<(String, Option<String>)>> {
    ensure!(action.len() == 1, "header rewrite action requires either `set` or `remove`");
    if let Some(value) = action.get("set") {
        let pairs = validate_header_map(serde_yaml_ng::from_value(value.clone())?, prefix, limit)?;
        return Ok(pairs.into_iter().map(|(k, v)| (k, Some(v))).collect());
    }
    let Some(value) = action.get("remove") else {
        bail!("header rewrite action requires either `set` or `remove`");
    };
    let names: Vec<String> = serde_yaml_ng::from_value(value.clone())?;
    ensure!((1..=4).contains(&names.len()), "header action must specify 1..=4 headers");
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let lower = name.to_ascii_lowercase();
        ensure!(
            lower.strip_prefix(prefix).is_some_and(|rest| {
                !rest.is_empty() && rest.len() <= limit && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
            "unsupported header name '{name}' (expected {prefix}*)"
        );
        ensure!(seen.insert(lower), "duplicate header removal '{name}'");
        out.push((name, None));
    }
    Ok(out)
}

fn compile_url_action(action: &serde_yaml_ng::Mapping) -> Result<(String, Option<Vec<String>>)> {
    ensure!(action.len() == 1, "url action requires either replace or remove-query");
    if let Some(value) = action.get("replace") {
        let target = value.as_str().unwrap_or("");
        ensure!(valid_url_path(target), "invalid url replace target '{target}'");
        return Ok((target.to_owned(), None));
    }
    let Some(value) = action.get("remove-query") else {
        bail!("url action requires either replace or remove-query");
    };
    let names: Vec<String> = serde_yaml_ng::from_value(value.clone())?;
    ensure!((1..=8).contains(&names.len()), "remove-query requires 1..=8 names");
    let mut seen = BTreeSet::new();
    for name in &names {
        ensure!(
            (1..=64).contains(&name.len())
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                && seen.insert(name),
            "expected distinct unreserved ASCII query names"
        );
    }
    Ok((String::new(), Some(names)))
}

fn compile_body_action(action: &serde_yaml_ng::Mapping) -> Result<(String, String, Option<bool>)> {
    let match_whole = action
        .get("match-whole")
        .map(|value| value.as_bool().ok_or_else(|| anyhow::anyhow!("match-whole must be a boolean")))
        .transpose()?;
    ensure!(
        action.len() == if match_whole.is_some() { 3 } else { 2 },
        "response-body action requires search and replace and supports optional match-whole"
    );
    let search = action.get("search").and_then(serde_yaml_ng::Value::as_str).unwrap_or("");
    let Some(replace) = action.get("replace").and_then(serde_yaml_ng::Value::as_str) else {
        bail!("response-body action requires string `replace`");
    };
    ensure!(
        !search.is_empty() && search.len() <= 1024 && replace.len() <= 4096,
        "invalid response-body search/replace bounds"
    );
    Ok((search.to_owned(), replace.to_owned(), match_whole.filter(|w| *w)))
}

pub(crate) fn parse_and_compile_manifest(
    manifest_path: &str,
    raw: &str,
) -> std::result::Result<CompiledManifestOutput, ModuleDiagnostic> {
    if let Err((line, message)) = validate_raw_yaml_safety(raw) {
        return Err(ModuleDiagnostic { manifest_path: manifest_path.to_owned(), line, message });
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

fn validate_manifest_metadata(manifest: &RawModuleManifest) -> Result<()> {
    ensure!(manifest.kind == "netverge-module", "expected kind: netverge-module");
    ensure!(manifest.schema == 1, "unsupported module schema {}", manifest.schema);
    ensure!(valid_module_id(&manifest.id), "invalid reverse-domain module ID \"{}\"", manifest.id);
    ensure!(
        !manifest.name.trim().is_empty() && manifest.name.chars().count() <= 80 && !manifest.name.chars().any(char::is_control),
        "invalid module name"
    );
    ensure!(
        !manifest.version.is_empty() && manifest.version.len() <= 32 && manifest.version.bytes().all(|b| (0x21..=0x7e).contains(&b)),
        "invalid module version"
    );
    ensure!(
        manifest.description.as_ref().is_none_or(|d| d.chars().count() <= 256 && !d.chars().any(char::is_control)),
        "invalid module description"
    );
    ensure!(
        manifest.author.as_ref().is_none_or(|a| a.chars().count() <= 64 && !a.chars().any(char::is_control)),
        "invalid module author"
    );
    if let Some(mitm) = &manifest.mitm {
        ensure!(mitm.hostnames.len() <= MAX_MITM_PROPOSALS, "too many proposed MITM hostnames");
        let mut seen_hosts = BTreeSet::new();
        for host in &mitm.hostnames {
            ensure!(super::valid_host(host) && seen_hosts.insert(host.as_str()), "invalid or duplicate MITM hostname \"{host}\"");
        }
    }
    ensure!(manifest.rewrite.len() <= MAX_REWRITE_ENTRIES, "at most 16 rewrite entries are supported per module");
    ensure!(manifest.scripts.len() <= MAX_SCRIPT_ENTRIES, "at most 8 script entries are supported per module");
    Ok(())
}

fn compile_validated_manifest(manifest: RawModuleManifest) -> Result<CompiledManifestOutput> {
    validate_manifest_metadata(&manifest)?;
    let source = format!("module:{}", manifest.id);
    let mut seen_ids = BTreeSet::new();
    let mut rewrites = CompiledModuleRewrites::default();
    let mut inline_blobs = BTreeMap::new();
    let mut map_local_files = Vec::new();

    for item in &manifest.rewrite {
        ensure!(valid_local_entry_id(&item.id) && seen_ids.insert(item.id.as_str()), "invalid or duplicate rewrite ID \"{}\"", item.id);
        let (path, method, regex) = normalize_match_condition(&item.condition, item.kind == "url")?;
        let full_id = format!("{}:{}", manifest.id, item.id);
        match item.kind.as_str() {
            "url" => {
                let (target, remove_query) = compile_url_action(&item.action)?;
                rewrites.path.push(UrlPathRule {
                    id: Some(full_id),
                    source: Some(source.clone()),
                    enabled: true,
                    host: item.condition.host.clone(),
                    path,
                    method,
                    regex,
                    target,
                    remove_query,
                });
            }
            "request-header" | "response-header" => {
                let is_req = item.kind == "request-header";
                let headers = parse_header_action(&item.action, if is_req { "x-custom-" } else { "x-" }, if is_req { 91 } else { 100 })?;
                let multi = headers.len() > 1;
                for (idx, (header, value)) in headers.into_iter().enumerate() {
                    let rule_id = if multi { format!("{full_id}.{}", idx + 1) } else { full_id.clone() };
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
                    if is_req {
                        rewrites.request.push(out);
                    } else {
                        rewrites.response.push(out);
                    }
                }
            }
            "response-body" => {
                let (search, value, match_whole) = compile_body_action(&item.action)?;
                rewrites.body.push(ResponseBodyRule {
                    id: Some(full_id),
                    source: Some(source.clone()),
                    enabled: true,
                    host: item.condition.host.clone(),
                    path,
                    method,
                    regex,
                    search,
                    value,
                    match_whole,
                });
            }
            "mock" | "map-local" => {
                let (rule, asset_file) = compile_local_action(
                    item.kind == "mock",
                    LocalRuleContext {
                        id: full_id,
                        source: source.clone(),
                        host: item.condition.host.clone(),
                        path,
                        method,
                        regex,
                    },
                    &item.action,
                    &mut inline_blobs,
                )?;
                let idx = rewrites.local.len();
                rewrites.local.push(rule);
                if let Some(file) = asset_file {
                    map_local_files.push((idx, file));
                }
            }
            other => bail!("unsupported rewrite type \"{other}\""),
        }
    }
    ensure!(
        rewrites.request.len() <= MAX_REWRITE_ENTRIES && rewrites.response.len() <= MAX_REWRITE_ENTRIES,
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
    Ok(CompiledManifestOutput { manifest, rewrites, inline_blobs, map_local_files })
}

#[cfg(test)]
mod tests;
