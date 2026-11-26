use anyhow::{Result, bail, ensure};
use std::collections::BTreeMap;

use super::{sha256_hex, validate_header_map};
use crate::core::mitm::rewrite::LocalResponseRule;

const MAX_INLINE_MOCK_BYTES: usize = 16_384;

pub(super) struct LocalRuleContext {
    pub(super) id: String,
    pub(super) source: String,
    pub(super) host: String,
    pub(super) path: String,
    pub(super) method: Option<String>,
    pub(super) regex: Option<String>,
}

fn valid_mime_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
}

fn valid_content_type(ct: &str) -> bool {
    if !(3..=128).contains(&ct.len()) || ct.trim() != ct {
        return false;
    }
    let mut parts = ct.split(';');
    let Some((ty, sub)) = parts.next().and_then(|m| m.trim().split_once('/')) else {
        return false;
    };
    valid_mime_token(ty)
        && valid_mime_token(sub)
        && parts.all(|p| {
            p.trim()
                .split_once('=')
                .is_some_and(|(k, v)| valid_mime_token(k) && valid_mime_token(v))
        })
}

fn infer_content_type(file_path: &str) -> &'static str {
    let lower = file_path.rsplit('/').next().unwrap_or(file_path).to_ascii_lowercase();
    match lower.rsplit_once('.').map(|(_, ext)| ext) {
        Some("json") => "application/json; charset=utf-8",
        Some("txt") => "text/plain; charset=utf-8",
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub(super) fn compile_local_action(
    is_mock: bool,
    ctx: LocalRuleContext,
    action: &serde_yaml_ng::Mapping,
    inline_blobs: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(LocalResponseRule, Option<String>)> {
    let payload_key = if is_mock { "body" } else { "file" };
    for key in action.keys() {
        let Some(k) = key.as_str() else { bail!("non-string local response action key") };
        ensure!(
            matches!(k, "status" | "content-type" | "headers") || k == payload_key,
            "unsupported {} action key '{k}'",
            if is_mock { "mock" } else { "map-local" }
        );
    }
    let status = match action.get("status") {
        None => 200u16,
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| anyhow::anyhow!("local response status must be an integer"))?,
    };
    ensure!(
        matches!(status, 200 | 201 | 202 | 204 | 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500 | 502 | 503),
        "unsupported local response status {status}"
    );
    let explicit_ct = match action.get("content-type") {
        None => None,
        Some(v) => {
            let ct = v.as_str().ok_or_else(|| anyhow::anyhow!("content-type must be a string"))?;
            ensure!(valid_content_type(ct), "invalid content-type '{ct}'");
            Some(ct.to_owned())
        }
    };
    let headers = match action.get("headers") {
        None => Vec::new(),
        Some(v) => validate_header_map(serde_yaml_ng::from_value(v.clone())?, "x-", 100)?,
    };
    if is_mock {
        if status == 204 {
            ensure!(explicit_ct.is_none(), "204 mock response cannot set content-type");
            let empty_ok = action.get("body").is_none_or(|v| v.as_str() == Some(""));
            ensure!(empty_ok, "204 mock response cannot carry a non-empty body");
            return Ok((
                LocalResponseRule {
                    id: ctx.id,
                    source: ctx.source,
                    enabled: true,
                    host: ctx.host,
                    path: ctx.path,
                    method: ctx.method,
                    regex: ctx.regex,
                    status,
                    content_type: None,
                    headers,
                    body_sha256: sha256_hex(b""),
                    body_len: 0,
                },
                None,
            ));
        }
        let Some(body) = action.get("body").and_then(serde_yaml_ng::Value::as_str) else {
            bail!("mock action requires string `body`");
        };
        ensure!(body.len() <= MAX_INLINE_MOCK_BYTES, "inline mock body exceeds 16384 bytes");
        let sha = sha256_hex(body.as_bytes());
        if !body.is_empty() {
            inline_blobs.insert(sha.clone(), body.as_bytes().to_vec());
        }
        return Ok((
            LocalResponseRule {
                id: ctx.id,
                source: ctx.source,
                enabled: true,
                host: ctx.host,
                path: ctx.path,
                method: ctx.method,
                regex: ctx.regex,
                status,
                content_type: Some(explicit_ct.unwrap_or_else(|| "text/plain; charset=utf-8".into())),
                headers,
                body_sha256: sha,
                body_len: u32::try_from(body.len()).unwrap_or(u32::MAX),
            },
            None,
        ));
    }
    ensure!(status != 204, "map-local does not support status 204");
    let Some(file) = action.get("file").and_then(serde_yaml_ng::Value::as_str) else {
        bail!("map-local action requires string `file`");
    };
    ensure!(
        !file.is_empty() && file.len() <= 256 && !file.chars().any(char::is_control),
        "invalid map-local file path"
    );
    let content_type = Some(explicit_ct.unwrap_or_else(|| infer_content_type(file).into()));
    Ok((
        LocalResponseRule {
            id: ctx.id,
            source: ctx.source,
            enabled: true,
            host: ctx.host,
            path: ctx.path,
            method: ctx.method,
            regex: ctx.regex,
            status,
            content_type,
            headers,
            body_sha256: String::new(),
            body_len: 0,
        },
        Some(file.to_owned()),
    ))
}
