use super::module_manifest::MAX_MANIFEST_BYTES;

const MAX_LINE_BYTES: usize = 2048;
const MAX_NESTING_INDENT: usize = 24;

fn scan_unquoted_yaml_line(
    line: &str,
    line_no: u32,
    seen_content: &mut bool,
) -> Result<(), (u32, String)> {
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
            b'&' | b'*' | b'!'
                if idx == 0 || matches!(bytes[idx - 1], b' ' | b':' | b'-' | b'[' | b',') =>
            {
                return Err((line_no, "YAML anchors, aliases and custom tags are forbidden".into()));
            }
            b'<' if bytes.get(idx + 1) == Some(&b'<')
                && bytes
                    .get(idx + 2..)
                    .is_some_and(|rest| rest.trim_ascii_start().starts_with(b":")) =>
            {
                return Err((line_no, "YAML merge keys (<<) are forbidden".into()));
            }
            _ => {}
        }
        idx += 1;
    }
    Ok(())
}

pub(super) fn validate_raw_yaml_safety(raw: &str) -> Result<(), (Option<u32>, String)> {
    if raw.is_empty() || raw.len() > MAX_MANIFEST_BYTES {
        return Err((None, format!("module.yaml must be 1..={MAX_MANIFEST_BYTES} bytes")));
    }
    let mut seen_content = false;
    for (idx, line) in raw.lines().enumerate() {
        let line_no = u32::try_from(idx + 1).unwrap_or(u32::MAX);
        if line.len() > MAX_LINE_BYTES || line.chars().any(|c| c.is_control() && c != '\t') {
            return Err((
                Some(line_no),
                "line exceeds length limit or contains control characters".into(),
            ));
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
