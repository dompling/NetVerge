//! Shared strict response framing for authenticated local control endpoints.
//! A persistent named pipe does not have to close after a complete response.
use anyhow::{Context, Result, ensure};

pub(crate) const MAX_RESPONSE: usize = 65536;

pub(crate) fn complete(raw: &[u8]) -> Result<Option<(u16, &[u8])>> {
    ensure!(raw.len() <= MAX_RESPONSE, "control response exceeds limit");
    let Some(pos) = raw.windows(4).position(|x| x == b"\r\n\r\n") else { return Ok(None); };
    let header = std::str::from_utf8(&raw[..pos])?;
    let mut lines = header.split("\r\n");
    let first = lines.next().context("missing HTTP status")?;
    ensure!(first.starts_with("HTTP/1.1 ") || first.starts_with("HTTP/1.0 "), "unexpected HTTP status");
    let status = first.split_whitespace().nth(1).context("missing HTTP code")?.parse::<u16>()?;
    ensure!((200..=599).contains(&status), "unexpected interim HTTP response");
    let mut length = None;
    for line in lines {
        let (key, value) = line.split_once(':').context("invalid HTTP header")?;
        ensure!(!key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b)), "invalid HTTP header name");
        ensure!(!key.eq_ignore_ascii_case("transfer-encoding"), "unsupported HTTP framing");
        if key.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "duplicate content length");
            let value = value.trim();
            ensure!(!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()), "invalid content length");
            length = Some(value.parse::<usize>()?);
        }
    }
    let length = if status == 204 {
        ensure!(length.unwrap_or(0) == 0, "unexpected body");
        0
    } else {
        length.context("missing content length")?
    };
    ensure!(length <= 32768, "control body exceeds limit");
    let body_start = pos + 4;
    ensure!(body_start + length <= MAX_RESPONSE, "control response exceeds limit");
    if raw.len() < body_start + length { return Ok(None); }
    ensure!(raw.len() == body_start + length, "unexpected bytes after control response");
    Ok(Some((status, &raw[body_start..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_fragmentation_and_bodyless_success() -> Result<()> {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        for n in 0..response.len() { assert!(complete(&response[..n])?.is_none()); }
        assert_eq!(complete(response)?, Some((200, b"abc".as_slice())));
        assert_eq!(complete(b"HTTP/1.1 204 No Content\r\n\r\n")?, Some((204, b"".as_slice())));
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_or_oversized_framing() {
        for response in [
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length : 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: +0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 32769\r\n\r\n",
            "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx",
            "HTTP/1.1 100 Continue\r\n\r\n",
        ] { assert!(complete(response.as_bytes()).is_err(), "{response:?}"); }
        assert!(complete(&vec![b'a'; MAX_RESPONSE + 1]).is_err());
    }
}
