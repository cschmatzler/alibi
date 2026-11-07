use super::{AuthError, AuthResult};

pub(super) fn invalid_disposition() -> AuthError {
    AuthError::CallbackFailure(Box::new(AuthError::internal(
        "Failed to parse body as FormData.",
    )))
}

// Multer's HeaderMap keeps only the last duplicate header. Fetch validates
// every Content-Disposition before a later one can replace its attributes.
pub(super) fn validate_dispositions(mut body: &[u8], boundary: &str) -> AuthResult<()> {
    let marker = format!("--{boundary}");
    while let Some(index) = find(body, marker.as_bytes()) {
        body = &body[index + marker.len()..];
        if body.starts_with(b"--") {
            return Ok(());
        }
        body = body.strip_prefix(b"\r\n").ok_or_else(invalid_disposition)?;
        let end = find(body, b"\r\n\r\n").ok_or_else(invalid_disposition)?;
        for line in body[..end].split(|byte| *byte == b'\n') {
            let Some(colon) = line.iter().position(|byte| *byte == b':') else {
                continue;
            };
            if line[..colon]
                .trim_ascii()
                .eq_ignore_ascii_case(b"content-disposition")
            {
                _ = disposition(line[colon + 1..].trim_ascii())?;
            }
        }
        body = &body[end + 4..];
    }
    Ok(())
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}

// Match the pinned Fetch multipart parser's attribute grammar rather than
// multer's case-sensitive, first-match name/filename extraction.
pub(super) fn disposition(mut input: &[u8]) -> AuthResult<(String, Option<String>)> {
    if !take_while(&mut input, token).eq_ignore_ascii_case(b"form-data") {
        return Err(invalid_disposition());
    }
    let mut name = None;
    let mut filename = None;
    let mut extended_filename = false;
    while !input.is_empty() {
        if input.first() == Some(&b';') {
            input = &input[1..];
        }
        _ = take_while(&mut input, |byte| matches!(byte, b' ' | b'\t'));
        let attribute = take_while(&mut input, |byte| token(byte) && byte != b'*');
        if attribute.is_empty() {
            break;
        }
        let extended = input.first() == Some(&b'*');
        if extended {
            input = &input[1..];
        }
        if input.first() != Some(&b'=') {
            break;
        }
        input = &input[1..];
        _ = take_while(&mut input, |byte| matches!(byte, b' ' | b'\t'));
        let value = if extended {
            let raw = take_while(&mut input, |byte| !matches!(byte, b' ' | b';'));
            let mut parts = raw.splitn(3, |byte| *byte == b'\'');
            let charset = parts.next().ok_or_else(invalid_disposition)?;
            let _language = parts.next().ok_or_else(invalid_disposition)?;
            let value = parts.next().ok_or_else(invalid_disposition)?;
            if !charset.eq_ignore_ascii_case(b"utf-8") {
                return Err(invalid_disposition());
            }
            decode_extended(&decode_header(value))?
        } else if input.first() == Some(&b'"') {
            input = &input[1..];
            let raw = take_while(&mut input, |byte| byte != b'"');
            if input.first() != Some(&b'"') {
                return Err(invalid_disposition());
            }
            input = &input[1..];
            decode_header(raw)
                .replace("%0A", "\n")
                .replace("%0a", "\n")
                .replace("%0D", "\r")
                .replace("%0d", "\r")
                .replace("%22", "\"")
        } else {
            decode_header(take_while(&mut input, token))
        };
        if attribute.eq_ignore_ascii_case(b"name") {
            name = Some(value);
        } else if attribute.eq_ignore_ascii_case(b"filename") && (extended || !extended_filename) {
            filename = Some(value);
            extended_filename |= extended;
        }
    }
    if !input.is_empty() {
        return Err(invalid_disposition());
    }
    Ok((name.ok_or_else(invalid_disposition)?, filename))
}

fn token(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
        && !matches!(
            byte,
            b'(' | b')'
                | b'<'
                | b'>'
                | b'@'
                | b','
                | b';'
                | b':'
                | b'\\'
                | b'"'
                | b'/'
                | b'['
                | b']'
                | b'?'
                | b'='
        )
}

fn take_while<'a>(input: &mut &'a [u8], predicate: impl Fn(u8) -> bool) -> &'a [u8] {
    let length = input.iter().take_while(|byte| predicate(**byte)).count();
    let (value, rest) = input.split_at(length);
    *input = rest;
    value
}

fn decode_header(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned()
}

fn decode_extended(value: &str) -> AuthResult<String> {
    let malformed = || AuthError::CallbackFailure(Box::new(AuthError::internal("URI malformed")));
    let mut input = value.as_bytes().iter().copied();
    let mut decoded = Vec::new();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let mut digit = || {
                input
                    .next()
                    .and_then(|byte| char::from(byte).to_digit(16))
                    .ok_or_else(malformed)
            };
            decoded.push((digit()? * 16 + digit()?) as u8);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).map_err(|_| malformed())
}
