//! The pinned plugin deliberately parses only the fields it uses. A strict
//! ERC-4361 parser would also reject messages whose URI, version or issued-at
//! fields Better Auth passes unchanged to the application verifier.

use better_auth_core::utils::javascript::{
    is_whitespace as js_whitespace, string_to_number as js_number, trim as js_trim,
};
#[derive(Debug, Default)]
pub(super) struct ParsedSiweMessage<'a> {
    pub domain: Option<&'a str>,
    pub address: Option<&'a str>,
    pub chain_id: Option<f64>,
    pub nonce: Option<&'a str>,
    pub expiration_time: Option<&'a str>,
    pub not_before: Option<&'a str>,
}

pub(super) fn valid_nonce(nonce: &str) -> bool {
    (8..=250).contains(&nonce.len()) && nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub(super) fn valid_address(address: &str) -> bool {
    address.len() == 42
        && address.starts_with("0x")
        && address
            .get(2..)
            .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub(super) fn parse_message(message: &str) -> ParsedSiweMessage<'_> {
    let lines: Vec<&str> = message
        .split_inclusive('\n')
        .map(|line| {
            // /\r?\n/ consumes a CR only when it precedes a newline. The final
            // line remains unchanged even when it ends in a lone CR.
            line.strip_suffix('\n')
                .map_or(line, |line| line.strip_suffix('\r').unwrap_or(line))
        })
        .collect();
    let mut parsed = ParsedSiweMessage::default();
    if let Some(first) = lines.first() {
        parsed.domain = first
            .strip_suffix(" wants you to sign in with your Ethereum account:")
            .filter(|value| !value.is_empty() && !value.chars().any(js_whitespace))
            .map(|authority| {
                authority
                    .split_once("://")
                    .filter(|(scheme, domain)| valid_scheme(scheme) && !domain.is_empty())
                    .map_or(authority, |(_, domain)| domain)
            })
            .filter(|domain| !domain.is_empty());
    }
    parsed.address = lines
        .get(1)
        .map(|line| js_trim(line))
        .filter(|address| valid_address(address));
    for line in lines {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b' ')
            || value
                .chars()
                .any(|character| matches!(character, '\r' | '\u{2028}' | '\u{2029}'))
        {
            continue;
        }
        match key {
            "Chain ID" => {
                if let Some(number) = js_number(value).filter(|number| number.fract() == 0.0) {
                    parsed.chain_id = Some(number);
                }
            }
            "Nonce" => parsed.nonce = Some(value),
            "Expiration Time" => parsed.expiration_time = Some(value),
            "Not Before" => parsed.not_before = Some(value),
            _ => {}
        }
    }
    parsed
}

fn valid_scheme(scheme: &str) -> bool {
    scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
}

pub(super) fn normalize_domain(domain: &str) -> String {
    let lower = js_trim(domain).to_lowercase();
    let authority = lower
        .split_once("://")
        .filter(|(scheme, _)| valid_scheme(scheme))
        .map_or(lower.as_str(), |(_, authority)| authority);
    authority.split('/').next().unwrap_or(authority).to_owned()
}
