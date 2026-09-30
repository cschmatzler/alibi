//! The pinned plugin deliberately parses only the fields it uses. A strict
//! ERC-4361 parser would also reject messages whose URI, version or issued-at
//! fields Better Auth passes unchanged to the application verifier.

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
            if let Some(line) = line.strip_suffix('\n') {
                line.strip_suffix('\r').unwrap_or(line)
            } else {
                line
            }
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

pub(super) fn js_trim(value: &str) -> &str {
    value.trim_matches(js_whitespace)
}

fn js_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

fn js_number(value: &str) -> Option<f64> {
    let value = js_trim(value);
    if value.is_empty() {
        return Some(0.0);
    }
    for (prefixes, radix, bits) in [
        (["0x", "0X"], 16, 4),
        (["0o", "0O"], 8, 3),
        (["0b", "0B"], 2, 1),
    ] {
        if let Some(digits) = prefixes
            .iter()
            .find_map(|prefix| value.strip_prefix(prefix))
        {
            return radix_number(digits, radix, bits);
        }
    }
    value.parse().ok()
}

/// Parse power-of-two radix integers with one IEEE-754 rounding, including
/// values wider than u64. Incremental floating addition would round each digit
/// and can change the chain presented to the verifier.
fn radix_number(digits: &str, radix: u32, bits_per_digit: usize) -> Option<f64> {
    if digits.is_empty() {
        return None;
    }
    let digits = digits
        .chars()
        .map(|character| character.to_digit(radix))
        .collect::<Option<Vec<_>>>()?;
    let Some(first_nonzero) = digits.iter().position(|digit| *digit != 0) else {
        return Some(0.0);
    };
    let significant = digits.get(first_nonzero..)?;
    let first = *significant.first()?;
    let first_bits = (u32::BITS - first.leading_zeros()) as usize;
    let bit_length = first_bits + (significant.len() - 1) * bits_per_digit;
    if bit_length > 1024 {
        return Some(f64::INFINITY);
    }
    let mut mantissa = 0u64;
    let mut position = 0;
    let mut guard = false;
    let mut sticky = false;
    for (index, digit) in significant.iter().enumerate() {
        let width = if index == 0 {
            first_bits
        } else {
            bits_per_digit
        };
        for bit in (0..width).rev() {
            let set = (*digit >> bit) & 1 != 0;
            if position < 53 {
                mantissa = (mantissa << 1) | u64::from(set);
            } else if position == 53 {
                guard = set;
            } else {
                sticky |= set;
            }
            position += 1;
        }
    }
    if bit_length <= 53 {
        return Some(mantissa as f64);
    }
    if guard && (sticky || mantissa & 1 != 0) {
        mantissa += 1;
    }
    Some(mantissa as f64 * 2.0f64.powi((bit_length - 53) as i32))
}
