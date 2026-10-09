//! Shared JavaScript primitive coercion used by actual identity and storage boundaries.

/// Nearest `f64` to an integer, as `Number(value)` would produce.
#[expect(
    clippy::cast_precision_loss,
    reason = "JavaScript numbers are IEEE754 doubles"
)]
pub(crate) const fn number_from_i64(value: i64) -> f64 {
    value as f64
}

/// Nearest `f64` to a length or count, as `Number(value)` would produce.
#[expect(
    clippy::cast_precision_loss,
    reason = "JavaScript numbers are IEEE754 doubles"
)]
pub(crate) const fn number_from_usize(value: usize) -> f64 {
    value as f64
}

#[must_use]
pub fn trim(value: &str) -> &str {
    value.trim_matches(is_whitespace)
}

#[must_use]
pub const fn is_whitespace(character: char) -> bool {
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

#[must_use]
pub fn string_to_number(value: &str) -> Option<f64> {
    let value = trim(value);
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
    match value {
        "Infinity" | "+Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ if value.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E')
        }) =>
        {
            value.parse().ok()
        }
        _ => None,
    }
}

/// Parse power-of-two radix integers with one IEEE-754 rounding, including
/// values wider than u64. Incremental floating addition would round each digit
/// and can change the chain presented to the verifier.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    reason = "JavaScript-compatible numbers deliberately retain IEEE754 rounding and guarded integer coercion at the wire or adapter boundary"
)]
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
    let first_bits = first.bit_width() as usize;
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
            match position.cmp(&53) {
                std::cmp::Ordering::Less => mantissa = (mantissa << 1) | u64::from(set),
                std::cmp::Ordering::Equal => guard = set,
                std::cmp::Ordering::Greater => sticky |= set,
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
