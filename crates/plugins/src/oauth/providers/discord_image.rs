use super::Value;
use alibi_core::utils::{javascript, json::JsString};
use rsa::BigUint;

pub(super) fn image_url(profile: &Value) -> Result<JsString, String> {
    let avatar = profile.property("avatar").map_err(str::to_owned)?;
    if avatar.is_null() {
        let discriminator = profile.property("discriminator").map_err(str::to_owned)?;
        let index = if discriminator == "0" {
            snowflake_number(&profile.property("id").map_err(str::to_owned)?)? % 6.0
        } else {
            parse_int(&discriminator)? % 5.0
        };
        let index = Value::Number(index)
            .coerce_string()
            .map_err(str::to_owned)?;
        return Ok(format!("https://cdn.discordapp.com/embed/avatars/{index}.png").into());
    }
    let Value::String(avatar) = avatar else {
        return Err("Discord avatar.startsWith is not a function".into());
    };
    let id = profile
        .property("id")
        .map_err(str::to_owned)?
        .coerce_js_string()
        .map_err(str::to_owned)?;
    let suffix = if avatar
        .code_units()
        .starts_with(&[u16::from(b'a'), u16::from(b'_')])
    {
        ".gif"
    } else {
        ".png"
    };
    let mut units: Vec<_> = "https://cdn.discordapp.com/avatars/"
        .encode_utf16()
        .collect();
    for part in [id, "/".into(), avatar, suffix.into()] {
        units.extend_from_slice(part.code_units());
    }
    Ok(JsString::from_code_units(units))
}

fn snowflake_number(value: &Value) -> Result<f64, String> {
    let invalid = || "Invalid Discord BigInt snowflake".to_owned();
    let (negative, magnitude) = match value {
        Value::Null | Value::Undefined => return Err(invalid()),
        Value::Number(number) => {
            if !number.is_finite() || number.fract() != 0.0 {
                return Err(invalid());
            }
            (
                number.is_sign_negative(),
                BigUint::parse_bytes(format!("{:.0}", number.abs()).as_bytes(), 10)
                    .ok_or_else(invalid)?,
            )
        }
        Value::Bool(boolean) => (false, BigUint::from(u8::from(*boolean))),
        _ => {
            let text = value
                .coerce_js_string()
                .map_err(str::to_owned)?
                .trim_matches(javascript::is_whitespace);
            let text = text.as_str().ok_or_else(invalid)?;
            if text.is_empty() {
                (false, BigUint::from(0_u8))
            } else {
                let signed = text.starts_with(['+', '-']);
                let negative = text.starts_with('-');
                let digits = if signed { &text[1..] } else { text };
                let (radix, digits) = if digits.starts_with("0x") || digits.starts_with("0X") {
                    (16, &digits[2..])
                } else if digits.starts_with("0o") || digits.starts_with("0O") {
                    (8, &digits[2..])
                } else if digits.starts_with("0b") || digits.starts_with("0B") {
                    (2, &digits[2..])
                } else {
                    (10, digits)
                };
                if signed && radix != 10
                    || digits.is_empty()
                    || !digits
                        .bytes()
                        .all(|byte| byte.is_ascii() && char::from(byte).is_digit(radix))
                {
                    return Err(invalid());
                }
                (
                    negative,
                    BigUint::parse_bytes(digits.as_bytes(), radix).ok_or_else(invalid)?,
                )
            }
        }
    };
    // BigInt right shift is arithmetic for negatives. Number conversion happens
    // after the shift, before remainder, retaining IEEE-754 rounding/overflow.
    let shifted = if negative {
        (magnitude + BigUint::from((1_u32 << 22) - 1)) >> 22_usize
    } else {
        magnitude >> 22_usize
    };
    let number = shifted
        .to_str_radix(10)
        .parse::<f64>()
        .map_err(|_| invalid())?;
    Ok(if negative { -number } else { number })
}

fn parse_int(value: &Value) -> Result<f64, String> {
    let text = value
        .coerce_js_string()
        .map_err(str::to_owned)?
        .trim_matches(javascript::is_whitespace);
    let mut units = text.code_units();
    let negative = units.first() == Some(&u16::from(b'-'));
    if units.first().is_some_and(|unit| matches!(*unit, 43 | 45)) {
        units = &units[1..];
    }
    let hex = units.starts_with(&[48, 120]) || units.starts_with(&[48, 88]);
    if hex {
        units = &units[2..];
    }
    let radix = if hex { 16 } else { 10 };
    let digits: String = units
        .iter()
        .map_while(|unit| {
            let character = char::from_u32(u32::from(*unit))?;
            (character.is_ascii() && character.is_digit(radix)).then_some(character)
        })
        .collect();
    if digits.is_empty() {
        return Ok(f64::NAN);
    }
    let input = if hex { format!("0x{digits}") } else { digits };
    let number =
        javascript::string_to_number(&input).expect("collected integer digits form a number");
    Ok(if negative { -number } else { number })
}
