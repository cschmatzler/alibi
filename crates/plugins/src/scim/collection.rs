//! Bounded classic pagination and the pinned SCIM equality-conjunction grammar.
use alibi_core::utils::json::JsValue;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
pub(super) struct CollectionQuery {
    pub start_index: i64,
    pub count: i64,
    pub filters: Vec<(String, String)>,
}
pub(super) struct QueryError {
    pub detail: String,
    pub kind: &'static str,
}
fn error(detail: impl Into<String>, kind: &'static str) -> QueryError {
    QueryError {
        detail: detail.into(),
        kind,
    }
}
fn integer(value: Option<&JsValue>, name: &str, default: i64) -> Result<i64, QueryError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed = match value {
        JsValue::Number(number) => Some(*number),
        JsValue::String(value) => {
            let value = alibi_core::utils::javascript::trim(value);
            let digits = value.strip_prefix('-').unwrap_or(value);
            if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                value.parse::<f64>().ok()
            } else {
                None
            }
        }
        _ => None,
    };
    let number = parsed
        .filter(|value| {
            value.is_finite() && value.fract() == 0.0 && value.abs() <= 9_007_199_254_740_991.0
        })
        .ok_or_else(|| error(format!("{name} must be an integer"), "invalidValue"))?;
    format!("{number:.0}")
        .parse()
        .map_err(|_| error(format!("{name} must be an integer"), "invalidValue"))
}
struct Word {
    start: usize,
    end: usize,
    value: String,
}
fn words(filter: &str) -> Result<Vec<Word>, QueryError> {
    let bytes = filter.as_bytes();
    let mut position = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut brackets = 0;
    let mut words = Vec::new();
    while let Some(&byte) = bytes.get(position) {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            position += 1;
            continue;
        }
        if byte == b'"' {
            quoted = true;
            position += 1;
            continue;
        }
        if byte == b'[' {
            brackets += 1;
            position += 1;
            continue;
        }
        if byte == b']' {
            if brackets == 0 {
                return Err(error(
                    "filter contains malformed quotes or brackets",
                    "invalidFilter",
                ));
            }
            brackets -= 1;
            position += 1;
            continue;
        }
        if brackets == 0 && byte.is_ascii_alphabetic() {
            let start = position;
            while bytes.get(position).is_some_and(u8::is_ascii_alphabetic) {
                position += 1;
            }
            words.push(Word {
                start,
                end: position,
                value: filter.get(start..position).unwrap_or("").into(),
            });
        } else {
            position += 1;
        }
    }
    if quoted || brackets != 0 {
        return Err(error(
            "filter contains malformed quotes or brackets",
            "invalidFilter",
        ));
    }
    Ok(words)
}
fn surrounded(filter: &str, word: &Word) -> bool {
    filter
        .get(..word.start)
        .and_then(|prefix| prefix.chars().last())
        .is_some_and(alibi_core::utils::javascript::is_whitespace)
        && filter
            .get(word.end..)
            .and_then(|suffix| suffix.chars().next())
            .is_some_and(alibi_core::utils::javascript::is_whitespace)
}
fn conjunction(filter: &str) -> Result<Vec<&str>, QueryError> {
    let mut output = Vec::new();
    let mut start = 0;
    for word in words(filter)? {
        if word.value.eq_ignore_ascii_case("and") && surrounded(filter, &word) {
            let expression =
                alibi_core::utils::javascript::trim(filter.get(start..word.start).unwrap_or(""));
            if expression.is_empty() {
                return Err(error(
                    "filter contains an invalid conjunction",
                    "invalidFilter",
                ));
            }
            output.push(expression);
            start = word.end;
        }
    }
    let final_expression = alibi_core::utils::javascript::trim(filter.get(start..).unwrap_or(""));
    if final_expression.is_empty() {
        return Err(error(
            "filter contains an invalid conjunction",
            "invalidFilter",
        ));
    }
    if output.len() >= 10 {
        return Err(error(
            "filter supports at most 10 equality expressions",
            "invalidFilter",
        ));
    }
    output.push(final_expression);
    Ok(output)
}
fn equality(
    expression: &str,
    connection: &str,
    kind: &str,
) -> Result<(String, String), QueryError> {
    let mut operation = None;
    for word in words(expression)? {
        if !surrounded(expression, &word) {
            continue;
        }
        let attribute =
            alibi_core::utils::javascript::trim(expression.get(..word.start).unwrap_or(""));
        let value = alibi_core::utils::javascript::trim(expression.get(word.end..).unwrap_or(""));
        if !attribute.is_empty() && !value.is_empty() {
            operation = Some((attribute, word.value, value));
            break;
        }
    }
    let Some((attribute, operator, value)) = operation else {
        return Err(error(
            "filter must use the form attribute eq \"value\"",
            "invalidFilter",
        ));
    };
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(error(
            format!("filter operator {operator} is not supported"),
            "invalidFilter",
        ));
    }
    let lower = attribute.to_lowercase();
    let normalized = lower
        .strip_prefix(&format!(
            "urn:ietf:params:scim:schemas:core:2.0:{}:",
            kind.to_lowercase()
        ))
        .unwrap_or(&lower);
    // JavaScript \s includes BOM and excludes NEL; Rust's Unicode class differs.
    let whitespace_normalized: String = normalized
        .chars()
        .map(|character| {
            if alibi_core::utils::javascript::is_whitespace(character) {
                ' '
            } else {
                character
            }
        })
        .collect();
    let work_email = kind == "User"
        && regex::Regex::new(r#"(?i)^emails\[ *type +eq +"work" *\]\.value$"#)
            .map_err(|error_value| error(error_value.to_string(), "invalidFilter"))?
            .is_match(&whitespace_normalized);
    let field = match normalized {
        _ if work_email => "workEmailValueIndex",
        "id" => "id",
        "displayname" if kind == "Group" => "displayNameKey",
        "username" if kind == "User" => "userNameKey",
        "emails.value" if kind == "User" => "emailValueIndex",
        "externalid" => "externalIdKey",
        _ => {
            return Err(error(
                format!("filter attribute {attribute} is not supported for {kind}"),
                "invalidFilter",
            ));
        }
    };
    let parsed: serde_json::Value = serde_json::from_str(value).map_err(|_| {
        error(
            "filter equality value must be a valid quoted JSON string",
            "invalidFilter",
        )
    })?;
    let value = parsed.as_str().ok_or_else(|| {
        error(
            "filter equality value must be a quoted string",
            "invalidFilter",
        )
    })?;
    let prepared = match field {
        "emailValueIndex" | "workEmailValueIndex" => format!(
            "|{}|",
            URL_SAFE_NO_PAD.encode(Sha256::digest(
                serde_json::to_vec(&[
                    "scim-email-value",
                    &alibi_core::utils::javascript::trim(value).to_lowercase()
                ])
                .map_err(|error_value| error(error_value.to_string(), "invalidFilter"))?
            ))
        ),
        "userNameKey" => URL_SAFE_NO_PAD.encode(Sha256::digest(
            serde_json::to_vec(&["scim-user-name", connection, &value.to_lowercase()])
                .map_err(|error_value| error(error_value.to_string(), "invalidFilter"))?,
        )),
        "externalIdKey" if kind == "User" && !value.is_empty() => {
            URL_SAFE_NO_PAD.encode(Sha256::digest(
                serde_json::to_vec(&["scim-user-external-id", connection, value])
                    .map_err(|error_value| error(error_value.to_string(), "invalidFilter"))?,
            ))
        }
        "displayNameKey" => URL_SAFE_NO_PAD.encode(Sha256::digest(
            serde_json::to_vec(&["scim-group-display-name", connection, &value.to_lowercase()])
                .map_err(|_| {
                    error(
                        "filter equality value must be a quoted string",
                        "invalidFilter",
                    )
                })?,
        )),
        "externalIdKey" if !value.is_empty() => URL_SAFE_NO_PAD.encode(Sha256::digest(
            serde_json::to_vec(&["scim-group-external-id", connection, value]).map_err(|_| {
                error(
                    "filter equality value must be a quoted string",
                    "invalidFilter",
                )
            })?,
        )),
        "externalIdKey" => String::new(),
        _ => value.into(),
    };
    Ok((field.into(), prepared))
}
pub(super) fn parse_group(
    query: Option<&JsValue>,
    connection: &str,
) -> Result<CollectionQuery, QueryError> {
    parse(query, connection, "Group")
}
pub(super) fn parse_user(
    query: Option<&JsValue>,
    connection: &str,
) -> Result<CollectionQuery, QueryError> {
    parse(query, connection, "User")
}
fn parse(
    query: Option<&JsValue>,
    connection: &str,
    kind: &str,
) -> Result<CollectionQuery, QueryError> {
    let start_index = integer(
        query.and_then(|query| query.get("startIndex")),
        "startIndex",
        1,
    )?
    .max(1);
    let count = integer(query.and_then(|query| query.get("count")), "count", 100)?.clamp(0, 100);
    let mut filters = Vec::new();
    if let Some(filter) = query
        .and_then(|query| query.get("filter"))
        .and_then(JsValue::as_str)
        .filter(|filter| !alibi_core::utils::javascript::trim(filter).is_empty())
    {
        for expression in conjunction(filter)? {
            filters.push(equality(expression, connection, kind)?);
        }
    }
    Ok(CollectionQuery {
        start_index,
        count,
        filters,
    })
}
