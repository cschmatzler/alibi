use crate::utils::cookie_utils::{related_cookie_name, verify_cookie_value};
use crate::{AuthError, AuthResult};
use indexmap::IndexMap;
// Better Call reads the first base cookie. Better Auth's session-store reader
// uses the last valid duplicate for chunks, with its stricter octet grammar.
pub(in crate::session::cookie_cache::runtime) fn cookies<H: std::hash::BuildHasher + Sync>(
    headers: &std::collections::HashMap<String, String, H>,
) -> IndexMap<String, String> {
    cookie_values(headers, false)
}

pub(in crate::session::cookie_cache::runtime) fn cookie_values<H: std::hash::BuildHasher + Sync>(
    headers: &std::collections::HashMap<String, String, H>,
    chunks: bool,
) -> IndexMap<String, String> {
    let mut values = IndexMap::new();
    if let Some(header) = headers.get("cookie") {
        for pair in header.split(';') {
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let (name, mut value) = if chunks {
                (
                    name.trim_matches([' ', '\t']),
                    value.trim_matches([' ', '\t']),
                )
            } else {
                (
                    crate::utils::javascript::trim(name),
                    crate::utils::javascript::trim(value),
                )
            };
            if value.starts_with('"') && (!chunks || (value.len() >= 2 && value.ends_with('"'))) {
                value = if value.len() == 1 {
                    ""
                } else {
                    value.get(1..value.len() - 1).unwrap_or(value)
                };
            }
            if chunks && (name.is_empty() || !name.bytes().all(|byte|
                matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'^' | b'_' | b'`' | b'a'..=b'z' | b'|' | b'~'))
                || !value.bytes().all(|byte| matches!(byte, 0x20..=0x21 | 0x23..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))) {
                continue;
            }
            let decoded = percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .map_or_else(|_| value.to_owned(), std::borrow::Cow::into_owned);
            if chunks {
                _ = values.insert(name.to_owned(), decoded);
            } else {
                _ = values.entry(name.to_owned()).or_insert(decoded);
            }
        }
    }
    values
}

pub(in crate::session::cookie_cache) fn chunk_index(name: &str, base: &str) -> Option<u64> {
    let suffix = name.strip_prefix(base)?.strip_prefix('.')?;
    let index: u64 = suffix.parse().ok()?;
    (index <= 9_007_199_254_740_991 && index.to_string() == suffix).then_some(index)
}

pub(in crate::session::cookie_cache::runtime) fn cache_value(
    values: &IndexMap<String, String>,
    chunks: &IndexMap<String, String>,
    name: &str,
) -> Option<String> {
    if let Some(value) = values.get(name).filter(|value| !value.is_empty()) {
        return Some(value.clone());
    }
    let mut chunks: Vec<_> = chunks
        .iter()
        .filter_map(|(key, value)| Some((chunk_index(key, name)?, value)))
        .collect();
    chunks.sort_by_key(|(index, _)| *index);
    (!chunks.is_empty()).then(|| {
        chunks
            .into_iter()
            .map(|(_, value)| value.as_str())
            .collect()
    })
}

pub(in crate::session::cookie_cache::runtime) fn existing_names(
    values: &IndexMap<String, String>,
    name: &str,
) -> Vec<String> {
    values
        .keys()
        .filter(|key| key.as_str() == name || chunk_index(key, name).is_some())
        .cloned()
        .collect()
}

pub(in crate::session::cookie_cache) fn browser_preference(
    headers: &std::collections::HashMap<String, String>,
    config: &crate::AuthConfig,
) -> bool {
    cookies(headers)
        .get(&related_cookie_name(config, "dont_remember"))
        .and_then(|value| verify_cookie_value(value, config.current_secret()))
        .is_some_and(|value| !value.is_empty())
}

/// Read a base cookie or numerically ordered canonical chunks.
#[must_use]
pub fn chunked_cookie_value(
    headers: &std::collections::HashMap<String, String>,
    name: &str,
) -> Option<String> {
    cache_value(&cookies(headers), &cookie_values(headers, true), name)
}

/// Emit bounded chunks, replacing incoming names and expiring stale chunks.
/// Account chunks resolve attributes against their base cookie.
///
/// # Errors
/// Propagates invalid attributes or encoding.
pub fn chunked_cookie_headers<H: std::hash::BuildHasher + Sync>(
    name: &str,
    value: &str,
    max_age: Option<f64>,
    config: &crate::AuthConfig,
    headers: &std::collections::HashMap<String, String, H>,
    account: bool,
) -> AuthResult<Vec<String>> {
    let render = |part: &str, value: &str, age: Option<f64>| {
        if account {
            crate::utils::cookie_utils::create_account_cookie_header(
                part,
                name,
                value,
                age.unwrap_or(300.0),
                config,
            )
        } else {
            super::super::cookie_header(part, value, age, config)
        }
    };
    let empty_header = render(&format!("{name}.99"), "", max_age)?;
    let capacity = 4050_usize.saturating_sub(empty_header.len());
    let count = if capacity == 0 {
        usize::MAX
    } else {
        value.len().div_ceil(capacity)
    };
    let mut output = IndexMap::new();
    for old in existing_names(&cookie_values(headers, true), name) {
        _ = output.insert(old.clone(), render(&old, "", Some(0.0))?);
    }
    if count <= 1 {
        _ = output.insert(name.to_owned(), render(name, value, max_age)?);
    } else if count <= 100 {
        // Encoded compact values are ASCII, so byte chunking matches JS strings.
        for (index, chunk) in value.as_bytes().chunks(capacity).enumerate() {
            let chunk = std::str::from_utf8(chunk)
                .map_err(|_error| AuthError::internal("Invalid compact cache encoding"))?;
            let part = format!("{name}.{index}");
            _ = output.insert(part.clone(), render(&part, chunk, max_age)?);
        }
    }
    Ok(output.into_values().collect())
}

/// Clear session cookies and the actual incoming compact-cache chunks.
/// Pending two-factor stages can preserve the signed browser preference.
///
/// # Errors
/// Propagates invalid configured cookie attributes.
pub fn session_cleanup_headers(
    config: &crate::AuthConfig,
    headers: &std::collections::HashMap<String, String>,
    skip_remember: bool,
) -> AuthResult<Vec<String>> {
    let cache_name = related_cookie_name(config, "session_data");
    let mut names = vec![config.session.cookie_name.clone(), cache_name.clone()];
    if config.account.store_account_cookie {
        let account_name = related_cookie_name(config, "account_data");
        names.push(account_name.clone());
        names.extend(existing_names(&cookie_values(headers, true), &account_name));
    }
    if matches!(
        config.account.store_state_strategy,
        crate::config::OAuthStateStrategy::Cookie
    ) {
        names.push(related_cookie_name(config, "oauth_state"));
    }
    names.extend(existing_names(&cookie_values(headers, true), &cache_name));
    if !skip_remember {
        names.push(related_cookie_name(config, "dont_remember"));
    }
    names
        .into_iter()
        .map(|name| super::super::cookie_header(&name, "", Some(0.0), config))
        .collect()
}
