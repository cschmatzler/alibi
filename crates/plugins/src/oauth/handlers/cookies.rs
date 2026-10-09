use super::{
    AccountCookiePayload, AuthRequest, AuthResponse, AuthResult, Duration, OAuthStatePayload,
    account_cookie_name, create_account_cookie_value, create_cookie_state_value,
    create_database_state_cookie_value, decode_account_cookie_value, state_cookie_name,
};
pub(in crate::oauth::handlers) fn account_cookie_max_age(config: &alibi_core::AuthConfig) -> f64 {
    if let Some(age) = config.account.cookie_max_age {
        return age;
    }
    config
        .advanced
        .cookies
        .get("account_data")
        .and_then(|cookie| cookie.attributes.max_age)
        .unwrap_or_else(|| {
            alibi_core::session::cookie_cache::effective_max_age(
                config
                    .session
                    .cookie_cache
                    .as_ref()
                    .map_or(300.0, |cache| cache.max_age),
            )
        })
}

/// Emit the encrypted account snapshot and clear stale incoming chunks.
///
/// # Errors
/// Propagates encryption or cookie attribute errors.
pub(crate) fn create_account_cookie_headers(
    config: &alibi_core::AuthConfig,
    payload: &AccountCookiePayload,
    req: &AuthRequest,
) -> AuthResult<Vec<String>> {
    let max_age = account_cookie_max_age(config);
    let value = create_account_cookie_value(config, payload, max_age)?;
    alibi_core::session::cookie_cache::runtime::chunked_cookie_headers(
        &account_cookie_name(config),
        &value,
        Some(max_age),
        config,
        &req.headers,
        true,
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::oauth) fn decode_account_cookie(
    req: &AuthRequest,
    config: &alibi_core::AuthConfig,
) -> AuthResult<Option<AccountCookiePayload>> {
    let Some(value) = alibi_core::session::cookie_cache::runtime::chunked_cookie_value(
        &req.headers,
        &account_cookie_name(config),
    ) else {
        return Ok(None);
    };
    decode_account_cookie_value(config, &value).map(Some)
}

pub(in crate::oauth::handlers) fn attach_state_cookie(
    response: AuthResponse,
    config: &alibi_core::AuthConfig,
    secret: &str,
    state: &str,
) -> AuthResult<AuthResponse> {
    let value = create_database_state_cookie_value(secret, state);
    Ok(response.with_appended_header(
        "Set-Cookie",
        alibi_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(5).num_seconds(),
            config,
        )?,
    ))
}

pub(in crate::oauth::handlers) fn attach_cookie_state_payload(
    response: AuthResponse,
    config: &alibi_core::AuthConfig,
    payload: &OAuthStatePayload,
) -> AuthResult<AuthResponse> {
    let value = create_cookie_state_value(config, payload)?;
    Ok(response.with_appended_header(
        "Set-Cookie",
        alibi_core::utils::cookie_utils::create_cookie(
            &state_cookie_name(config),
            &value,
            Duration::minutes(10).num_seconds(),
            config,
        )?,
    ))
}
