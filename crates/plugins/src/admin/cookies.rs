//! Cookies published by HTTP and logical impersonation calls.
use alibi_core::utils::cookie_utils::{
    create_clear_cookie, create_derived_session_cookie, create_session_cookie_with_max_age,
    create_session_like_cookie, related_cookie_name, sign_cookie_value, verify_cookie_value,
};
use alibi_core::{AuthConfig, AuthResult, Headers};
use std::collections::HashMap;

pub(super) fn impersonation_cookie_headers(
    config: &AuthConfig,
    headers: &HashMap<String, String>,
    admin_token: &str,
    token: &str,
) -> AuthResult<Headers> {
    let name = related_cookie_name(config, "dont_remember");
    let remembered = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value)
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (key, value) = cookie.trim().split_once('=')?;
                (key == name)
                    .then(|| verify_cookie_value(value, config.current_secret()))
                    .flatten()
            })
        })
        .unwrap_or_default();
    let admin = sign_cookie_value(
        &format!("{admin_token}:{remembered}"),
        config.current_secret(),
    );
    let mut result = Headers::new();
    for cookie in crate::helpers::delete_session_cookie_headers(config)? {
        result.append("set-cookie", cookie);
    }
    result.append(
        "set-cookie",
        create_derived_session_cookie(
            &related_cookie_name(config, "admin_session"),
            &admin,
            false,
            config,
        )?,
    );
    result.append(
        "set-cookie",
        create_session_cookie_with_max_age(Some(token), None, config)?,
    );
    result.append(
        "set-cookie",
        create_session_like_cookie(
            &name,
            &sign_cookie_value("true", config.current_secret()),
            None,
            config,
        )?,
    );
    Ok(result)
}

pub(super) fn restoration_cookie_headers(
    config: &AuthConfig,
    token: &str,
    dont_remember: bool,
) -> AuthResult<Headers> {
    let mut headers = Headers::new();
    headers.append(
        "set-cookie",
        create_session_cookie_with_max_age(
            Some(token),
            if dont_remember {
                None
            } else {
                Some(config.session.expires_in.num_seconds())
            },
            config,
        )?,
    );
    if dont_remember {
        headers.append(
            "set-cookie",
            create_session_like_cookie(
                &related_cookie_name(config, "dont_remember"),
                &sign_cookie_value("true", config.current_secret()),
                None,
                config,
            )?,
        );
    }
    headers.append(
        "set-cookie",
        create_clear_cookie(&related_cookie_name(config, "admin_session"), config)?,
    );
    Ok(headers)
}
