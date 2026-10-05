use super::*;
pub(in crate::plugins::oauth::handlers) fn redirect_response(location: &str) -> AuthResponse {
    AuthResponse::new(302)
        .with_header("content-type", "application/json")
        .with_header("Location", location)
}

pub(in crate::plugins::oauth::handlers) fn validate_redirect_target(
    target: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error_message: &str,
) -> AuthResult<()> {
    if ctx.config.current_origin_check_disabled() {
        return Ok(());
    }
    if ctx.config.is_redirect_target_trusted(target) {
        Ok(())
    } else {
        Err(AuthError::forbidden(error_message.to_owned()))
    }
}

pub(in crate::plugins::oauth::handlers) fn build_redirect_url(
    base_url: &str,
    callback_url: Option<&str>,
    params: &[(&str, &str)],
) -> AuthResult<String> {
    let base = url::Url::parse(base_url)
        .map_err(|error| AuthError::internal(format!("Invalid base URL: {error}")))?;
    let mut url = if let Some(callback_url) = callback_url {
        base.join(callback_url)
            .map_err(|error| AuthError::bad_request(format!("Invalid callbackURL: {error}")))?
    } else {
        base.join("/error")
            .map_err(|error| AuthError::internal(format!("Invalid error URL: {error}")))?
    };
    if !params.is_empty() {
        let mut query_segments = Vec::new();
        if let Some(existing_query) = url.query()
            && !existing_query.is_empty()
        {
            query_segments.push(existing_query.to_owned());
        }
        for (key, value) in params {
            query_segments.push(format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value),
            ));
        }
        let query = query_segments.join("&");
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

pub(in crate::plugins::oauth::handlers) fn auth_base_url(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> String {
    format!(
        "{}{}",
        ctx.config.base_url.trim_end_matches('/'),
        ctx.config.base_path
    )
}

pub(in crate::plugins::oauth::handlers) fn build_default_error_url(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> String {
    ctx.config
        .api_error_url
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| format!("{}/error", auth_base_url(ctx)))
}

pub(in crate::plugins::oauth::handlers) fn callback_failure_location(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error: &str,
) -> String {
    build_redirect_url(
        &auth_base_url(ctx),
        Some(&build_default_error_url(ctx)),
        &[("error", error)],
    )
    .unwrap_or_else(|_| {
        format!(
            "{}/error?error={}",
            auth_base_url(ctx),
            urlencoding::encode(error)
        )
    })
}

pub(in crate::plugins::oauth::handlers) fn callback_failure_redirect(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    error: &str,
) -> AuthResponse {
    redirect_response(&callback_failure_location(ctx, error))
}

pub(in crate::plugins) fn ambiguous_account_sign_in_response(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResponse {
    callback_failure_redirect(ctx, "internal_server_error")
}
