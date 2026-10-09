use super::LinkSocialOutcome;
use super::OAuthIdentity;
use super::OAuthProcessPolicy;
use super::OAuthSignInError;
use super::ambiguous_account_sign_in_response;
use super::authorization::link_social_core;
use super::authorization::social_sign_in_core;
use super::authorization::validate_authorization_params;
use super::cookies::attach_cookie_state_payload;
use super::cookies::attach_state_cookie;
use super::create_account_cookie_headers;
use super::fetch_user_info_from_provider;
use super::linking::complete_link_social_with_raw_email;
use super::linking::link_with_id_token_core;
use super::linking::sign_in_with_id_token_core;
use super::oauth_callback_path;
use super::oauth_disable_sign_up_option;
use super::parse_callback_user_payload;
use super::process_oauth_sign_in_with_output;
use super::raw_truthy;
use super::redirects::auth_base_url;
use super::redirects::build_default_error_url;
use super::redirects::build_redirect_url;
use super::redirects::callback_failure_location;
use super::redirects::callback_failure_redirect;
use super::redirects::redirect_response;
use super::require_session;
use super::resolve_oauth_account_key;
use super::validate_authorization_code_via_provider;
use crate::oauth::providers::OAuthConfig;
use crate::oauth::providers::OAuthUserInfoRequest;
use crate::oauth::state::OAuthStatePayload;
use crate::oauth::state::RecoveredOAuthServerContext;
use crate::oauth::state::decode_cookie_state_value;
use crate::oauth::state::decode_database_state_cookie_value;
use crate::oauth::state::get_cookie;
use crate::oauth::state::state_cookie_name;
use crate::oauth::state::state_verification_identifier;
use crate::oauth::state::verified_server_context;
use crate::oauth::types::LinkSocialRequest;
use crate::oauth::types::SocialSignInRequest;
use alibi_core::AuthContext;
use alibi_core::AuthError;
use alibi_core::AuthRequest;
use alibi_core::AuthResponse;
use alibi_core::AuthResult;
use alibi_core::AuthSession;
use std::collections::HashMap;

pub(crate) async fn handle_social_sign_in(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let body: SocialSignInRequest = match alibi_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    validate_authorization_params(body.additional_params.as_ref())?;
    let meta = alibi_core::RequestMeta::from_request(req);
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = match sign_in_with_id_token_core(&body, id_token, provider, &meta, ctx).await
        {
            Err(AuthError::Database(alibi_core::DatabaseError::AmbiguousAccount { .. })) => {
                return Ok(ambiguous_account_sign_in_response(ctx));
            }
            result => result?,
        };
        let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;
        if let Some(token) = response.token.as_deref() {
            auth_response = auth_response.with_appended_header(
                "Set-Cookie",
                alibi_core::utils::cookie_utils::create_session_cookie(token, &ctx.config)?,
            );
        }
        return Ok(auth_response);
    }

    let flow = match social_sign_in_core(&body, config, ctx).await {
        Err(error @ AuthError::Config(_)) => {
            tracing::error!(%error, "OAuth authorization configuration failed");
            return Ok(AuthResponse::new(500));
        }
        result => result?,
    };
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }
    if let Some(token) = response.token.as_deref() {
        auth_response = auth_response.with_appended_header(
            "Set-Cookie",
            alibi_core::utils::cookie_utils::create_session_cookie(token, &ctx.config)?,
        );
    }

    match ctx.config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Automatic | alibi_core::OAuthStateStrategy::Database => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_state_cookie(
                auth_response,
                &ctx.config,
                ctx.config.current_secret(),
                &flow.state,
            )
        }
        alibi_core::OAuthStateStrategy::Cookie => {
            if response.token.is_some() {
                return Ok(auth_response);
            }
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OAuth state consumption, provider errors, and cookie cleanup in their required order"
)]
pub(in crate::oauth) async fn handle_callback(
    config: &OAuthConfig,
    provider_name: &str,
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let default_error_url = build_default_error_url(ctx);
    let meta = alibi_core::RequestMeta::from_request(req);

    let mut merged = HashMap::new();
    if req.method() == &alibi_core::HttpMethod::Post {
        if let Some(body) = &req.body
            && !body.is_empty()
        {
            let body_text = String::from_utf8(body.clone()).map_err(|error| {
                AuthError::bad_request(format!("Invalid callback body: {error}"))
            })?;
            let parsed_body =
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body_text)
                    .ok()
                    .map(|body_2| {
                        body_2
                            .into_iter()
                            .filter_map(|(key, value)| match value {
                                serde_json::Value::String(value) => Some((key, value)),
                                serde_json::Value::Null => None,
                                other @ (serde_json::Value::Bool(_)
                                | serde_json::Value::Number(_)
                                | serde_json::Value::Array(_)
                                | serde_json::Value::Object(_)) => Some((key, other.to_string())),
                            })
                            .collect::<HashMap<String, String>>()
                    })
                    .or_else(|| {
                        Some(
                            url::form_urlencoded::parse(body_text.as_bytes())
                                .into_owned()
                                .collect::<HashMap<String, String>>(),
                        )
                    })
                    .ok_or_else(|| AuthError::bad_request("Invalid callback request"))?;
            merged.extend(parsed_body);
        }

        // Match the TS callback route: POST body seeds the redirect, but
        // explicit query parameters win over conflicting body fields.
        merged.extend(req.query.clone());

        let mut params = url::form_urlencoded::Serializer::new(String::new());
        let mut pairs: Vec<_> = merged.iter().collect();
        pairs.sort_by_key(|(left, _)| *left);
        for (key, value) in pairs {
            _ = params.append_pair(key, value);
        }
        return Ok(redirect_response(&format!(
            "{}/callback/{}?{}",
            auth_base_url(ctx),
            provider_name,
            params.finish()
        )));
    }

    let merged_2 = req.query.clone();

    let error = merged_2.get("error").cloned();
    let Some(state_param) = merged_2.get("state").cloned() else {
        if merged_2.get("code").is_some_and(|code| !code.is_empty())
            && config
                .providers
                .get(provider_name)
                .is_some_and(|provider| provider.allow_idp_initiated)
        {
            let mut authorization = req.clone();
            authorization.body = Some(serde_json::to_vec(&serde_json::json!({
                "provider": provider_name, "callbackURL": ctx.config.base_url
            }))?);
            let mut response = handle_social_sign_in(config, &authorization, ctx).await?;
            response.status = 302;
            response.body.clear();
            return Ok(response);
        }
        return Ok(callback_failure_redirect(ctx, "state_not_found"));
    };
    let payload = match ctx.config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Automatic | alibi_core::OAuthStateStrategy::Database => {
            let verification = match ctx
                .verifications()
                .find(&state_verification_identifier(&state_param))
                .await
            {
                Ok(Some(verification)) => verification,
                Ok(None) => {
                    return Ok(redirect_response(&callback_failure_location(
                        ctx,
                        "state_mismatch",
                    )));
                }
                Err(_) => {
                    return Ok(redirect_response(&callback_failure_location(
                        ctx,
                        "internal_server_error",
                    )));
                }
            };

            let payload: OAuthStatePayload = match verification.value().and_then(|value| {
                serde_json::from_str(value)
                    .map_err(|error| AuthError::internal(format!("Invalid state payload: {error}")))
            }) {
                Ok(payload) => payload,
                Err(_) => {
                    return Ok(redirect_response(&callback_failure_location(
                        ctx,
                        "internal_server_error",
                    )));
                }
            };
            let state_error_url = payload.error_url.as_deref().unwrap_or(&default_error_url);
            let state_mismatch = || {
                redirect_response(
                    &build_redirect_url(
                        &auth_base_url(ctx),
                        Some(state_error_url),
                        &[("error", "state_mismatch")],
                    )
                    .unwrap_or_else(|_| callback_failure_location(ctx, "state_mismatch")),
                )
            };
            if payload
                .additional_data
                .get("oauthState")
                .is_some_and(|value| value.as_str() != Some(state_param.as_str()))
            {
                return Ok(state_mismatch());
            }
            if !ctx.config.account.skip_state_cookie_check {
                let persisted_state =
                    get_cookie(req, &state_cookie_name(&ctx.config)).and_then(|value| {
                        decode_database_state_cookie_value(ctx.config.current_secret(), &value).ok()
                    });
                if persisted_state.as_deref() != Some(state_param.as_str()) {
                    return Ok(state_mismatch());
                }
            }
            if ctx
                .verifications()
                .delete(&state_verification_identifier(&state_param))
                .await
                .is_err()
            {
                return Ok(redirect_response(&callback_failure_location(
                    ctx,
                    "internal_server_error",
                ))
                .with_appended_header(
                    "Set-Cookie",
                    alibi_core::utils::cookie_utils::create_clear_cookie(
                        &state_cookie_name(&ctx.config),
                        &ctx.config,
                    )?,
                ));
            }
            payload
        }
        alibi_core::OAuthStateStrategy::Cookie => {
            let Some(cookie_value) = get_cookie(req, &state_cookie_name(&ctx.config)) else {
                return Ok(redirect_response(&callback_failure_location(
                    ctx,
                    "please_restart_the_process",
                )));
            };
            match decode_cookie_state_value(&ctx.config, &cookie_value) {
                Ok(payload)
                    if payload
                        .additional_data
                        .get("oauthState")
                        .and_then(serde_json::Value::as_str)
                        == Some(state_param.as_str()) =>
                {
                    payload
                }
                Ok(payload) => {
                    let error_url = payload
                        .error_url
                        .as_deref()
                        .filter(|url| !url.is_empty())
                        .unwrap_or(&default_error_url);
                    return Ok(redirect_response(
                        &build_redirect_url(
                            &auth_base_url(ctx),
                            Some(error_url),
                            &[("error", "state_mismatch")],
                        )
                        .unwrap_or_else(|_| callback_failure_location(ctx, "state_mismatch")),
                    ));
                }
                Err(_) => {
                    return Ok(redirect_response(&callback_failure_location(
                        ctx,
                        "please_restart_the_process",
                    )));
                }
            }
        }
    };

    let clear_state_cookie = alibi_core::utils::cookie_utils::create_clear_cookie(
        &state_cookie_name(&ctx.config),
        &ctx.config,
    )?;
    let error_url = payload
        .error_url
        .clone()
        .unwrap_or_else(|| default_error_url.clone());

    let redirect_on_error = |error_code: &str, description: Option<&str>| {
        let mut parameters = vec![("error", error_code)];
        if let Some(description) = description {
            parameters.push(("error_description", description));
        }
        redirect_response(
            &build_redirect_url(&auth_base_url(ctx), Some(&error_url), &parameters)
                .unwrap_or_else(|_error| callback_failure_location(ctx, error_code)),
        )
        .with_appended_header("Set-Cookie", clear_state_cookie.clone())
    };

    if payload.is_expired() {
        return Ok(redirect_on_error("state_mismatch", None));
    }
    if let Some(error) = error.as_deref() {
        return Ok(redirect_on_error(
            error,
            merged_2.get("error_description").map(String::as_str),
        ));
    }

    let authenticated_state_cookie = get_cookie(req, &state_cookie_name(&ctx.config));
    let context_secret = match ctx.config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Cookie => crate::token_crypto::decryption_key(
            authenticated_state_cookie
                .as_deref()
                .ok_or_else(|| AuthError::internal("Authenticated state cookie disappeared"))?,
            &ctx.config,
        )?,
        alibi_core::OAuthStateStrategy::Automatic | alibi_core::OAuthStateStrategy::Database => {
            ctx.config.current_secret()
        }
    };
    if let Some(context) = verified_server_context(&payload, &state_param, context_secret) {
        req.extensions()
            .insert(RecoveredOAuthServerContext(context));
    }

    let Some(code) = merged_2.get("code").cloned() else {
        return Ok(redirect_on_error("no_code", None));
    };
    let Some(provider) = config.providers.get(provider_name) else {
        return Ok(redirect_on_error("oauth_provider_not_found", None));
    };

    let Ok(tokens) = validate_authorization_code_via_provider(
        provider,
        &code,
        &format!(
            "{}{}",
            auth_base_url(ctx),
            oauth_callback_path(provider_name, provider)
        ),
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.authorization_code_pkce.unwrap_or(policy.pkce))
            .then_some(payload.code_verifier.as_str()),
        merged_2.get("device_id").map(String::as_str),
    )
    .await
    else {
        return Ok(redirect_on_error("invalid_code", None));
    };

    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.verify_grant_id_token)
        && let Some(token) = tokens.id_token.as_deref().filter(|token| !token.is_empty())
        && !crate::oauth::id_token::verify_provider_token(
            provider,
            token,
            payload.id_token_nonce.as_deref(),
        )
        .await
    {
        return Ok(redirect_on_error("unable_to_get_user_info", None));
    }

    let user_info_result = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            token_type: tokens.token_type.clone(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scopes: tokens.scopes.clone(),
            id_token: tokens.id_token.clone(),
            raw: tokens.raw.clone(),
            user: parse_callback_user_payload(merged_2.get("user").map(String::as_str)),
        },
    )
    .await;
    let mut user_info = match user_info_result {
        Ok(user_info) => user_info,
        Err(error) => {
            if matches!(&error,AuthError::Api {code:Some(code),..} if code == "OAUTH_PROFILE_EXCEPTION")
            {
                return Ok(AuthResponse::new(500));
            }
            if provider
                .authorization
                .as_ref()
                .is_some_and(|policy| policy.propagate_grant_profile_errors)
                && tokens
                    .raw
                    .as_ref()
                    .and_then(|raw| raw.get("id_token"))
                    .is_some_and(raw_truthy)
            {
                // The published factory throws outside callback redirect handling.
                // State was consumed, but its pending clear-cookie is not emitted.
                return Ok(AuthResponse::new(500));
            }
            return Ok(redirect_on_error("unable_to_get_user_info", None));
        }
    };

    if resolve_oauth_account_key(provider, &tokens, &mut user_info)
        .await
        .is_err()
    {
        return Ok(redirect_on_error("unable_to_get_user_info", None));
    }

    let raw_email = provider
        .authorization
        .as_ref()
        .filter(|policy| policy.preserve_raw_email_errors)
        .and(user_info.user_output.as_ref())
        .and_then(|output| output.get("email"));

    if let Some(link) = payload.link.as_ref() {
        let link_result = complete_link_social_with_raw_email(
            provider_name,
            &user_info.user,
            &user_info.data,
            &tokens,
            link,
            ctx,
            (raw_email, provider.authorization.as_ref()),
        )
        .await;
        if matches!(link_result, Ok(LinkSocialOutcome::InvalidRawEmail)) {
            return Ok(AuthResponse::new(500));
        }
        if let Err(error_3) = link_result {
            if error_3.is_ambiguous_account() {
                return Ok(AuthResponse::new(500));
            }
            let (code, description) = match &error_3 {
                OAuthSignInError::Generic(message) => (message.clone(), None),
                _ => error_3.redirect_parts(),
            };
            return Ok(redirect_on_error(&code, description));
        }

        return Ok(redirect_response(&payload.callback_url)
            .with_appended_header("Set-Cookie", clear_state_cookie));
    }

    if raw_email.is_some_and(|email| raw_truthy(email) && !email.is_string()) {
        // Source first resolves account ownership, then lowercases email either
        // in the caught email lookup (new identity) or uncaught validation (owned).
        let existing_account = ctx
            .database
            .get_account_record(provider_name, &user_info.user.id)
            .await;
        return Ok(match existing_account {
            Ok(Some(_)) => AuthResponse::new(500),
            Ok(None) | Err(_) => {
                redirect_response(&callback_failure_location(ctx, "internal_server_error"))
                    .with_appended_header("Set-Cookie", clear_state_cookie.clone())
            }
        });
    }

    let disable_sign_up = provider.disable_implicit_sign_up
        && !payload.request_sign_up.unwrap_or(false)
        || (oauth_disable_sign_up_option(provider).unwrap_or(false)
            && provider
                .authorization
                .as_ref()
                .is_none_or(|policy| policy.honor_factory_options));
    let outcome = match process_oauth_sign_in_with_output(
        OAuthIdentity {
            provider_name,
            user: &user_info.user,
            profile: &user_info.data,
        },
        &OAuthProcessPolicy::for_provider(provider, Some(payload.callback_url.clone())),
        &tokens,
        disable_sign_up,
        &meta,
        ctx,
        (
            provider
                .authorization
                .as_ref()
                .filter(|policy| policy.preserve_raw_profile_scalars)
                .and(user_info.user_output.as_ref()),
            provider.authorization.as_ref(),
        ),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error_4) => {
            if error_4.is_ambiguous_account() {
                return Ok(redirect_response(&callback_failure_location(
                    ctx,
                    "internal_server_error",
                ))
                .with_appended_header("Set-Cookie", clear_state_cookie.clone()));
            }
            let (code_2, description) = error_4.redirect_parts();
            return Ok(redirect_on_error(&code_2, description));
        }
    };

    let redirect_target = if outcome.is_register {
        payload
            .new_user_url
            .as_deref()
            .unwrap_or(&payload.callback_url)
            .to_owned()
    } else {
        payload.callback_url.clone()
    };
    let mut response = redirect_response(&redirect_target)
        .with_appended_header("Set-Cookie", clear_state_cookie)
        .with_appended_header(
            "Set-Cookie",
            alibi_core::utils::cookie_utils::create_session_cookie(
                outcome.session.token(),
                &ctx.config,
            )?,
        );
    if let Some(account_cookie) = outcome.account_cookie.as_ref() {
        for header in create_account_cookie_headers(&ctx.config, account_cookie, req)? {
            response.headers.append("Set-Cookie", header);
        }
    }
    Ok(response)
}

pub(in crate::oauth) async fn handle_link_social(
    config: &OAuthConfig,
    req: &AuthRequest,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<AuthResponse> {
    let session = require_session(req, ctx)
        .await
        .map_err(|error| match error {
            AuthError::Unauthenticated => AuthError::Api {
                status: 401,
                code: Some("UNAUTHORIZED".to_owned()),
                message: "Unauthorized".to_owned(),
            },
            error => error,
        })?;
    let body: LinkSocialRequest = match alibi_core::validate_request_body(req) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    validate_authorization_params(body.additional_params.as_ref())?;
    if let Some(id_token) = &body.id_token {
        let provider = config
            .providers
            .get(&body.provider)
            .ok_or_else(|| AuthError::not_found("Provider not found"))?;
        let response = match link_with_id_token_core(&body, id_token, provider, &session, ctx).await
        {
            Err(AuthError::Database(alibi_core::DatabaseError::AmbiguousAccount { .. })) => {
                return Ok(AuthResponse::new(500));
            }
            result => result?,
        };
        return AuthResponse::json(200, &response).map_err(AuthError::from);
    }

    let flow = match link_social_core(&body, &session, config, ctx).await {
        Err(error @ AuthError::Config(_)) => {
            tracing::error!(%error, "OAuth linking authorization configuration failed");
            return Ok(AuthResponse::new(500));
        }
        result => result?,
    };
    let response = flow.response;
    let mut auth_response = AuthResponse::json(200, &response).map_err(AuthError::from)?;

    if let Some(url) = response.url.as_deref()
        && response.redirect
    {
        auth_response = auth_response.with_header("Location", url);
    }

    match ctx.config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Automatic | alibi_core::OAuthStateStrategy::Database => {
            attach_state_cookie(
                auth_response,
                &ctx.config,
                ctx.config.current_secret(),
                &flow.state,
            )
        }
        alibi_core::OAuthStateStrategy::Cookie => {
            attach_cookie_state_payload(auth_response, &ctx.config, &flow.payload)
        }
    }
}
