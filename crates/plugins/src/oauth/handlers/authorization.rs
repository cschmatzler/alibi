const RESERVED_AUTHORIZATION_PARAMS: [&str; 8] = [
    "state",
    "client_id",
    "redirect_uri",
    "response_type",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "scope",
];

use super::*;
pub(in crate::oauth::handlers) fn generate_pkce() -> (String, String) {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    let mut random = rand::rng();
    let verifier: String = (0..128)
        .filter_map(|_| {
            ALPHABET
                .get(random.random_range(0..ALPHABET.len()))
                .copied()
                .map(char::from)
        })
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

pub(in crate::oauth::handlers) fn build_authorization_url(
    provider: &OAuthProvider,
    callback_url: &str,
    scopes: Option<&[String]>,
    state: &str,
    code_challenge: &str,
    login_hint: Option<&str>,
    additional_params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<String> {
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.require_client_secret)
        && (provider.client_id.is_empty() || provider.client_secret.is_empty())
    {
        return Err(AuthError::config(
            "Client ID and client secret are required",
        ));
    }
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.require_client_id)
        && provider.client_id.is_empty()
    {
        return Err(AuthError::config("Client ID is required"));
    }
    let mut effective_scopes: Vec<&str> = provider.authorization.as_ref().map_or_else(
        || {
            scopes.map_or_else(
                || provider.scopes.iter().map(String::as_str).collect(),
                |s| s.iter().map(String::as_str).collect(),
            )
        },
        |policy| {
            if policy.omit_scopes {
                return Vec::new();
            }
            let mut effective = Vec::new();
            if !policy.disable_default_scopes {
                effective.extend(provider.scopes.iter().map(String::as_str));
            }
            let configured = policy.configured_scopes.iter().map(String::as_str);
            let requested = scopes.unwrap_or_default().iter().map(String::as_str);
            match policy.scope_order {
                OAuthScopeOrder::ConfiguredThenRequested => {
                    effective.extend(configured);
                    effective.extend(requested);
                }
                OAuthScopeOrder::RequestedThenConfigured => {
                    effective.extend(requested);
                    effective.extend(configured);
                }
            }
            if policy.deduplicate_scopes {
                let mut seen = std::collections::HashSet::new();
                effective.retain(|scope| seen.insert(*scope));
            }
            effective
        },
    );
    if provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.discovery_openid_scope)
        && !effective_scopes.contains(&"openid")
    {
        effective_scopes.insert(0, "openid");
    }
    let scope_str = effective_scopes.join(
        provider
            .authorization
            .as_ref()
            .map_or(" ", |policy| policy.scope_separator.as_str()),
    );

    let mut url = url::Url::parse(&provider.auth_url)
        .map_err(|error| AuthError::internal(format!("Invalid auth URL: {error}")))?;
    set_authorization_param(
        &mut url,
        "response_type",
        provider
            .authorization
            .as_ref()
            .map_or("code", |policy| policy.response_type.as_str()),
    );
    set_authorization_param(
        &mut url,
        provider
            .authorization
            .as_ref()
            .map_or("client_id", |policy| policy.client_id_parameter.as_str()),
        provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.literal_client_id.as_deref())
            .unwrap_or(&provider.client_id),
    );
    set_authorization_param(&mut url, "state", state);
    if provider.authorization.is_none()
        || !effective_scopes.is_empty()
        || provider
            .authorization
            .as_ref()
            .is_some_and(|policy| policy.emit_empty_scope)
    {
        set_authorization_param(&mut url, "scope", &scope_str);
    }
    set_authorization_param(
        &mut url,
        "redirect_uri",
        provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.redirect_uri.as_deref())
            .filter(|uri| !uri.is_empty())
            .unwrap_or(callback_url),
    );
    if provider
        .authorization
        .as_ref()
        .is_none_or(|policy| policy.pkce)
    {
        set_authorization_param(&mut url, "code_challenge_method", "S256");
        set_authorization_param(&mut url, "code_challenge", code_challenge);
    }
    if let Some(policy) = &provider.authorization {
        if let Some(mode) = policy
            .response_mode
            .as_deref()
            .filter(|mode| !mode.is_empty())
        {
            set_authorization_param(&mut url, "response_mode", mode);
        }
        if let Some(prompt) = policy
            .prompt
            .as_deref()
            .filter(|prompt| !prompt.is_empty())
            .or(policy.default_prompt.as_deref())
        {
            set_authorization_param(&mut url, "prompt", prompt);
        }
        if effective_scopes.contains(&"bot")
            && let Some(permissions) = policy.discord_permissions
        {
            let value = if permissions.is_nan() {
                "NaN".into()
            } else if permissions == f64::INFINITY {
                "Infinity".into()
            } else if permissions == f64::NEG_INFINITY {
                "-Infinity".into()
            } else {
                let number = serde_json::Number::from_f64(permissions)
                    .ok_or_else(|| AuthError::internal("Invalid Discord permissions number"))?;
                alibi_core::utils::json::number_to_string(&number)?
            };
            set_authorization_param(&mut url, "permissions", &value);
        }
    }
    if let Some(login_hint) = login_hint.filter(|hint| {
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.login_hint && !hint.is_empty())
    }) {
        set_authorization_param(&mut url, "login_hint", login_hint);
    }
    for (key, value) in &provider.authorization_params {
        if RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str()) {
            continue;
        }
        set_authorization_param(&mut url, key, value);
    }
    if let Some(params) = additional_params {
        for (key, value) in params {
            if provider.authorization.as_ref().is_some_and(|policy| {
                policy.client_id_parameter != "client_id" && key == &policy.client_id_parameter
            }) {
                continue;
            }
            set_authorization_param(&mut url, key, value);
        }
    }
    if let Some(policy) = &provider.authorization {
        for (key, value) in &policy.fixed_authorization_params {
            set_authorization_param(&mut url, key, value);
        }
        if let Some(fragment) = &policy.authorization_fragment {
            url.set_fragment(Some(fragment));
        }
    }
    if provider.authorization.as_ref().is_some_and(|policy| {
        matches!(
            policy.scope_encoding,
            super::super::providers::OAuthScopeEncoding::UriComponent
        )
    }) && let Some(scope) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "scope").then(|| value.into_owned()))
        .filter(|value| !value.is_empty())
    {
        let existing: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "scope")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        _ = url.query_pairs_mut().clear().extend_pairs(existing);
        let encoded = [
            ("%21", "!"),
            ("%27", "'"),
            ("%28", "("),
            ("%29", ")"),
            ("%2A", "*"),
        ]
        .into_iter()
        .fold(
            urlencoding::encode(&scope).into_owned(),
            |value, (encoded, literal)| value.replace(encoded, literal),
        );
        let query = format!("{}&scope={encoded}", url.query().unwrap_or_default());
        url.set_query(Some(&query));
    }
    Ok(url.to_string())
}

// URLSearchParams.set replaces duplicate values at the first occurrence;
// unrelated application-owned endpoint parameters retain their order.
pub(in crate::oauth::handlers) fn set_authorization_param(
    url: &mut url::Url,
    key: &str,
    value: &str,
) {
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (name, previous) in url.query_pairs() {
        if name == key {
            if !replaced {
                pairs.push((key.to_owned(), value.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((name.into_owned(), previous.into_owned()));
        }
    }
    if !replaced {
        pairs.push((key.to_owned(), value.to_owned()));
    }
    _ = url.query_pairs_mut().clear().extend_pairs(pairs);
}

pub(in crate::oauth::handlers) fn validate_authorization_params(
    params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<()> {
    if params.is_some_and(|params| {
        params
            .keys()
            .any(|key| RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str()))
    }) {
        return Err(AuthError::Api {
            status: 400,
            code: Some("VALIDATION_ERROR".into()),
            message: format!(
                "[body.additionalParams] additionalParams cannot include reserved OAuth parameters: {}",
                RESERVED_AUTHORIZATION_PARAMS.join(", ")
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

pub(in crate::oauth::handlers) async fn social_sign_in_core(
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }
    if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
        validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
    }

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: body.new_user_callback_url.clone(),
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: body.login_hint.as_deref(),
            additional_params: body.additional_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: None,
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

pub(in crate::oauth::handlers) async fn link_social_core(
    body: &LinkSocialRequest,
    session: &impl AuthSession,
    config: &OAuthConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .providers
        .get(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .unwrap_or_else(|| ctx.config.base_url.clone());
    validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
    if let Some(error_callback_url) = body.error_callback_url.as_deref() {
        validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
    }

    let user = ctx
        .session_user(session)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let email = user
        .email()
        .ok_or_else(|| AuthError::bad_request("User email not found"))?;

    initiate_oauth_flow_core(
        ctx,
        FlowStartRequest {
            provider_name: &body.provider,
            provider,
            callback_url: &callback_url,
            new_user_callback_url: None,
            error_callback_url: body.error_callback_url.clone(),
            scopes: body.scopes.as_deref(),
            login_hint: None,
            additional_params: body.additional_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: Some(OAuthStateLink {
                email: email.to_lowercase(),
                user_id: session.user_id().to_string(),
            }),
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

/// Shared logic for social sign-in and link-social flows.
///
/// Both flows build a verification payload, store it, construct the
/// authorization URL, and return a redirect response. The only difference
/// is `link_user_id` (None for sign-in, Some for linking).
pub(in crate::oauth::handlers) async fn initiate_oauth_flow_core(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    request: FlowStartRequest<'_>,
) -> AuthResult<InitiatedOAuthFlow> {
    let (code_verifier, code_challenge) = generate_pkce();
    let state: String = {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
        let mut random = rand::rng();
        (0..32)
            .filter_map(|_| {
                alphabet
                    .get(random.random_range(0..alphabet.len()))
                    .copied()
                    .map(char::from)
            })
            .collect()
    };

    let proxy = alibi_core::hooks::current_request_hook_context().and_then(|req| {
        req.extensions
            .get::<crate::oauth_proxy::OAuthProxyFlow>()
    });
    let mut payload = OAuthStatePayload::new(
        proxy
            .as_ref()
            .map_or(request.callback_url, |flow| flow.callback_url.as_str())
            .to_owned(),
        code_verifier,
        request.error_callback_url,
        request.new_user_callback_url,
        request.link,
        request.request_sign_up,
        request.additional_data,
    );
    if request
        .provider
        .authorization
        .as_ref()
        .is_some_and(|policy| policy.id_token_nonce_binding)
    {
        payload.id_token_nonce = Some(alibi_core::utils::id::generate_id(32));
    }
    capture_server_context(&mut payload, &state, ctx.config.current_secret())?;
    drop(payload.additional_data.insert(
        "oauthState".to_owned(),
        serde_json::Value::String(state.clone()),
    ));
    if proxy.is_some()
        && let Some(req) = alibi_core::hooks::current_request_hook_context()
    {
        req.extensions
            .insert(crate::oauth_proxy::IssuedProxyState {
                state: state.clone(),
                payload: payload.clone(),
            });
    }

    match ctx.config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Automatic | alibi_core::OAuthStateStrategy::Database => {
            let created = ctx
                .verifications()
                .create(CreateVerification {
                    identifier: state_verification_identifier(&state),
                    value: serde_json::to_string(&payload)?,
                    expires_at: Utc::now() + Duration::minutes(10),
                })
                .await?;
            if created.is_none() {
                return Err(AuthError::internal("Unable to create verification"));
            }
        }
        alibi_core::OAuthStateStrategy::Cookie => {}
    }

    let mut url = build_authorization_url(
        request.provider,
        &format!(
            "{}{}",
            proxy.as_ref().map_or_else(
                || auth_base_url(ctx),
                |flow| flow.effective_auth_base_url.clone()
            ),
            oauth_callback_path(request.provider_name, request.provider)
        ),
        request.scopes,
        &state,
        &code_challenge,
        request.login_hint,
        request.additional_params,
    )?;
    if let Some(nonce) = &payload.id_token_nonce {
        let mut parsed = url::Url::parse(&url)
            .map_err(|_| AuthError::config("Invalid authorization endpoint"))?;
        set_authorization_param(&mut parsed, "nonce", nonce);
        url = parsed.to_string();
    }

    Ok(InitiatedOAuthFlow {
        response: SocialSignInResponse {
            url: Some(url),
            redirect: !request.disable_redirect,
            status: None,
            token: None,
            user: None,
        },
        state,
        payload,
    })
}
