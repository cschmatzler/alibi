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

use super::FlowStartRequest;
use super::InitiatedOAuthFlow;
use super::oauth_callback_path;
use super::redirects::auth_base_url;
use crate::helpers::validate_redirect_target;
use crate::oauth::providers::OAuthConfig;
use crate::oauth::providers::OAuthProvider;
use crate::oauth::providers::OAuthScopeOrder;
use crate::oauth::state::OAuthStateLink;
use crate::oauth::state::OAuthStatePayload;
use crate::oauth::state::capture_server_context;
use crate::oauth::state::filter_additional_state_data;
use crate::oauth::state::state_verification_identifier;
use crate::oauth::types::LinkSocialRequest;
use crate::oauth::types::SocialSignInRequest;
use crate::oauth::types::SocialSignInResponse;
use alibi_core::AuthContext;
use alibi_core::AuthError;
use alibi_core::AuthResult;
use alibi_core::AuthUser;
use alibi_core::CreateVerification;
use alibi_core::entity::AuthSession;
use alibi_core::error::codes;
use base64::Engine;
use chrono::Duration;
use chrono::Utc;
use rand::RngExt;
use sha2::Digest;
use sha2::Sha256;
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

#[expect(
    clippy::too_many_arguments,
    reason = "Mirror the published createAuthorizationURL inputs"
)]
pub(in crate::oauth::handlers) fn build_authorization_url(
    provider: &OAuthProvider,
    callback_url: &str,
    scopes: Option<&[String]>,
    state: &str,
    code_challenge: &str,
    login_hint: Option<&str>,
    additional_params: Option<&std::collections::BTreeMap<String, String>>,
    nonce: Option<&str>,
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
    if code_challenge.is_empty()
        && let Some(name) = provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.code_verifier_required_for)
    {
        return Err(AuthError::config(format!(
            "codeVerifier is required for {name}"
        )));
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
    // Parameters Alibi sets are collected separately, so the endpoint's own
    // query text is kept as published instead of being re-encoded.
    let mut params = Vec::new();
    set_authorization_param(
        &mut params,
        "response_type",
        provider
            .authorization
            .as_ref()
            .map_or("code", |policy| policy.response_type.as_str()),
    );
    set_authorization_param(
        &mut params,
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
    set_authorization_param(&mut params, "state", state);
    if provider.authorization.is_none()
        || !effective_scopes.is_empty()
        || provider
            .authorization
            .as_ref()
            .is_some_and(|policy| policy.emit_empty_scope)
    {
        set_authorization_param(&mut params, "scope", &scope_str);
    }
    set_authorization_param(
        &mut params,
        "redirect_uri",
        provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.redirect_uri.as_deref())
            .filter(|uri| !uri.is_empty())
            .unwrap_or(callback_url),
    );
    if !code_challenge.is_empty()
        && provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.pkce)
    {
        set_authorization_param(&mut params, "code_challenge_method", "S256");
        set_authorization_param(&mut params, "code_challenge", code_challenge);
    }
    if let Some(policy) = &provider.authorization {
        if let Some(mode) = policy
            .response_mode
            .as_deref()
            .filter(|mode| !mode.is_empty())
        {
            set_authorization_param(&mut params, "response_mode", mode);
        }
        if let Some(prompt) = policy
            .prompt
            .as_deref()
            .filter(|prompt| !prompt.is_empty())
            .or(policy.default_prompt.as_deref())
        {
            set_authorization_param(&mut params, "prompt", prompt);
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
            set_authorization_param(&mut params, "permissions", &value);
        }
    }
    if let Some(login_hint) = login_hint.filter(|hint| {
        provider
            .authorization
            .as_ref()
            .is_none_or(|policy| policy.login_hint && !hint.is_empty())
    }) {
        set_authorization_param(&mut params, "login_hint", login_hint);
    }
    for (key, value) in &provider.authorization_params {
        if RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str()) {
            continue;
        }
        set_authorization_param(&mut params, key, value);
    }
    if let Some(additional) = additional_params {
        for (key, value) in additional {
            if provider.authorization.as_ref().is_some_and(|policy| {
                policy.client_id_parameter != "client_id" && key == &policy.client_id_parameter
            }) {
                continue;
            }
            set_authorization_param(&mut params, key, value);
        }
    }
    if let Some(policy) = &provider.authorization {
        for (key, value) in &policy.fixed_authorization_params {
            set_authorization_param(&mut params, key, value);
        }
    }
    if let Some(nonce) = nonce {
        set_authorization_param(&mut params, "nonce", nonce);
    }
    let encode_scope = provider.authorization.as_ref().is_some_and(|policy| {
        matches!(
            policy.scope_encoding,
            crate::oauth::providers::OAuthScopeEncoding::UriComponent
        )
    });
    with_query_params(&mut url, &params, encode_scope);
    if let Some(fragment) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.authorization_fragment.as_deref())
    {
        url.set_fragment(Some(fragment));
    }
    Ok(url.to_string())
}

// URLSearchParams.set replaces duplicate values at the first occurrence.
fn set_authorization_param(params: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some((_, previous)) = params.iter_mut().find(|(name, _)| name == key) {
        value.clone_into(previous);
    } else {
        params.push((key.to_owned(), value.to_owned()));
    }
}

/// Adds `params` to the endpoint's query and removes the pairs they replace.
/// The rest of the query keeps its original text, including empty segments,
/// because re-serializing it would change its encoding, such as `%20` to `+`,
/// and break providers that sign the query.
fn with_query_params(url: &mut url::Url, params: &[(String, String)], encode_scope: bool) {
    let mut segments: Vec<String> = url
        .query()
        .filter(|query| !query.is_empty())
        .map(|query| {
            query
                .split('&')
                .filter(|pair| {
                    pair.is_empty()
                        || !url::form_urlencoded::parse(pair.as_bytes())
                            .next()
                            .is_some_and(|(name, _)| params.iter().any(|(key, _)| *key == name))
                })
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let uri_scope = |key: &str, value: &str| encode_scope && key == "scope" && !value.is_empty();
    let added = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter().filter(|(key, value)| !uri_scope(key, value)))
        .finish();
    if !added.is_empty() {
        segments.push(added);
    }
    if let Some((_, scope)) = params.iter().find(|(key, value)| uri_scope(key, value)) {
        let encoded = alibi_core::utils::javascript::encode_uri_component(scope);
        segments.push(format!("scope={encoded}"));
    }
    let search = segments.join("&");
    url.set_query((!search.is_empty()).then_some(search.as_str()));
}

pub(in crate::oauth) fn validate_authorization_params(
    params: Option<&std::collections::BTreeMap<String, String>>,
) -> AuthResult<()> {
    if params.is_some_and(|params| {
        params
            .keys()
            .any(|key| RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str()))
    }) {
        return Err(AuthError::Api {
            status: 400,
            code: Some(codes::VALIDATION_ERROR.into()),
            message: format!(
                "[body.additionalParams] additionalParams cannot include reserved OAuth parameters: {}",
                RESERVED_AUTHORIZATION_PARAMS.join(", ")
            ),
        });
    }
    Ok(())
}

pub(in crate::oauth) async fn social_sign_in_core(
    body: &SocialSignInRequest,
    config: &OAuthConfig,
    request: Option<&alibi_core::AuthRequest>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .provider(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| ctx.config.base_url.clone());
    if request.is_some() {
        validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
        if let Some(error_callback_url) = body.error_callback_url.as_deref() {
            validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
        }
        if let Some(new_user_callback_url) = body.new_user_callback_url.as_deref() {
            validate_redirect_target(new_user_callback_url, ctx, "Invalid newUserCallbackURL")?;
        }
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
            authorization_params: body.authorization_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: None,
            disable_redirect: body.disable_redirect.unwrap_or(false),
        },
    )
    .await
}

pub(in crate::oauth) async fn link_social_core(
    body: &LinkSocialRequest,
    session: &impl AuthSession,
    config: &OAuthConfig,
    request: Option<&alibi_core::AuthRequest>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<InitiatedOAuthFlow> {
    let provider = config
        .provider(&body.provider)
        .ok_or_else(|| AuthError::not_found("Provider not found"))?;

    let callback_url = body
        .callback_url
        .clone()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| ctx.config.base_url.clone());
    if request.is_some() {
        validate_redirect_target(&callback_url, ctx, "Invalid callbackURL")?;
        if let Some(error_callback_url) = body.error_callback_url.as_deref() {
            validate_redirect_target(error_callback_url, ctx, "Invalid errorCallbackURL")?;
        }
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
            login_hint: body.login_hint.as_deref(),
            additional_params: body.additional_params.as_ref(),
            authorization_params: body.authorization_params.as_ref(),
            request_sign_up: body.request_sign_up,
            additional_data: filter_additional_state_data(body.additional_data.clone()),
            link: Some(OAuthStateLink {
                email: email.to_lowercase(),
                user_id: session.user_id().to_string(),
                encrypted_session_token: Some(
                    crate::token_crypto::encrypt_with_config_for_purpose(
                        session.token(),
                        &ctx.config,
                        crate::token_crypto::EncryptionPurpose::LinkSessionToken,
                    )?,
                ),
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
    let mut additional_params = request.additional_params.cloned().unwrap_or_default();
    if let Some(params) = request.authorization_params {
        for (key, value) in params {
            if request.provider.allowed_request_params.contains(key)
                && !RESERVED_AUTHORIZATION_PARAMS.contains(&key.as_str())
                && request
                    .provider
                    .authorization
                    .as_ref()
                    .is_none_or(|policy| key != &policy.client_id_parameter)
            {
                _ = additional_params.insert(key.clone(), value.clone());
            }
        }
    }
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

    let proxy = alibi_core::endpoint::current_endpoint_call_context()
        .and_then(|call| {
            call.extensions()
                .get::<crate::oauth_proxy::OAuthProxyFlow>()
        })
        .or_else(|| {
            alibi_core::hooks::current_request_hook_context()
                .and_then(|req| req.extensions.get::<crate::oauth_proxy::OAuthProxyFlow>())
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
    _ = payload.additional_data.insert(
        "oauthState".to_owned(),
        serde_json::Value::String(state.clone()),
    );
    if proxy.is_some() {
        let issued = crate::oauth_proxy::IssuedProxyState {
            state: state.clone(),
            payload: payload.clone(),
        };
        if let Some(call) = alibi_core::endpoint::current_endpoint_call_context() {
            call.extensions().insert(issued.clone());
        }
        if let Some(req) = alibi_core::hooks::current_request_hook_context() {
            req.extensions.insert(issued);
        }
    }

    match ctx.config.account.store_state_strategy {
        alibi_core::OAuthStateStrategy::Automatic => {
            return Err(AuthError::config(
                "OAuth state strategy has not been initialized",
            ));
        }
        alibi_core::OAuthStateStrategy::Database => {
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

    let url = build_authorization_url(
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
        Some(&additional_params),
        payload.id_token_nonce.as_deref(),
    )?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> OAuthProvider {
        let mut provider =
            crate::oauth::providers::GenericOAuthConfig::new("client", "secret").provider;
        provider.auth_url = "https://example.com/authorize".into();
        provider
    }

    #[tokio::test]
    async fn generic_authorization_requires_a_client_id() {
        for client_id in ["", "client"] {
            let mut config = crate::oauth::providers::GenericOAuthConfig::new(client_id, "");
            config.authorization_url = Some("https://example.com/authorize".into());
            let provider = config.resolve().await.unwrap().unwrap().provider;
            let result = build_authorization_url(
                &provider,
                "https://app/callback",
                None,
                "state",
                "challenge",
                None,
                None,
                None,
            );
            assert_eq!(result.is_ok(), !client_id.is_empty());
            if client_id.is_empty() {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("Client ID is required")
                );
            }
        }
    }

    #[test]
    fn published_required_verifiers_preserve_credential_order_and_optional_pkce() {
        for (name, provider) in [
            ("Paybin", OAuthProvider::paybin("client", Some("secret"))),
            (
                "Salesforce",
                OAuthProvider::salesforce("client", Some("secret")),
            ),
            ("Vercel", OAuthProvider::vercel("", None)),
        ] {
            let result = build_authorization_url(
                &provider,
                "https://app/callback",
                None,
                "state",
                "",
                None,
                None,
                None,
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(&format!("codeVerifier is required for {name}"))
            );
            let result = build_authorization_url(
                &provider,
                "https://app/callback",
                None,
                "state",
                "challenge",
                None,
                None,
                None,
            )
            .unwrap();
            let url = url::Url::parse(&result).unwrap();
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "code_challenge" && value == "challenge")
            );
        }
        for provider in [
            OAuthProvider::paybin("", None),
            OAuthProvider::salesforce("", None),
        ] {
            let error = build_authorization_url(
                &provider,
                "https://app/callback",
                None,
                "state",
                "",
                None,
                None,
                None,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("Client ID and client secret are required")
            );
        }
    }

    fn endpoint_url(endpoint: &str, prompt: Option<&str>, additional: &[(&str, &str)]) -> String {
        let mut provider = provider();
        endpoint.clone_into(&mut provider.auth_url);
        provider.authorization.as_mut().unwrap().prompt = prompt.map(str::to_owned);
        let additional = additional
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let result = build_authorization_url(
            &provider,
            "https://app/callback",
            None,
            "state-xyz",
            "challenge",
            None,
            Some(&additional),
            None,
        )
        .unwrap();
        let url = url::Url::parse(&result).unwrap();
        url.query().map(|query| format!("?{query}")).unwrap_or_default()
    }

    fn all(search: &str, name: &str) -> Vec<String> {
        url::form_urlencoded::parse(search.strip_prefix('?').unwrap_or(search).as_bytes())
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .collect()
    }

    // Upstream: packages/core/src/oauth2/create-authorization-url.test.ts (#12572, #12620).
    #[test]
    fn authorization_keeps_the_endpoint_query_text() {
        let search = endpoint_url(
            "https://idp.example/authorize?tenant=acme%20inc&value=~",
            None,
            &[],
        );
        assert!(search.starts_with("?tenant=acme%20inc&value=~&"), "{search}");
        assert_eq!(all(&search, "client_id"), ["client"]);

        let search = endpoint_url(
            "https://idp.example/authorize?tenant=acme&&value=~&&prompt=login",
            Some("consent"),
            &[],
        );
        assert!(
            search
                .strip_prefix("?tenant=acme&&value=~&&")
                .is_some_and(|rest| !rest.starts_with('&')),
            "{search}"
        );
        assert_eq!(all(&search, "prompt"), ["consent"]);

        let search = endpoint_url(
            "https://idp.example/authorize?prompt=login&",
            Some("consent"),
            &[],
        );
        assert!(search.starts_with("?&") && !search.starts_with("?&&"), "{search}");
        assert_eq!(all(&search, "prompt"), ["consent"]);

        let search = endpoint_url(
            "https://idp.example/authorize?tenant=acme&?",
            None,
            &[("?", "new")],
        );
        assert_eq!(all(&search, "?"), ["new"]);
        assert!(
            search.starts_with("?tenant=acme&") && !search.starts_with("?tenant=acme&&"),
            "{search}"
        );

        let search = endpoint_url("https://idp.example/authorize??state=stale", None, &[]);
        assert!(search.starts_with("??state=stale&"), "{search}");
        assert_eq!(all(&search, "state"), ["state-xyz"]);

        let search = endpoint_url(
            "https://idp.example/authorize?prompt=login&tenant=acme%20inc",
            Some("consent"),
            &[],
        );
        assert_eq!(all(&search, "prompt"), ["consent"]);
        assert!(search.starts_with("?tenant=acme%20inc&"), "{search}");
    }

    #[test]
    fn authorization_omits_pkce_without_a_challenge() {
        let provider = provider();
        for challenge in ["", "challenge"] {
            let result = build_authorization_url(
                &provider,
                "https://app/callback",
                None,
                "state",
                challenge,
                None,
                None,
                None,
            )
            .unwrap();
            let url = url::Url::parse(&result).unwrap();
            let pairs: std::collections::HashMap<_, _> = url.query_pairs().collect();
            assert_eq!(
                pairs.get("code_challenge").map(|value| value.as_ref()),
                (!challenge.is_empty()).then_some(challenge)
            );
            assert_eq!(
                pairs
                    .get("code_challenge_method")
                    .map(|value| value.as_ref()),
                (!challenge.is_empty()).then_some("S256")
            );
        }
    }
}
