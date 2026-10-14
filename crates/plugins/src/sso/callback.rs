//! OIDC callback state admission, grant redemption, and session issuance.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, ServerEndpoint, SsoPlugin,
    Value, api, json,
};
use crate::oauth::{
    OAuthTokenSet, OAuthUserInfo,
    handlers::{OAuthIdentity, OAuthProcessPolicy, process_oauth_sign_in},
    state::{OAuthStatePayload, get_cookie, state_cookie_name, state_verification_identifier},
};
use alibi_core::utils::cookie_utils::{create_clear_cookie, verify_cookie_value};
use alibi_core::{OAuthStateStrategy, RequestMeta, session::SessionRequest};
use std::sync::Arc;
impl SsoPlugin {
    pub fn callback_sso_endpoint(
        provider_id: &str,
        query: &Value,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "callbackSSO")
            .with_params(&json!({"providerId":provider_id}))?
            .with_query(query)
    }
    pub(super) async fn callback<S: AuthSchema>(
        &self,
        provider_id: Option<&str>,
        query: &Value,
        request: &impl SessionRequest,
        meta: &RequestMeta,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let default_error = format!("{base}/error");
        let Some(state) = query
            .get("state")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            return redirect_error(&default_error, "state_not_found", None);
        };
        let cookie = get_cookie(request, &state_cookie_name(&ctx.config));
        let payload: Option<OAuthStatePayload> = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Database => {
                let identifier = state_verification_identifier(state);
                let proof = ctx.verifications().find(&identifier).await?;
                let payload = proof
                    .as_ref()
                    .and_then(|proof| proof.value().ok())
                    .and_then(|value| serde_json::from_str::<OAuthStatePayload>(value).ok());
                if let Some(payload) = payload.as_ref()
                    && !ctx.config.account.skip_state_cookie_check
                    && cookie
                        .as_deref()
                        .and_then(|cookie| verify_cookie_value(cookie, ctx.config.current_secret()))
                        .as_deref()
                        != Some(state)
                {
                    return redirect_error(
                        payload.error_url.as_deref().unwrap_or(&default_error),
                        "state_mismatch",
                        None,
                    );
                }
                if payload.is_some() && ctx.verifications().consume(&identifier).await?.is_none() {
                    None
                } else {
                    payload
                }
            }
            OAuthStateStrategy::Cookie => cookie.as_deref().and_then(|cookie| {
                crate::oauth::state::decode_cookie_state_value(&ctx.config, cookie).ok()
            }),
            OAuthStateStrategy::Automatic => None,
        };
        let Some(payload) = payload else {
            return redirect_error(&default_error, "state_mismatch", None);
        };
        let clear = create_clear_cookie(&state_cookie_name(&ctx.config), &ctx.config)?;
        let target = payload
            .error_url
            .as_deref()
            .unwrap_or(&payload.callback_url);
        let fail =
            |error: &str, description: Option<&str>| -> AuthResult<EndpointResponse> {
                Ok(redirect_error(target, error, description)?
                    .with_header("Set-Cookie", clear.clone()))
            };
        if payload
            .additional_data
            .get("oauthState")
            .and_then(Value::as_str)
            != Some(state)
        {
            return fail("state_mismatch", None);
        }
        if payload.expires_at < chrono::Utc::now().timestamp_millis() {
            return fail("state_expired", None);
        }
        // Shared callbacks derive the provider only from protected state.
        let provider_id = match provider_id {
            Some(id) => id,
            None => match payload
                .server_context
                .as_ref()
                .and_then(|context| context.get("ssoProviderReference"))
                .and_then(|reference| reference.get("providerId"))
                .and_then(Value::as_str)
            {
                Some(id) => id,
                None => return fail("invalid_state", Some("missing_sso_provider_reference")),
            },
        };
        let code = query
            .get("code")
            .and_then(Value::as_str)
            .filter(|code| !code.is_empty());
        let error = query
            .get("error")
            .and_then(Value::as_str)
            .filter(|error| !error.is_empty());
        if code.is_none() || error.is_some() {
            return fail(
                error.unwrap_or("invalid_request"),
                Some(
                    query
                        .get("error_description")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| error.unwrap_or("authorization_code_not_found")),
                ),
            );
        }
        let Some(provider) = self.find_provider(provider_id, ctx).await? else {
            return fail("invalid_provider", Some("provider not found"));
        };
        let reference = payload
            .server_context
            .as_ref()
            .and_then(|value| value.get("ssoProviderReference"));
        if reference.is_none() {
            return fail("invalid_state", Some("missing_sso_provider_reference"));
        }
        if reference
            != Some(&super::sign_in::provider_reference(
                &provider,
                self.config.domain_verification,
            )?)
        {
            return fail(
                "invalid_state",
                Some("sso_provider_changed_during_authentication"),
            );
        }
        if self.config.domain_verification && provider.domain_verified != Some(true) {
            return Err(api(401, "Provider domain has not been verified"));
        }
        let Some(config) = provider
            .oidc_config
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        else {
            return fail("invalid_provider", Some("provider not found"));
        };
        let config = match super::discovery::ensure(&config, &provider.issuer, ctx).await {
            Ok(config) => config,
            Err(error) => {
                return fail(
                    "discovery_failed",
                    Some(super::discovery::callback_error_message(&error)),
                );
            }
        };
        let Some(token_endpoint) = config.get("tokenEndpoint").and_then(Value::as_str) else {
            return fail("invalid_provider", Some("token_endpoint_not_found"));
        };
        let redirect_uri = self.oidc_redirect_uri(&base, provider_id);
        let mut form = vec![
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), code.unwrap_or_default().to_owned()),
            ("redirect_uri".to_owned(), redirect_uri),
        ];
        if config.get("pkce") == Some(&json!(true)) {
            form.push(("code_verifier".into(), payload.code_verifier.clone()));
        }
        let client_id = config
            .get("clientId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let secret = config
            .get("clientSecret")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let client_assertion = if config
            .get("tokenEndpointAuthentication")
            .and_then(Value::as_str)
            == Some("private_key_jwt")
        {
            let mut key = self
                .config
                .default_providers
                .iter()
                .find(|provider| provider.provider_id == provider_id)
                .and_then(|provider| provider.private_key.clone());
            if key.is_none()
                && let Some(resolver) = &self.config.resolve_private_key
            {
                key = resolver
                    .0
                    .resolve(super::SsoPrivateKeyContext {
                        provider_id: provider_id.into(),
                        key_id: config
                            .get("privateKeyId")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        issuer: config
                            .get("issuer")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .into(),
                    })
                    .await?;
            }
            let Some(key) = key.filter(super::SsoPrivateKey::has_material) else {
                return fail("invalid_provider", Some("no_private_key_available"));
            };
            Some(key.assertion(&config).map_err(AuthError::internal)?)
        } else {
            None
        };
        let exchange = async {
            let (client, token_url) = outbound_client(token_endpoint, ctx).await?;
            let mut grant = client.post(token_url);
            if let Some(assertion) = client_assertion.as_ref() {
                let signed_assertion = assertion
                    .0
                    .get_client_assertion(crate::oauth::OAuthClientAssertionContext {
                        client_id: client_id.into(),
                        token_endpoint: token_endpoint.into(),
                        grant_type: crate::oauth::OAuthTokenGrant::AuthorizationCode,
                    })
                    .await
                    .map_err(AuthError::internal)?;
                form.push(("client_id".into(), client_id.into()));
                form.push(("client_assertion".into(), signed_assertion));
                form.push((
                    "client_assertion_type".into(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ));
            } else if config
                .get("tokenEndpointAuthentication")
                .and_then(Value::as_str)
                == Some("client_secret_post")
            {
                form.push(("client_id".into(), client_id.into()));
                form.push(("client_secret".into(), secret.into()));
            } else {
                grant = grant.basic_auth(client_id, Some(secret));
            }
            let raw = grant
                .form(&form)
                .send()
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?
                .error_for_status()
                .map_err(|e| AuthError::internal(e.to_string()))?
                .json::<Value>()
                .await
                .map_err(|e| AuthError::internal(e.to_string()))?;
            let verified = if let Some(token) = raw
                .get("id_token")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty())
            {
                let endpoint = config
                    .get("jwksEndpoint")
                    .and_then(Value::as_str)
                    .ok_or_else(|| api(400, "jwks_endpoint_not_found"))?;
                Some(
                    super::callback_id_token::verify(
                        token,
                        endpoint,
                        client_id,
                        &provider.issuer,
                        ctx,
                    )
                    .await?,
                )
            } else {
                None
            };
            let access = raw
                .get("access_token")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::internal("missing_access_token"))?;
            let profile = if let Some(endpoint) = config
                .get("userInfoEndpoint")
                .and_then(Value::as_str)
                .filter(|endpoint| !endpoint.is_empty())
            {
                let (client, info_url) = outbound_client(endpoint, ctx).await?;
                let profile = client
                    .get(info_url)
                    .bearer_auth(access)
                    .send()
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .error_for_status()
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .json::<Value>()
                    .await
                    .map_err(|error| AuthError::internal(error.to_string()))?;
                if verified
                    .as_ref()
                    .is_some_and(|claims| profile.get("sub") != claims.get("sub"))
                {
                    return Err(api(400, "id_token_userinfo_subject_mismatch"));
                }
                profile
            } else {
                verified.ok_or_else(|| api(400, "user_info_endpoint_not_found"))?
            };
            let field = |name: &str, default: &str| {
                config
                    .get("mapping")
                    .and_then(|mapping| mapping.get(name))
                    .and_then(Value::as_str)
                    .filter(|field| !field.is_empty())
                    .unwrap_or(default)
                    .to_owned()
            };
            let text = |name: &str, default: &str| {
                profile
                    .get(field(name, default))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            let user = OAuthUserInfo {
                id: text("id", "sub")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| AuthError::internal("missing_user_info"))?,
                email: text("email", "email")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| AuthError::internal("missing_user_info"))?,
                name: text("name", "name"),
                image: text("image", "picture"),
                email_verified: self.config.trust_email_verified
                    && super::provider_email_verified(
                        profile.get(field("emailVerified", "email_verified")),
                    ),
                additional_fields: serde_json::Map::new(),
            };
            let tokens = OAuthTokenSet {
                id_token: raw
                    .get("id_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                access_token: Some(access.into()),
                refresh_token: raw
                    .get("refresh_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                token_type: raw
                    .get("token_type")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                access_token_expires_at: raw.get("expires_in").and_then(Value::as_i64).and_then(
                    |seconds| {
                        chrono::Utc::now().checked_add_signed(chrono::Duration::seconds(seconds))
                    },
                ),
                scopes: raw.get("scope").and_then(Value::as_str).map_or_else(
                    || {
                        config.get("scopes").and_then(Value::as_array).map_or_else(
                            || {
                                vec![
                                    "openid".into(),
                                    "email".into(),
                                    "profile".into(),
                                    "offline_access".into(),
                                ]
                            },
                            |scopes| {
                                scopes
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_owned)
                                    .collect()
                            },
                        )
                    },
                    |scope| scope.split(' ').map(str::to_owned).collect(),
                ),
                raw: Some(raw.clone()),
                ..Default::default()
            };
            Ok((user, tokens, profile))
        }
        .await;
        let (user, tokens, profile) = match exchange {
            Ok(value) => value,
            Err(error) => return fail("invalid_provider", Some(&error.to_string())),
        };
        let mut scoped = ctx.clone();
        let mut scoped_config = (*ctx.config).clone();
        scoped_config
            .account
            .account_linking
            .trusted_providers
            .retain(|id| id != provider_id);
        if provider.domain_verified == Some(true)
            && user
                .email
                .split('@')
                .nth(1)
                .is_some_and(|domain| super::domains::matches(domain, &provider.domain))
        {
            scoped_config
                .account
                .account_linking
                .trusted_providers
                .push(provider_id.into());
        }
        scoped.config = Arc::new(scoped_config);
        let policy = OAuthProcessPolicy {
            user_validation_method: Some("sso-oidc"),
            override_user_info: config
                .get("overrideUserInfo")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            callback_url: Some(payload.callback_url.clone()),
            use_updated_user: true,
            ..Default::default()
        };
        let issued = match process_oauth_sign_in(
            OAuthIdentity {
                provider_name: provider_id,
                user: &user,
                profile: &profile,
            },
            &policy,
            &tokens,
            self.config.disable_implicit_sign_up && payload.request_sign_up != Some(true),
            meta,
            &scoped,
        )
        .await
        {
            Ok(issued) => issued,
            Err(error) => {
                let (code, description) =
                    if let crate::oauth::handlers::OAuthSignInError::Generic(message) = &error {
                        (message.clone(), None)
                    } else {
                        error.redirect_parts()
                    };
                return fail(&code, description);
            }
        };
        let destination = if issued.is_register {
            payload
                .new_user_url
                .as_deref()
                .unwrap_or(&payload.callback_url)
        } else {
            &payload.callback_url
        };
        let mut response = crate::authentication_helpers::with_session_cookies(
            crate::authentication_helpers::redirect(destination),
            &ctx.config,
            &issued.session.token,
            false,
        )?;
        response.headers.append("Set-Cookie", clear);
        Ok(EndpointResponse::from_http_response(response))
    }
}
fn redirect_error(
    target: &str,
    error: &str,
    description: Option<&str>,
) -> AuthResult<EndpointResponse> {
    let mut url =
        url::Url::parse(target).map_err(|error| AuthError::internal(error.to_string()))?;
    {
        let mut query = url.query_pairs_mut();
        _ = query.append_pair("error", error);
        if let Some(description) = description {
            _ = query.append_pair("error_description", description);
        }
    }
    Ok(EndpointResponse::from_http_response(
        crate::authentication_helpers::redirect(url.as_str()),
    ))
}
pub(super) async fn outbound_client<S: AuthSchema>(
    endpoint: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<(reqwest::Client, url::Url)> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy();
    let url = url::Url::parse(endpoint).map_err(|e| AuthError::internal(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AuthError::internal("Invalid OIDC endpoint URL"));
    }
    if !ctx.config.is_redirect_target_trusted(endpoint) {
        let host = url
            .host_str()
            .ok_or_else(|| AuthError::internal("Invalid OIDC endpoint host"))?;
        let addresses = tokio::net::lookup_host((host, url.port_or_known_default().unwrap_or(443)))
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?
            .collect::<Vec<_>>();
        if addresses.is_empty()
            || addresses.iter().any(|address| match address.ip() {
                std::net::IpAddr::V4(ip) => {
                    ip.is_private()
                        || ip.is_loopback()
                        || ip.is_link_local()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                        || ip.is_broadcast()
                }
                std::net::IpAddr::V6(ip) => {
                    ip.is_loopback()
                        || ip.is_unique_local()
                        || ip.is_unicast_link_local()
                        || ip.is_unspecified()
                        || ip.is_multicast()
                }
            })
        {
            return Err(AuthError::internal(
                "OIDC endpoint resolves to a private or reserved address",
            ));
        }
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    Ok((
        builder
            .build()
            .map_err(|error| AuthError::internal(error.to_string()))?,
        url,
    ))
}
