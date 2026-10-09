use super::{
    AuthError, AuthResult, OAuthClientAssertionContext, OAuthProvider, OAuthTokenEndpointAuth,
    OAuthTokenGrant, OAuthTokenSet, OAuthUserInfoRequest, OAuthUserInfoResponse, Utc,
};
use base64::Engine;
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::oauth) async fn refresh_tokens_via_provider(
    provider: &OAuthProvider,
    refresh_token: &str,
    context: Option<super::super::providers::OAuthRefreshContext<'_>>,
) -> AuthResult<OAuthTokenSet> {
    if let Some(handler) = &provider.refresh_access_token {
        return handler
            .refresh_access_token_with_context(refresh_token, context)
            .await
            .map_err(AuthError::internal)
            .and_then(|tokens| with_default_access_expiry(provider, tokens));
    }

    // Resolve once per real grant, without mutating the shared provider config.
    let mut resolved_provider;
    let provider = if let Some(resolver) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.refresh_token_params_resolver.as_ref())
    {
        let params = resolver
            .0
            .resolve(context)
            .await
            .map_err(AuthError::internal)?;
        resolved_provider = provider.clone();
        if let Some(policy) = &mut resolved_provider.authorization {
            policy.refresh_token_params = params.unwrap_or_default();
        }
        &resolved_provider
    } else {
        provider
    };

    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    if let Some(scope) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.refresh_scope.as_deref())
    {
        form.push(("scope", scope));
    }
    let request = provider_token_request(provider, &form, OAuthTokenGrant::RefreshToken).await?;
    let token_resp = request
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token refresh failed: {e}")))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "Token refresh returned error: {error_body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse refresh response: {e}")))?;

    with_default_access_expiry(
        provider,
        parse_token_response(
            token_data,
            provider
                .authorization
                .as_ref()
                .is_some_and(|policy| policy.allow_missing_access_token),
        )?,
    )
}

pub(in crate::oauth::handlers) async fn provider_token_request(
    provider: &OAuthProvider,
    fields: &[(&str, &str)],
    grant_type: OAuthTokenGrant,
) -> AuthResult<reqwest::RequestBuilder> {
    let mut form: Vec<_> = fields
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    if let Some(policy) = &provider.authorization {
        let additions = if grant_type == OAuthTokenGrant::RefreshToken {
            &policy.refresh_token_params
        } else {
            &policy.authorization_code_params
        };
        for (key, value) in additions {
            if grant_type == OAuthTokenGrant::RefreshToken {
                if matches!(
                    key.as_str(),
                    "grant_type" | "refresh_token" | "__proto__" | "constructor" | "prototype"
                ) {
                    continue;
                }
                form.retain(|(existing, _)| existing != key);
            } else if form.iter().any(|(existing, _)| existing == key) {
                continue;
            }
            form.push((key.clone(), value.clone()));
        }
    }
    let request = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| AuthError::internal(format!("Token HTTP client failed: {error}")))?
        .post(&provider.token_url)
        .header("Accept", "application/json");
    let mut request = request;
    if grant_type == OAuthTokenGrant::AuthorizationCode
        && let Some(policy) = &provider.authorization
    {
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &policy.authorization_code_headers {
            let name =
                reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                    AuthError::config(format!("Invalid code grant header: {error}"))
                })?;
            let value = reqwest::header::HeaderValue::from_str(value).map_err(|error| {
                AuthError::config(format!("Invalid code grant header: {error}"))
            })?;
            drop(headers.insert(name, value));
        }
        request = request.headers(headers);
    }
    let authentication = provider.authorization.as_ref().and_then(|policy| {
        if grant_type == OAuthTokenGrant::RefreshToken {
            policy
                .refresh_token_endpoint_auth
                .or(policy.token_endpoint_auth)
        } else {
            policy.token_endpoint_auth
        }
    });
    let has_field = |name: &str| form.iter().any(|(key, _)| key == name);
    if has_field("client_assertion") != has_field("client_assertion_type") {
        return Err(AuthError::config(
            "client_assertion and client_assertion_type must both be provided",
        ));
    }
    if has_field("client_assertion") {
        if authentication.is_some() {
            return Err(AuthError::config(
                "client_assertion body parameters cannot be combined with tokenEndpointAuth",
            ));
        }
        if !provider.client_secret.is_empty() || has_field("client_secret") {
            return Err(AuthError::config(
                "private_key_jwt token endpoint authentication cannot be combined with clientSecret",
            ));
        }
        if !provider.client_id.is_empty() {
            form.retain(|(key, _)| key != "client_id");
            form.push(("client_id".into(), provider.client_id.clone()));
        }
        return Ok(request.form(&form));
    }
    // Generic parameter policies use the published automatic authentication
    // selection. Retain the legacy transport for providers with no additions.
    let authentication = authentication.or_else(|| {
        provider.authorization.as_ref().and_then(|policy| {
            let additions = if grant_type == OAuthTokenGrant::RefreshToken {
                &policy.refresh_token_params
            } else {
                &policy.authorization_code_params
            };
            (!additions.is_empty()).then_some(if provider.client_secret.is_empty() {
                OAuthTokenEndpointAuth::None
            } else {
                OAuthTokenEndpointAuth::ClientSecretPost
            })
        })
    });
    let request = match authentication {
        None => {
            form.retain(|(key, _)| key != "client_id" && key != "client_secret");
            form.extend([
                ("client_id".into(), provider.client_id.clone()),
                ("client_secret".into(), provider.client_secret.clone()),
            ]);
            request
        }
        Some(OAuthTokenEndpointAuth::None) => {
            if provider.client_id.is_empty()
                || !provider.client_secret.is_empty()
                || has_field("client_secret")
            {
                return Err(AuthError::config(
                    "Public token authentication requires client ID and no secret",
                ));
            }
            form.retain(|(key, _)| key != "client_id");
            form.push(("client_id".into(), provider.client_id.clone()));
            request
        }
        Some(OAuthTokenEndpointAuth::PrivateKeyJwt) => {
            if provider.client_id.is_empty()
                || provider.token_url.is_empty()
                || !provider.client_secret.is_empty()
                || has_field("client_secret")
            {
                return Err(AuthError::config(
                    "Client assertion requires client ID and no secret",
                ));
            }
            let assertion = provider
                .authorization
                .as_ref()
                .and_then(|policy| policy.client_assertion.as_ref())
                .ok_or_else(|| AuthError::config("Client assertion callback is required"))?
                .0
                .get_client_assertion(OAuthClientAssertionContext {
                    client_id: provider.client_id.clone(),
                    token_endpoint: provider.token_url.clone(),
                    grant_type,
                })
                .await
                .map_err(AuthError::internal)?;
            form.retain(|(key, _)| key != "client_id");
            form.extend([
                ("client_id".into(), provider.client_id.clone()),
                ("client_assertion".into(), assertion),
                (
                    "client_assertion_type".into(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
                ),
            ]);
            request
        }
        Some(OAuthTokenEndpointAuth::ClientKeyPost) => {
            form.retain(|(key, _)| key != "client_key" && key != "client_secret");
            form.extend([
                ("client_key".into(), provider.client_id.clone()),
                ("client_secret".into(), provider.client_secret.clone()),
            ]);
            request
        }
        Some(method) => {
            if provider.client_id.is_empty() || provider.client_secret.is_empty() {
                return Err(AuthError::config(
                    "Client ID and client secret are required",
                ));
            }
            if method == OAuthTokenEndpointAuth::ClientSecretBasic {
                if has_field("client_secret") {
                    return Err(AuthError::config(
                        "client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters",
                    ));
                }
                let encode = |value: &str| {
                    url::form_urlencoded::Serializer::new(String::new())
                        .append_key_only(value)
                        .finish()
                };
                request.basic_auth(
                    encode(&provider.client_id),
                    Some(encode(&provider.client_secret)),
                )
            } else {
                form.retain(|(key, _)| key != "client_id" && key != "client_secret");
                form.extend([
                    ("client_id".into(), provider.client_id.clone()),
                    ("client_secret".into(), provider.client_secret.clone()),
                ]);
                request
            }
        }
    };
    Ok(request.form(&form))
}

pub(in crate::oauth::handlers) fn with_default_access_expiry(
    provider: &OAuthProvider,
    mut tokens: OAuthTokenSet,
) -> AuthResult<OAuthTokenSet> {
    if tokens.access_token_expires_at.is_none()
        && let Some(seconds) = provider
            .authorization
            .as_ref()
            .and_then(|policy| policy.default_access_token_expires_in)
        && seconds != 0.0
        && !seconds.is_nan()
    {
        tokens.access_token_expires_at = super::super::providers::remaining_profile::grant_expiry(
            &serde_json::json!(seconds),
            false,
        );
        if tokens.access_token_expires_at.is_none() {
            return Err(AuthError::internal("Invalid provider token expiry"));
        }
    }
    Ok(tokens)
}

pub(in crate::oauth::handlers) fn parse_token_response(
    token_data: serde_json::Value,
    allow_missing_access_token: bool,
) -> AuthResult<OAuthTokenSet> {
    if token_data.is_null() {
        return Err(AuthError::internal("Missing token response"));
    }
    let access_token = token_data
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    if access_token.is_none() && !allow_missing_access_token {
        return Err(AuthError::internal(
            "Missing access_token in token response",
        ));
    }
    let refresh_token = token_data
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let id_token = token_data
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let expiry = |field: &str| -> Option<chrono::DateTime<Utc>> {
        super::super::providers::remaining_profile::grant_expiry(token_data.get(field)?, true)
    };
    let access_token_expires_at = expiry("expires_in");
    let refresh_token_expires_at = expiry("refresh_token_expires_in");
    let scopes = match token_data.get("scope") {
        Some(serde_json::Value::String(scope)) => scope
            .split(super::super::providers::remaining_profile::js_whitespace)
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect(),
        Some(serde_json::Value::Array(scopes)) => scopes
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(|value| {
                value.trim_matches(super::super::providers::remaining_profile::js_whitespace)
            })
            .filter(|value| !value.is_empty())
            .map(String::from)
            .collect(),
        _ => Vec::new(),
    };

    Ok(OAuthTokenSet {
        token_type: token_data
            .get("token_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        access_token,
        refresh_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scopes,
        id_token,
        raw: Some(token_data),
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(crate) async fn validate_authorization_code_via_provider(
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    device_id: Option<&str>,
) -> AuthResult<OAuthTokenSet> {
    let redirect_uri = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.redirect_uri.as_deref())
        .filter(|uri| !uri.is_empty())
        .unwrap_or(redirect_uri);
    if let Some(handler) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.authorization_code.as_ref())
    {
        return handler
            .0
            .validate_authorization_code(super::super::providers::OAuthAuthorizationCodeContext {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                code_verifier: code_verifier.map(str::to_owned),
                device_id: device_id.map(str::to_owned),
            })
            .await
            .map_err(AuthError::internal)
            .and_then(|tokens| with_default_access_expiry(provider, tokens));
    }
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(client_key) = provider
        .authorization
        .as_ref()
        .and_then(|policy| policy.authorization_code_client_key.as_deref())
        .filter(|value| !value.is_empty())
    {
        form.push(("client_key", client_key));
    }
    if let Some(code_verifier) = code_verifier {
        form.push(("code_verifier", code_verifier));
    }
    if let Some(device_id) = device_id {
        form.push(("device_id", device_id));
    }

    let request =
        provider_token_request(provider, &form, OAuthTokenGrant::AuthorizationCode).await?;
    let token_resp = request
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let error_body = token_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "Token exchange returned error: {error_body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse token response: {e}")))?;
    with_default_access_expiry(
        provider,
        parse_token_response(
            token_data,
            provider
                .authorization
                .as_ref()
                .is_some_and(|policy| policy.allow_missing_access_token),
        )?,
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(crate) async fn fetch_user_info_from_provider(
    provider: &OAuthProvider,
    request: OAuthUserInfoRequest,
) -> AuthResult<OAuthUserInfoResponse> {
    if let Some(handler) = &provider.get_user_info {
        let response = handler.get_user_info(request).await.map_err(|error| {
            if provider
                .authorization
                .as_ref()
                .is_some_and(|policy| policy.source_profile_exceptions)
                && (handler.errors_are_exceptions()
                    || error.starts_with(
                        super::super::providers::remaining_profile::PROFILE_EXCEPTION_PREFIX,
                    ))
            {
                AuthError::Api {
                    status: 500,
                    code: Some("OAUTH_PROFILE_EXCEPTION".into()),
                    message: "Provider profile callback failed".into(),
                }
            } else {
                AuthError::internal(error)
            }
        })?;
        return Ok(response);
    }

    if let Some(token) = request
        .id_token
        .as_deref()
        .filter(|_| provider.id_token.is_some())
    {
        // Direct sign-in verifies this immutable token before requesting its profile;
        // the code flow obtains it from the trusted provider token exchange.
        let payload = token
            .split('.')
            .nth(1)
            .ok_or_else(|| AuthError::internal("Missing ID-token payload"))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        let profile: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| AuthError::internal(error.to_string()))?;
        if !super::super::id_token::hosted_domain_allowed(
            provider,
            profile.get("hd").and_then(serde_json::Value::as_str),
        ) {
            return Err(AuthError::internal("Hosted domain mismatch"));
        }
        let mapper = provider
            .map_user_info
            .ok_or_else(|| AuthError::internal("Missing user-info mapper"))?;
        let user = mapper(profile.clone()).map_err(AuthError::internal)?;
        let response = OAuthUserInfoResponse {
            user_output: None,
            user,
            data: profile,
        };
        return Ok(response);
    }

    let user_info_url = provider
        .user_info_url
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing user_info_url for provider"))?;
    let access_token = request
        .access_token
        .as_deref()
        .ok_or_else(|| AuthError::internal("Missing access token for user-info lookup"))?;
    let mapper = provider
        .map_user_info
        .ok_or_else(|| AuthError::internal("Missing user-info mapper for provider"))?;

    let client = reqwest::Client::new();
    let user_info_resp = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to fetch user info: {e}")))?;

    if !user_info_resp.status().is_success() {
        let error_body = user_info_resp
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_owned());
        return Err(AuthError::internal(format!(
            "User info request failed: {error_body}"
        )));
    }

    let user_info_json: serde_json::Value = user_info_resp
        .json()
        .await
        .map_err(|e| AuthError::internal(format!("Failed to parse user info: {e}")))?;

    let user = mapper(user_info_json.clone())
        .map_err(|e| AuthError::internal(format!("Failed to map user info: {e}")))?;

    let response = OAuthUserInfoResponse {
        user_output: None,
        user,
        data: user_info_json,
    };
    Ok(response)
}
