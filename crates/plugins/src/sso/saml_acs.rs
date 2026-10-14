//! SAML ACS admission, verified-claim consumption, and real session issuance.
use super::{
    AuthContext, AuthError, AuthResult, AuthSchema, EndpointResponse, JsValue, ServerEndpoint,
    SsoPlugin, Value, api, json,
};
use crate::oauth::{
    OAuthTokenSet, OAuthUserInfo,
    handlers::{OAuthIdentity, OAuthProcessPolicy, process_oauth_sign_in},
    state::{OAuthStatePayload, get_cookie, state_verification_identifier},
};
use alibi_core::{OAuthStateStrategy, RequestMeta, session::SessionRequest};
use base64::Engine as _;
use std::sync::Arc;
impl SsoPlugin {
    pub fn acs_endpoint(provider_id: &str, input: &Value) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("sso", "acsEndpoint")
            .with_params(&json!({"providerId":provider_id}))?
            .with_body(input)
    }
    pub(super) async fn acs<S: AuthSchema>(
        &self,
        provider_id: &str,
        body: Option<&Value>,
        query: Option<&Value>,
        request: &impl SessionRequest,
        meta: &RequestMeta,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        let base = format!(
            "{}{}",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path.trim_end_matches('/')
        );
        let callback = format!("{base}/sso/saml2/sp/acs/{provider_id}");
        let encoded = body
            .and_then(|body| body.get("SAMLResponse"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        if *request.session_method() == alibi_core::HttpMethod::Get && encoded.is_none() {
            if crate::helpers::ordinary_session(request, ctx)
                .await
                .is_err()
            {
                return error_redirect(
                    &format!("{}/error", ctx.config.base_url.trim_end_matches('/')),
                    "invalid_request",
                    None,
                    None,
                    ctx,
                );
            }
            let target = safe_redirect(
                [query
                    .and_then(|query| query.get("RelayState"))
                    .and_then(Value::as_str)],
                &callback,
                ctx,
            );
            return Ok(EndpointResponse::from_http_response(
                crate::authentication_helpers::redirect(&target),
            ));
        }
        let encoded =
            encoded.ok_or_else(|| api(400, "SAMLResponse is required for POST requests"))?;
        let relay = body
            .and_then(|body| body.get("RelayState"))
            .and_then(Value::as_str)
            .filter(|state| !state.is_empty());
        let (payload, failed, clear) = if let Some(state) = relay {
            let payload = self.parse_saml_relay(state, request, ctx).await?;
            let failed = payload.is_none();
            let clear = payload
                .as_ref()
                .map(|_| {
                    alibi_core::utils::cookie_utils::create_clear_cookie(
                        &alibi_core::utils::cookie_utils::related_cookie_name(
                            &ctx.config,
                            "relay_state",
                        ),
                        &ctx.config,
                    )
                })
                .transpose()?;
            (payload, failed, clear)
        } else {
            (None, false, None)
        };
        let provider = ctx
            .database
            .get_sso_provider(provider_id)
            .await?
            .ok_or_else(|| api(404, "No SAML provider found"))?;
        let config = provider
            .saml_config
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .filter(|value| !value.is_null())
            .ok_or_else(|| api(404, "No SAML provider found"))?;
        if self.config.domain_verification && provider.domain_verified != Some(true) {
            return Err(api(401, "Provider domain has not been verified"));
        }
        let target = safe_redirect(
            [
                payload
                    .as_ref()
                    .map(|payload| payload.callback_url.as_str()),
                config
                    .get("idpInitiatedCallbackUrl")
                    .and_then(Value::as_str),
                config.get("callbackUrl").and_then(Value::as_str),
            ],
            &callback,
            ctx,
        );
        let error_target = safe_redirect(
            [
                payload
                    .as_ref()
                    .and_then(|payload| payload.error_url.as_deref()),
                Some(target.as_str()),
            ],
            &callback,
            ctx,
        );
        let fail = |code: &str, message: Option<&str>| {
            error_redirect(&error_target, code, message, clear.as_deref(), ctx)
        };
        if encoded.len() > self.config.saml_max_response_size {
            return fail(
                "saml_error",
                Some(&format!(
                    "SAML response exceeds maximum allowed size ({} bytes)",
                    self.config.saml_max_response_size
                )),
            );
        }
        let encoded = encoded
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let Some(xml) = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            return fail("saml_error", Some("Invalid SAML response"));
        };
        let identity = match super::saml_crypto::verify(
            &xml,
            &config,
            &callback,
            self.config.saml_clock_skew,
            self.config.saml_require_timestamps,
        ) {
            Ok(identity) => identity,
            Err(error) => return fail(error.code, Some(error.message)),
        };
        let request_reference = if self.config.saml_enable_in_response_to_validation {
            let Some(response_to) = identity.in_response_to.as_deref() else {
                return fail(
                    "unsolicited_response",
                    Some("IdP-initiated SSO not allowed"),
                );
            };
            let proof = ctx
                .verifications()
                .consume(&format!("saml-authn-request:{response_to}"))
                .await?;
            let proof = proof
                .as_ref()
                .and_then(|proof| proof.value().ok())
                .and_then(|value| serde_json::from_str::<Value>(value).ok());
            let Some(proof) = proof else {
                return fail(
                    "invalid_saml_response",
                    Some("Unknown or expired request ID"),
                );
            };
            if proof.get("providerId").and_then(Value::as_str) != Some(provider_id) {
                return fail("invalid_saml_response", Some("Provider mismatch"));
            }
            let Some(reference) = proof.get("providerReference").cloned() else {
                return fail(
                    "invalid_state",
                    Some("SSO provider reference missing or invalid"),
                );
            };
            Some(reference)
        } else {
            None
        };
        if failed {
            return fail("invalid_state", Some("invalid_or_expired_relay_state"));
        }
        let relay_reference = payload
            .as_ref()
            .and_then(|payload| payload.server_context.as_ref())
            .and_then(|context| context.get("ssoProviderReference"));
        if payload.is_some() && relay_reference.is_none() {
            return fail(
                "invalid_state",
                Some("sso_provider_reference_missing_or_invalid"),
            );
        }
        if let (Some(relay), Some(request)) = (relay_reference, request_reference.as_ref())
            && relay != request
        {
            return fail("invalid_state", Some("sso_provider_reference_mismatch"));
        }
        let current =
            super::sign_in::provider_reference(&provider, self.config.domain_verification)?;
        let reference = relay_reference
            .or(request_reference.as_ref())
            .unwrap_or(&current);
        if reference != &current {
            return fail(
                "invalid_state",
                Some("sso_provider_changed_during_authentication"),
            );
        }
        if let Some(assertion) = identity.assertion_id.as_deref() {
            let expires_at = identity
                .expires_at
                .and_then(|expiry| expiry.checked_add_signed(self.config.saml_clock_skew))
                .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::minutes(10));
            if !ctx.verifications().reserve(alibi_core::CreateVerification{identifier:format!("saml-used-assertion:{assertion}"),value:serde_json::to_string(&json!({"assertionId":assertion,"issuer":identity.issuer,"providerId":provider_id,"usedAt":chrono::Utc::now().timestamp_millis(),"expiresAt":expires_at.timestamp_millis()}))?,expires_at}).await?{return fail("replay_detected",Some("SAML assertion has already been used"));}
        }
        let verified = config
            .get("mapping")
            .and_then(|mapping| mapping.get("emailVerified"))
            .and_then(Value::as_str)
            .filter(|field| !field.is_empty())
            .and_then(|field| identity.attributes.get(field))
            .and_then(|value| {
                if let Some(values) = value.as_array() {
                    values.first()
                } else {
                    Some(value)
                }
            });
        let verified = self.config.trust_email_verified && super::provider_email_verified(verified);
        let user = OAuthUserInfo {
            id: identity.id,
            email: identity.email,
            name: Some(identity.name),
            image: None,
            email_verified: verified,
            additional_fields: serde_json::Map::new(),
        };
        let mut scoped = ctx.clone();
        let mut config = (*ctx.config).clone();
        config
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
            config
                .account
                .account_linking
                .trusted_providers
                .push(provider_id.into());
        }
        scoped.config = Arc::new(config);
        let tokens = OAuthTokenSet {
            access_token: Some(String::new()),
            refresh_token: Some(String::new()),
            ..Default::default()
        };
        let policy = OAuthProcessPolicy {
            user_validation_method: Some("sso-saml"),
            callback_url: Some(target.clone()),
            use_updated_user: true,
            ..Default::default()
        };
        let issued = match process_oauth_sign_in(
            OAuthIdentity {
                provider_name: provider_id,
                user: &user,
                profile: &identity.attributes,
            },
            &policy,
            &tokens,
            self.config.disable_implicit_sign_up,
            meta,
            &scoped,
        )
        .await
        {
            Ok(issued) => issued,
            Err(error) => {
                let (code, description) = error.redirect_parts();
                let target = if matches!(
                    error,
                    crate::oauth::handlers::OAuthSignInError::IdentityDenied { .. }
                        | crate::oauth::handlers::OAuthSignInError::Banned(_)
                ) {
                    &error_target
                } else {
                    &target
                };
                return error_redirect(target, &code, description, clear.as_deref(), ctx);
            }
        };
        if self.config.saml_enable_single_logout {
            let key = format!("saml-session:{provider_id}:{}", user.id);
            let mut data = json!({"sessionId":issued.session.id,"sessionToken":issued.session.token,"providerId":provider_id,"nameID":user.id});
            if let Some(index) = identity.session_index {
                _ = data
                    .as_object_mut()
                    .ok_or_else(|| AuthError::internal("SAML session serialization failed"))?
                    .insert("sessionIndex".into(), json!(index));
            }
            let value = serde_json::to_string(&data)?;
            if let Err(error) = ctx
                .verifications()
                .create(alibi_core::CreateVerification {
                    identifier: key.clone(),
                    value,
                    expires_at: issued.session.expires_at,
                })
                .await
            {
                tracing::warn!(%error,"Failed to create SAML session record");
            }
            if let Err(error) = ctx
                .verifications()
                .create(alibi_core::CreateVerification {
                    identifier: format!("saml-session-by-id:{}", issued.session.id),
                    value: key,
                    expires_at: issued.session.expires_at,
                })
                .await
            {
                tracing::warn!(%error,"Failed to create SAML session lookup record");
            }
        }
        let mut response = crate::authentication_helpers::with_session_cookies(
            crate::authentication_helpers::redirect(&target),
            &ctx.config,
            &issued.session.token,
            false,
        )?;
        if let Some(clear) = clear {
            response.headers.append("Set-Cookie", clear);
        }
        Ok(EndpointResponse::from_http_response(response))
    }
    async fn parse_saml_relay<S: AuthSchema>(
        &self,
        state: &str,
        request: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<OAuthStatePayload>> {
        let payload = match ctx.config.account.store_state_strategy {
            OAuthStateStrategy::Database => {
                let identifier = state_verification_identifier(state);
                let found = ctx.verifications().find(&identifier).await?;
                let payload = found
                    .as_ref()
                    .and_then(|proof| proof.value().ok())
                    .and_then(|value| serde_json::from_str::<OAuthStatePayload>(value).ok());
                if payload.as_ref().is_some_and(|payload| {
                    payload
                        .additional_data
                        .get("oauthState")
                        .and_then(Value::as_str)
                        .is_some_and(|stored| stored != state)
                }) {
                    return Ok(None);
                }
                if payload.is_some() && ctx.verifications().consume(&identifier).await?.is_none() {
                    None
                } else {
                    payload
                }
            }
            OAuthStateStrategy::Cookie => get_cookie(
                request,
                &alibi_core::utils::cookie_utils::related_cookie_name(&ctx.config, "relay_state"),
            )
            .as_deref()
            .and_then(|cookie| {
                crate::oauth::state::decode_cookie_state_value(&ctx.config, cookie).ok()
            })
            .filter(|payload| {
                payload
                    .additional_data
                    .get("oauthState")
                    .and_then(Value::as_str)
                    == Some(state)
            }),
            OAuthStateStrategy::Automatic => None,
        };
        Ok(payload
            .filter(|payload| payload.expires_at >= chrono::Utc::now().timestamp_millis())
            .map(|mut payload| {
                if payload.error_url.is_none() {
                    payload.error_url = Some(format!(
                        "{}{}/error",
                        ctx.config.base_url.trim_end_matches('/'),
                        ctx.config.base_path.trim_end_matches('/')
                    ));
                }
                payload
            }))
    }
}
pub(super) fn safe_redirect<'a, S: AuthSchema>(
    candidates: impl IntoIterator<Item = Option<&'a str>>,
    callback: &str,
    ctx: &AuthContext<S>,
) -> String {
    let origin = url::Url::parse(&ctx.config.base_url).ok();
    let callback = url::Url::parse(callback).ok();
    for value in candidates
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
    {
        let relative = value.starts_with('/') && !value.starts_with("//") && !value.contains('\\');
        let url = if relative {
            origin.as_ref().and_then(|origin| origin.join(value).ok())
        } else {
            url::Url::parse(value).ok()
        };
        if let Some(url) = url
            && matches!(url.scheme(), "http" | "https")
            && origin.as_ref().is_some_and(|origin| {
                url.origin() == origin.origin() || ctx.config.is_redirect_target_trusted(value)
            })
            && !callback.as_ref().is_some_and(|callback| {
                url.origin() == callback.origin() && url.path() == callback.path()
            })
        {
            return value.into();
        }
    }
    origin.map_or_else(
        || ctx.config.base_url.clone(),
        |origin| origin.origin().ascii_serialization(),
    )
}
fn error_redirect<S: AuthSchema>(
    target: &str,
    code: &str,
    message: Option<&str>,
    clear: Option<&str>,
    ctx: &AuthContext<S>,
) -> AuthResult<EndpointResponse> {
    let relative = target.starts_with('/');
    let origin = url::Url::parse(&ctx.config.base_url)
        .map_err(|error| AuthError::internal(error.to_string()))?;
    let mut url = origin
        .join(target)
        .map_err(|error| AuthError::internal(error.to_string()))?;
    {
        let mut query = url.query_pairs_mut();
        _ = query.append_pair("error", code);
        if let Some(message) = message {
            _ = query.append_pair("error_description", message);
        }
    }
    let target = if relative {
        format!(
            "{}{}{}",
            url.path(),
            url.query()
                .map_or_else(String::new, |query| format!("?{query}")),
            url.fragment()
                .map_or_else(String::new, |fragment| format!("#{fragment}"))
        )
    } else {
        url.to_string()
    };
    let response =
        EndpointResponse::from_http_response(crate::authentication_helpers::redirect(&target));
    Ok(if let Some(clear) = clear {
        response.with_header("Set-Cookie", clear)
    } else {
        response
    })
}
pub(super) fn validate_body(input: Option<&JsValue>) -> AuthResult<Option<JsValue>> {
    input
        .map(|input| {
            crate::endpoint::validate_fields(
                Some(input),
                "body",
                &[
                    crate::authentication_helpers::JsonField::string("SAMLResponse", true),
                    crate::authentication_helpers::JsonField::string("RelayState", false),
                ],
            )
        })
        .transpose()
}
pub(super) fn validate_query(input: Option<&JsValue>) -> AuthResult<Option<JsValue>> {
    input
        .map(|input| {
            crate::endpoint::validate_fields(
                Some(input),
                "query",
                &[crate::authentication_helpers::JsonField::string(
                    "RelayState",
                    false,
                )],
            )
        })
        .transpose()
}
