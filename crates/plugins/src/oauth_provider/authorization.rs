//! Authorization admission and signed browser interaction requests.
use super::OAuthProviderPlugin;
use alibi_core::endpoint::{EndpointResponse, ServerEndpoint};
use alibi_core::session::SessionRequest;
use alibi_core::utils::json::JsValue;
use alibi_core::{AuthContext, AuthError, AuthResult, AuthSchema, AuthUser};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

// Replace only logical query input. Browser continuations can carry genuine
// authenticated session state and response/header overrides independently of
// their enclosing endpoint call; those still belong to the original input.
struct AuthorizationRequest<'a, R> {
    original: &'a R,
    call: alibi_core::endpoint::EndpointCall,
}
struct AuthorizationAdmission {
    query: serde_json::Map<String, Value>,
    validation: Result<AuthorizationParameters, (&'static str, String)>,
    nonfinite_values: std::collections::BTreeMap<String, JsValue>,
    reserved_error: Option<(&'static str, &'static str)>,
}
#[derive(Default)]
pub(super) struct AuthorizationSettings {
    pub initial: bool,
    pub post_login_cleared_for_session: Option<String>,
    /// The user returned from the post-login page through `/oauth2/continue`.
    pub post_login_continuation: bool,
}
impl<R: SessionRequest> SessionRequest for AuthorizationRequest<'_, R> {
    fn endpoint_call(&self) -> Option<&alibi_core::endpoint::EndpointCall> {
        Some(&self.call)
    }
    fn physical_request(&self) -> Option<&alibi_core::AuthRequest> {
        self.original.physical_request()
    }
    fn session_headers(&self) -> &std::collections::HashMap<String, String> {
        self.original.session_headers()
    }
    fn session_method(&self) -> &alibi_core::HttpMethod {
        self.original.session_method()
    }
    fn session_query_truthy(&self, name: &str) -> bool {
        self.call.session_query_truthy(name)
    }
    fn extensions(&self) -> &alibi_core::types::RequestExtensions {
        self.original.extensions()
    }
    fn virtual_session<S: AuthSchema>(
        &self,
        ctx: &AuthContext<S>,
    ) -> Option<alibi_core::SessionView> {
        self.original.virtual_session(ctx)
    }
    fn authenticated_user<S: AuthSchema>(&self, ctx: &AuthContext<S>) -> Option<S::User> {
        self.original.authenticated_user(ctx)
    }
    fn take_response_headers(&self) -> alibi_core::Headers {
        self.original.take_response_headers()
    }
    fn queue_response_header(&self, name: impl Into<String>, value: impl Into<String>) {
        self.original.queue_response_header(name, value);
    }
    fn set_session_hook_snapshot(
        &self,
        user: alibi_core::UserView,
        session: alibi_core::SessionView,
    ) {
        self.original.set_session_hook_snapshot(user, session);
    }
}
impl OAuthProviderPlugin {
    /// Authorize an OAuth request with its genuine physical request attached.
    pub fn oauth2_authorize_endpoint(
        query: &impl serde::Serialize,
    ) -> AuthResult<ServerEndpoint<Value>> {
        ServerEndpoint::new("oauth-provider", "oauth2Authorize").with_query(query)
    }
    pub(super) async fn authorize<S: AuthSchema>(
        &self,
        input: Option<JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        Box::pin(self.authorize_flow(
            input,
            req,
            ctx,
            AuthorizationSettings {
                initial: true,
                ..Default::default()
            },
        ))
        .await
    }
    pub(super) async fn authorize_flow<S: AuthSchema>(
        &self,
        mut input: Option<JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
        settings: AuthorizationSettings,
    ) -> AuthResult<EndpointResponse> {
        if !self
            .config
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        {
            return Ok(EndpointResponse::error(AuthError::Api {
                status: 404,
                code: None,
                message: String::new(),
            })
            .without_error_body()
            .with_header("Content-Type", "application/json"));
        }
        if req.physical_request().is_none() {
            return super::clients::status_protocol_error(
                401,
                "invalid_request",
                "request not found",
            );
        }
        // Reserved request controls belong only to the original input. A
        // resolver replaces the parameters once; its result is never resolved
        // recursively or subjected to the original request-object dispatch.
        let string = |name: &str| {
            input
                .as_ref()
                .and_then(|value| value.get(name))
                .and_then(JsValue::as_str)
        };
        let request_error = match (string("request"), string("request_uri")) {
            (Some(_), Some(_)) => Some((
                "invalid_request",
                "request and request_uri cannot be used together",
            )),
            (Some(_), None) => Some(("request_not_supported", "request object not supported")),
            (None, Some(uri)) => {
                match (
                    string("client_id").filter(|id| !id.is_empty()),
                    &self.config.request_uri_resolver,
                ) {
                    (None, _) => Some(("invalid_request", "client_id is required")),
                    (Some(_), None) => {
                        Some(("request_uri_not_supported", "request_uri not supported"))
                    }
                    (Some(client_id), Some(resolver)) => {
                        let context = alibi_core::CallbackContext::new(ctx, req.physical_request());
                        let resolved = resolver
                            .resolve(super::OAuthRequestUriInput {
                                request_uri: uri,
                                client_id,
                                context: &context,
                            })
                            .await
                            .map_err(|error| {
                                if alibi_core::endpoint::is_endpoint_api_error(&error) {
                                    error
                                } else {
                                    AuthError::CallbackFailure(Box::new(error))
                                }
                            })?;
                        if let Some(mut parameters) = resolved {
                            _ = parameters
                                .insert("client_id".into(), JsValue::String(client_id.into()));
                            input = Some(JsValue::Object(parameters));
                            None
                        } else {
                            Some(("invalid_request_uri", "request_uri is invalid or expired"))
                        }
                    }
                }
            }
            (None, None) => None,
        };
        // Clone the actual logical call, sharing its session/output state and
        // retaining the distinct physical Request. Discovery and other native
        // callbacks must observe the effective input, not the caller's query.
        if let Some(call) = alibi_core::endpoint::current_endpoint_call_context() {
            let effective = AuthorizationRequest {
                original: req,
                call: call.handler_context(call.body().cloned(), input.clone()),
            };
            return alibi_core::endpoint::with_endpoint_call_context(
                effective.call.clone(),
                Box::pin(self.authorize_parameters(
                    input,
                    &effective,
                    ctx,
                    settings,
                    request_error,
                )),
            )
            .await;
        }
        Box::pin(self.authorize_parameters(input, req, ctx, settings, request_error)).await
    }
    async fn authorize_parameters<S: AuthSchema>(
        &self,
        input: Option<JsValue>,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
        settings: AuthorizationSettings,
        reserved_error: Option<(&'static str, &'static str)>,
    ) -> AuthResult<EndpointResponse> {
        let validated_max_age = maximum_age(input.as_ref().and_then(|input| input.get("max_age")));
        let nonfinite_values = nonfinite_query_values(input.as_ref());
        let mut logical_query = input
            .clone()
            .unwrap_or_else(|| JsValue::Object(super::OAuthAuthorizationQuery::new()));
        let mut query: serde_json::Map<String, Value> = input
            .and_then(|value| alibi_core::utils::json::from_value(value).ok())
            .unwrap_or_default();
        let validation = authorization_parameters(&query, validated_max_age);
        // Failed schemas and unsupported request objects redirect using their raw
        // parameters. Only a fully parsed query publishes URL transformations.
        if reserved_error.is_none()
            && let Ok(parameters) = &validation
            && let Some(redirect) = &parameters.redirect_uri
        {
            _ = query.insert("redirect_uri".into(), json!(redirect));
            if let JsValue::Object(fields) = &mut logical_query {
                _ = fields.insert("redirect_uri".into(), JsValue::String(redirect.clone()));
            }
        }
        let logical = alibi_core::endpoint::current_endpoint_call_context()
            .map(|call| call.handler_context(call.body().cloned(), Some(logical_query)));
        let run = Box::pin(self.authorize_admission(
            AuthorizationAdmission {
                query,
                validation,
                nonfinite_values,
                reserved_error,
            },
            req,
            ctx,
            settings,
        ));
        if let Some(logical) = logical {
            alibi_core::endpoint::with_endpoint_call_context(logical, run).await
        } else {
            run.await
        }
    }
    async fn authorize_admission<S: AuthSchema>(
        &self,
        input: AuthorizationAdmission,
        req: &impl SessionRequest,
        ctx: &AuthContext<S>,
        settings: AuthorizationSettings,
    ) -> AuthResult<EndpointResponse> {
        let AuthorizationAdmission {
            mut query,
            validation,
            nonfinite_values,
            reserved_error,
        } = input;
        let error_mode = authorization_error_mode(&query);
        let text = |name: &str| {
            query
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let client_id = text("client_id");
        let redirect_uri = text("redirect_uri");
        let response_type = text("response_type");
        let state = text("state");
        let server_error = format!(
            "{}{}/error",
            ctx.config.base_url.trim_end_matches('/'),
            ctx.config.base_path
        );
        if reserved_error.is_none()
            && response_type == "code"
            && validation.as_ref().is_ok_and(|parameters| {
                parameters
                    .prompts
                    .contains(&AuthorizationPrompt::SelectAccount)
            })
            && self.select_account_page().is_none_or(str::is_empty)
        {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "unsupported_prompt_select_account",
                    "unsupported prompt type",
                    None,
                    None,
                )?,
            );
        }
        let error_only =
            reserved_error.is_some() || validation.is_err() || response_type.is_empty();
        let client = if error_only {
            if client_id.is_empty() || redirect_uri.is_empty() {
                None
            } else {
                super::discovery::resolve(ctx, &client_id)
                    .await
                    .unwrap_or(None)
            }
        } else {
            super::discovery::resolve(ctx, &client_id).await?
        };
        let authorization_code_allowed = client.as_ref().is_some_and(|client| {
            client
                .metadata
                .get("grant_types")
                .and_then(Value::as_array)
                .is_some_and(|grants| grants.contains(&json!("authorization_code")))
        });
        // Early request/schema errors can trust an enabled client without grant
        // admission. Valid requests reach the operator only after that admission.
        // Keep one decision for both the error channel and eventual code binding.
        let trusted = if let Some(client) = client.as_ref().filter(|client| {
            client.metadata.get("disabled") != Some(&json!(true))
                && (error_only || authorization_code_allowed)
        }) {
            self.authorization_redirect_is_trusted(&client.metadata, &redirect_uri)
                .await?
        } else {
            false
        };
        let issuer = self
            .metadata(ctx)?
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let admission_error = |error: &str, description: &str| {
            let target = if trusted {
                redirect_uri.as_str()
            } else {
                server_error.as_str()
            };
            let url = error_url(
                target,
                error,
                description,
                if trusted { Some(state.as_str()) } else { None },
                if trusted { Some(issuer.as_str()) } else { None },
            )?;
            browser_redirect(req, &url)
        };
        let request_error = |error: &str, description: &str| {
            if trusted && error_mode == AuthorizationErrorMode::Fragment {
                browser_redirect(
                    req,
                    &fragment_error_url(
                        &redirect_uri,
                        error,
                        description,
                        Some(&state),
                        Some(&issuer),
                    ),
                )
            } else {
                admission_error(error, description)
            }
        };
        if let Some((error, description)) = reserved_error {
            return request_error(error, description);
        }
        let parameters = match validation {
            Ok(parameters) => parameters,
            Err((error, description)) => return request_error(error, &description),
        };
        if response_type.is_empty() {
            return request_error("invalid_request", "response_type is required");
        }
        let prompts = parameters.prompts;
        let max_age = parameters.max_age;
        let Some(client) = client else {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "invalid_client",
                    "client not found",
                    None,
                    None,
                )?,
            );
        };
        if client.metadata.get("disabled") == Some(&json!(true)) {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "client_disabled",
                    "client is disabled",
                    None,
                    None,
                )?,
            );
        }
        if !authorization_code_allowed {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "unauthorized_client",
                    "client is not authorized to use the authorization_code grant",
                    None,
                    None,
                )?,
            );
        }
        if !trusted {
            return browser_redirect(
                req,
                &error_url(
                    &server_error,
                    "invalid_redirect",
                    "invalid redirect uri",
                    None,
                    None,
                )?,
            );
        }
        let allowed = client
            .metadata
            .get("scope")
            .and_then(Value::as_str)
            .map_or_else(
                || self.config.scopes.clone(),
                |scope| scope.split(' ').map(str::to_owned).collect(),
            );
        let scope = query
            .get("scope")
            .and_then(Value::as_str)
            .map_or_else(|| allowed.join(" "), str::to_owned);
        let requested = scope
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .collect::<Vec<_>>();
        let invalid = requested
            .iter()
            .filter(|scope| !allowed.iter().any(|allowed| allowed == **scope))
            .copied()
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return admission_error(
                "invalid_scope",
                &format!("The following scopes are invalid: {}", invalid.join(", ")),
            );
        }
        let requested_user_info_claims = if let Some(claims) = query.get("claims") {
            if !requested.contains(&"openid") {
                return admission_error(
                    "invalid_request",
                    "openid scope must be requested when using the claims parameter",
                );
            }
            let Some(claims) = super::claims_request::parse(claims) else {
                return admission_error(
                    "invalid_request",
                    "claims must be a valid Claims request object",
                );
            };
            if !claims.acr_satisfied {
                return admission_error("access_denied", "essential acr requirement cannot be met");
            }
            let supported = self.supported_claims();
            claims
                .user_info
                .into_iter()
                .filter(|name| supported.contains(name))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if let Err(error) = self
            .admit_resources(ctx, &client_id, &requested, query.get("resource"))
            .await
        {
            if let Some(body) = error.body {
                let body = body.to_json_value()?;
                return admission_error(
                    body.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("server_error"),
                    body.get("error_description")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
            }
            return Err(error.error);
        }
        let challenge = text("code_challenge");
        let method = text("code_challenge_method");
        let public = client
            .metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            == Some("none");
        let nonce = text("nonce");
        let pkce = if public {
            Some("pkce is required for public clients")
        } else if requested.contains(&"offline_access")
            && (!requested.contains(&"openid") || nonce.is_empty())
        {
            Some("pkce or OIDC nonce is required when requesting offline_access scope")
        } else if client.metadata.get("require_pkce") != Some(&json!(false)) {
            Some("pkce is required for this client")
        } else {
            None
        };
        if let Some(reason) = pkce
            && (challenge.is_empty() || method.is_empty())
        {
            return admission_error("invalid_request", reason);
        }
        if challenge.is_empty() != method.is_empty() {
            return admission_error(
                "invalid_request",
                "code_challenge and code_challenge_method must both be provided",
            );
        }
        let session = Box::pin(ctx.require_cached_session(req)).await.ok();

        let within_max_age = if let (Some((_, session)), Some(age)) = (&session, max_age) {
            let elapsed = json!(
                chrono::Utc::now().timestamp_millis() - session.created_at.timestamp_millis()
            )
            .as_f64()
            .ok_or_else(|| AuthError::internal("Invalid session authentication time"))?;
            age > 0.0 && elapsed <= age * 1000.0
        } else {
            false
        };
        let force_login = session.is_none()
            || max_age.is_some() && !within_max_age
            || prompts.contains(&AuthorizationPrompt::Login)
            || prompts.contains(&AuthorizationPrompt::Create);
        if let Some(age) = max_age {
            if !force_login && within_max_age {
                _ = query.remove("max_age");
            } else {
                _ = query.insert("max_age".into(), json!(age));
            }
        }
        _ = query.insert("scope".into(), json!(scope));
        if !force_login
            && settings.initial
            && prompts.contains(&AuthorizationPrompt::SelectAccount)
            && let Some(page) = self.select_account_page()
        {
            let params = self.sign_authorization_query(query, &nonfinite_values, None, ctx)?;
            return browser_redirect(req, &format!("{page}?{params}"));
        }
        if !force_login
            && settings.initial
            && let Some(selection) = &self.config.select_account
            && let Some((user, session)) = &session
        {
            let user = ctx.user_view(user);
            let scopes = requested
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>();
            if selection
                .should_redirect
                .should_redirect(super::OAuthInteractionContext {
                    headers: &req
                        .physical_request()
                        .ok_or_else(|| AuthError::internal("request not found"))?
                        .headers,
                    user: &user,
                    session,
                    scopes: &scopes,
                })
                .await
                .map_err(|error| {
                    if alibi_core::endpoint::is_endpoint_api_error(&error) {
                        error
                    } else {
                        AuthError::CallbackFailure(Box::new(error))
                    }
                })?
            {
                if prompts.contains(&AuthorizationPrompt::None) {
                    return admission_error(
                        "account_selection_required",
                        "End-User account selection is required",
                    );
                }
                let page = self
                    .select_account_page()
                    .unwrap_or(&self.config.login_page);
                let params = self.sign_authorization_query(query, &nonfinite_values, None, ctx)?;
                return browser_redirect(req, &format!("{page}?{params}"));
            }
        }
        if !force_login
            && let Some(policy) = self
                .config
                .signup
                .as_ref()
                .and_then(|signup| signup.should_redirect.as_ref())
            && let Some((user, session)) = &session
        {
            let user = ctx.user_view(user);
            let scopes = requested
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>();
            let decision = policy
                .should_redirect(super::OAuthSignupContext {
                    // authorize_flow has already required a physical request.
                    headers: &req
                        .physical_request()
                        .ok_or_else(|| AuthError::internal("request not found"))?
                        .headers,
                    user: &user,
                    session,
                    scopes: &scopes,
                })
                .await
                .map_err(|error| {
                    if alibi_core::endpoint::is_endpoint_api_error(&error) {
                        error
                    } else {
                        AuthError::CallbackFailure(Box::new(error))
                    }
                })?;
            let page = match decision {
                super::OAuthSignupRedirect::Continue => None,
                super::OAuthSignupRedirect::Page(page) if page.is_empty() => None,
                super::OAuthSignupRedirect::Page(page) => Some(page),
                super::OAuthSignupRedirect::ConfiguredPage => Some(self.signup_page().to_owned()),
            };
            if let Some(page) = page {
                if prompts.contains(&AuthorizationPrompt::None) {
                    return admission_error(
                        "interaction_required",
                        "End-User interaction is required",
                    );
                }
                let params = self.sign_authorization_query(query, &nonfinite_values, None, ctx)?;
                return browser_redirect(req, &format!("{page}?{params}"));
            }
        }
        if !force_login
            && let Some(post_login) = &self.config.post_login
            && let Some((user, session)) = &session
            && settings.post_login_cleared_for_session.as_deref() != Some(session.id.as_str())
        {
            let user = ctx.user_view(user);
            let scopes = requested
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>();
            if post_login
                .should_redirect
                .should_redirect(super::OAuthPostLoginContext {
                    headers: &req
                        .physical_request()
                        .ok_or_else(|| AuthError::internal("request not found"))?
                        .headers,
                    user: &user,
                    session,
                    scopes: &scopes,
                    is_continuation: settings.post_login_continuation,
                })
                .await
                .map_err(|error| {
                    if alibi_core::endpoint::is_endpoint_api_error(&error) {
                        error
                    } else {
                        AuthError::CallbackFailure(Box::new(error))
                    }
                })?
            {
                if prompts.contains(&AuthorizationPrompt::None) {
                    return admission_error(
                        "interaction_required",
                        "End-User interaction is required",
                    );
                }
                if post_login.page.is_empty() {
                    return Ok(EndpointResponse::error(AuthError::Api {
                        status: 500,
                        code: None,
                        message: String::new(),
                    })
                    .with_error_body(JsValue::from(
                        json!({"error_description":"postLogin should have been defined"}),
                    )));
                }
                let params = self.sign_authorization_query(query, &nonfinite_values, None, ctx)?;
                return browser_redirect(req, &format!("{}?{params}", post_login.page));
            }
        }
        let reference_id = if !force_login
            && !prompts.contains(&AuthorizationPrompt::Consent)
            && let Some((user, session)) = &session
        {
            let scopes = requested
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>();
            self.consent_reference_id(&ctx.user_view(user), session, &scopes)
                .await?
        } else {
            None
        };
        let remembered = if !force_login
            && !prompts.contains(&AuthorizationPrompt::Consent)
            && client.metadata.get("skip_consent") != Some(&json!(true))
            && let Some((user, _)) = &session
        {
            let requested_resources = super::resource_policy::resource_list(query.get("resource"));
            ctx.database
                .list_oauth_consents_by_user(user.id().as_ref())
                .await?
                .into_iter()
                .find(|consent| {
                    consent.client_id == client_id
                        && super::post_login::consent_matches_reference(&consent.metadata, reference_id.as_deref())
                })
                .is_some_and(|consent| {
                    requested_user_info_claims.iter().all(|name| {
                        consent
                            .metadata
                            .get("requestedUserInfoClaims")
                            .and_then(Value::as_array)
                            .is_some_and(|names| {
                                names.iter().any(|value| value.as_str() == Some(name))
                            })
                    }) && scope.split(' ').all(|scope| {
                        consent
                            .metadata
                            .get("scopes")
                            .and_then(Value::as_array)
                            .is_some_and(|scopes| {
                                scopes.iter().any(|value| value.as_str() == Some(scope))
                            })
                    }) && requested_resources.iter().all(|resource| {
                        consent
                            .metadata
                            .get("resources")
                            .and_then(Value::as_array)
                            .is_some_and(|resources| {
                                resources
                                    .iter()
                                    .any(|value| value.as_str() == Some(resource))
                            })
                    })
                })
        } else {
            false
        };
        if !force_login
            && !prompts.contains(&AuthorizationPrompt::Consent)
            && (client.metadata.get("skip_consent") == Some(&json!(true)) || remembered)
            && let Some((user, session)) = &session
        {
            let code = rand::RngExt::sample_iter(rand::rng(), rand::distr::Alphanumeric)
                .map(char::from)
                .take(32)
                .collect::<String>();
            let now = chrono::Utc::now().timestamp();
            let created = chrono::DateTime::from_timestamp(now, 0)
                .ok_or_else(|| AuthError::internal("Invalid authorization code issue time"))?;
            let seconds = json!(now)
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid authorization code issue time"))?;
            let expires_ms = ((seconds + self.config.code_expires_in) * 1000.0)
                .trunc()
                .to_string()
                .parse::<i64>()
                .map_err(|_| AuthError::internal("Invalid authorization code expiration"))?;
            let expires = chrono::DateTime::from_timestamp_millis(expires_ms)
                .ok_or_else(|| AuthError::internal("Invalid authorization code expiration"))?;
            let identifier = self.hash_token(&code, "authorization_code").await?;
            let resources = query.get("resource").map_or_else(Vec::new, |value| {
                value
                    .as_array()
                    .cloned()
                    .unwrap_or_else(|| vec![value.clone()])
            });
            let mut value = json!({"type":"authorization_code","query":query,"userId":user.id().as_ref(),"sessionId":session.id,"authTime":session.created_at.timestamp_millis(),"resource":resources});
            if let Some(reference_id) = reference_id {
                _ = value
                    .as_object_mut()
                    .ok_or_else(|| AuthError::internal("Invalid authorization code payload"))?
                    .insert("referenceId".into(), json!(reference_id));
            }
            let value = serde_json::to_string(&value)?;
            _ = ctx
                .verifications()
                .create(alibi_core::verification::VerificationCreation {
                    id: None,
                    identifier,
                    value,
                    expires_at: expires,
                    created_at: created,
                    updated_at: created,
                })
                .await?;
            let mut target = url::Url::parse(&redirect_uri)
                .map_err(|error| AuthError::internal(error.to_string()))?;
            let mut pairs = target
                .query_pairs()
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            for (name, value) in [
                ("code", code.as_str()),
                ("state", state.as_str()),
                ("iss", issuer.as_str()),
            ] {
                if name == "state" && value.is_empty() {
                    continue;
                }
                // URLSearchParams.set replaces the first occurrence in place
                // and removes later duplicates, retaining unrelated entries.
                let mut replaced = false;
                pairs.retain_mut(|(key, previous)| {
                    if key.as_str() != name {
                        return true;
                    }
                    if replaced {
                        return false;
                    }
                    *previous = value.into();
                    replaced = true;
                    true
                });
                if !replaced {
                    pairs.push((name.into(), value.into()));
                }
            }
            _ = target.query_pairs_mut().clear().extend_pairs(pairs);
            return browser_redirect(req, target.as_str());
        }
        if prompts.contains(&AuthorizationPrompt::None) {
            return admission_error(
                if force_login {
                    "login_required"
                } else {
                    "consent_required"
                },
                if force_login {
                    "authentication required"
                } else {
                    "End-User consent is required"
                },
            );
        }
        let page = if force_login {
            if prompts.contains(&AuthorizationPrompt::Create) {
                self.signup_page()
            } else {
                &self.config.login_page
            }
        } else {
            &self.config.consent_page
        };
        let cleared_session = if !force_login && self.config.post_login.is_some() {
            session.as_ref().map(|(_, session)| session.id.as_str())
        } else {
            None
        };
        let params =
            self.sign_authorization_query(query, &nonfinite_values, cleared_session, ctx)?;
        browser_redirect(req, &format!("{page}?{params}"))
    }
    fn signup_page(&self) -> &str {
        self.config
            .signup
            .as_ref()
            .and_then(|signup| signup.page.as_deref())
            .unwrap_or(&self.config.login_page)
    }
    fn select_account_page(&self) -> Option<&str> {
        self.config
            .select_account
            .as_ref()
            .and_then(|selection| selection.page.as_deref())
            .or(self.config.select_account_page.as_deref())
    }
    async fn authorization_redirect_is_trusted(
        &self,
        metadata: &Value,
        requested: &str,
    ) -> AuthResult<bool> {
        let default_result = registered_redirect(metadata, requested);
        let Some(policy) = &self.config.validate_redirect_uri else {
            return Ok(default_result);
        };
        // SafeUrlSchema validates a JS-trimmed value, but the subsequent URL
        // constructor and the operator still receive the original parameter.
        if !super::clients::safe_uri_issues(alibi_core::utils::javascript::trim(requested))
            .is_empty()
        {
            return Ok(false);
        }
        let parsed = url::Url::parse(requested).map_err(|error| {
            AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
        })?;
        if !parsed.username().is_empty()
            || parsed
                .password()
                .is_some_and(|password| !password.is_empty())
        {
            return Ok(false);
        }
        let registered = metadata
            .get("redirect_uris")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        // Only callback failures deny trust. Raw URL constructor errors above
        // remain ordinary empty-500 failures, matching the reference boundary.
        Ok(policy
            .validate(requested, &registered, default_result)
            .await
            .unwrap_or(false))
    }
    fn sign_authorization_query<S: AuthSchema>(
        &self,
        query: serde_json::Map<String, Value>,
        nonfinite_values: &std::collections::BTreeMap<String, JsValue>,
        post_login_cleared_for_session: Option<&str>,
        ctx: &AuthContext<S>,
    ) -> AuthResult<String> {
        let now = chrono::Utc::now().timestamp_millis();
        let seconds = json!(now / 1000)
            .as_f64()
            .ok_or_else(|| AuthError::internal("Invalid authorization timestamp"))?;
        let mut pairs = Vec::new();
        for (name, value) in query {
            if ["sig", "exp", "ba_iat", "ba_param", "ba_pl"].contains(&name.as_str()) {
                continue;
            }
            // Grant JSON follows JSON.stringify's null projection. Browser
            // interactions instead preserve String(Infinity/NaN), including arrays.
            if let Some(value) = nonfinite_values.get(&name) {
                if let JsValue::Array(values) = value {
                    for value in values {
                        pairs.push((name.clone(), js_parameter_text(value)?));
                    }
                } else {
                    pairs.push((name, js_parameter_text(value)?));
                }
                continue;
            }
            match value {
                Value::Null => {}
                Value::Array(values) => {
                    for value in values {
                        pairs.push((name.clone(), parameter_text(&value)?));
                    }
                }
                value if name == "claims" && value.is_object() => {
                    pairs.push((name, alibi_core::utils::json::to_string(&value)?));
                }
                value => pairs.push((name, parameter_text(&value)?)),
            }
        }
        pairs.push((
            "exp".into(),
            (seconds + self.config.code_expires_in).to_string(),
        ));
        pairs.push(("ba_iat".into(), now.to_string()));
        if let Some(session_id) = post_login_cleared_for_session {
            pairs.push(("ba_pl".into(), session_id.into()));
        }
        let mut names = pairs
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        names.push("ba_param".into());
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        names.dedup();
        for name in names {
            pairs.push(("ba_param".into(), name));
        }
        let mut canonical = pairs.clone();
        canonical.sort_by(|(a, av), (b, bv)| {
            a.encode_utf16()
                .cmp(b.encode_utf16())
                .then_with(|| av.encode_utf16().cmp(bv.encode_utf16()))
        });
        let mut mac = Hmac::<Sha256>::new_from_slice(ctx.config.current_secret().as_bytes())
            .map_err(|_| AuthError::internal("Invalid authorization signing key"))?;
        mac.update(encode_pairs(&canonical).as_bytes());
        let signature =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        pairs.push(("sig".into(), signature));
        Ok(encode_pairs(&pairs))
    }
}
fn parameter_text(value: &Value) -> AuthResult<String> {
    js_parameter_text(&JsValue::from(value.clone()))
}

fn js_parameter_text(value: &JsValue) -> AuthResult<String> {
    value
        .coerce_string()
        .map_err(|message| AuthError::CallbackFailure(Box::new(AuthError::internal(message))))
}

fn nonfinite_query_values(input: Option<&JsValue>) -> std::collections::BTreeMap<String, JsValue> {
    let Some(values) = input.and_then(JsValue::as_object) else {
        return std::collections::BTreeMap::default();
    };
    values
        .iter()
        .filter(|(_, value)| has_nonfinite_array_value(value))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

// String(object) is unaffected by JSON's non-finite number projection; scalar
// and array coercion is not. Traverse arrays without adding recursive stack use.
fn has_nonfinite_array_value(value: &JsValue) -> bool {
    let mut pending = match value {
        JsValue::Number(number) => return !number.is_finite(),
        JsValue::Array(values) => values.iter().collect::<Vec<_>>(),
        _ => return false,
    };
    while let Some(value) = pending.pop() {
        match value {
            JsValue::Number(number) if !number.is_finite() => return true,
            JsValue::Array(values) => pending.extend(values.iter()),
            _ => {}
        }
    }
    false
}
#[derive(PartialEq, Eq)]
enum AuthorizationErrorMode {
    Query,
    Fragment,
}

fn authorization_error_mode(query: &serde_json::Map<String, Value>) -> AuthorizationErrorMode {
    match query.get("response_mode").and_then(Value::as_str) {
        Some("fragment") => AuthorizationErrorMode::Fragment,
        Some("query") => AuthorizationErrorMode::Query,
        _ => {
            let implicit = query
                .get("response_type")
                .and_then(Value::as_str)
                .is_some_and(|response_type| {
                    response_type
                        .split(|character: char| {
                            !character.is_ascii_alphanumeric() && character != '_'
                        })
                        .any(|word| matches!(word, "token" | "id_token"))
                });
            if implicit {
                AuthorizationErrorMode::Fragment
            } else {
                AuthorizationErrorMode::Query
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum AuthorizationPrompt {
    None,
    Consent,
    Login,
    Create,
    SelectAccount,
}

#[derive(Default)]
struct AuthorizationParameters {
    prompts: Vec<AuthorizationPrompt>,
    max_age: Option<f64>,
    redirect_uri: Option<String>,
}

fn authorization_parameters(
    query: &serde_json::Map<String, Value>,
    max_age: Result<Option<f64>, &'static str>,
) -> Result<AuthorizationParameters, (&'static str, String)> {
    let mut parameters = AuthorizationParameters::default();
    let invalid = |description: String| ("invalid_request", description);
    // Schema declaration order determines the first published issue, regardless
    // of caller key order. Optional fields are validated before provider policy.
    for name in [
        "response_type",
        "request",
        "request_uri",
        "redirect_uri",
        "scope",
        "state",
        "client_id",
        "prompt",
        "display",
        "ui_locales",
        "max_age",
        "acr_values",
        "login_hint",
        "id_token_hint",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "claims",
        "dpop_jkt",
        "resource",
    ] {
        let Some(value) = query.get(name) else {
            if name == "client_id" {
                return Err(invalid("client_id is required".into()));
            }
            continue;
        };
        match name {
            "max_age" => {
                parameters.max_age = max_age.map_err(|description| invalid(description.into()))?;
                continue;
            }
            "claims" => {
                if !value.is_string() && !value.is_object() {
                    return Err(invalid("claims: Invalid input".into()));
                }
                continue;
            }
            "resource" => {
                if let Some(description) = authorization_resource_error(Some(value)) {
                    return Err(invalid(description));
                }
                continue;
            }
            _ => {}
        }
        let Some(text) = value.as_str() else {
            return Err(invalid(if value.is_array() {
                format!("{name} must not appear more than once")
            } else {
                format!("{name} must be a string")
            }));
        };
        match name {
            "response_type" if text != "code" => {
                return Err((
                    "unsupported_response_type",
                    "response_type must be one of: code".into(),
                ));
            }
            "redirect_uri" => {
                let text = alibi_core::utils::javascript::trim(text);
                if let Some(issue) = super::clients::safe_uri_issues(text).into_iter().next() {
                    return Err(invalid(format!("redirect_uri: {issue}")));
                }
                parameters.redirect_uri = Some(text.into());
            }
            "client_id" if text.is_empty() => {
                return Err(invalid("client_id: client_id is required".into()));
            }
            "prompt" => parameters.prompts = authorization_prompts(Some(text)).map_err(invalid)?,
            "code_challenge_method" if text != "S256" => {
                return Err(invalid("code_challenge_method must be one of: S256".into()));
            }
            "dpop_jkt"
                if text.len() != 43
                    || !text.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                    }) =>
            {
                return Err(invalid(
                    "dpop_jkt: dpop_jkt must be a base64url-encoded SHA-256 JWK thumbprint".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(parameters)
}

fn authorization_prompts(input: Option<&str>) -> Result<Vec<AuthorizationPrompt>, String> {
    let Some(input) = input else {
        return Ok(Vec::new());
    };
    let mut prompts = Vec::new();
    for token in input
        .split(' ')
        .map(alibi_core::utils::javascript::trim)
        .filter(|token| !token.is_empty())
    {
        let prompt = match token {
            "none" => AuthorizationPrompt::None,
            "consent" => AuthorizationPrompt::Consent,
            "login" => AuthorizationPrompt::Login,
            "create" => AuthorizationPrompt::Create,
            "select_account" => AuthorizationPrompt::SelectAccount,
            _ => return Err(format!("prompt: unsupported prompt value: {token}")),
        };
        if !prompts.contains(&prompt) {
            prompts.push(prompt);
        }
    }
    if prompts.is_empty() {
        return Err("prompt: prompt must include at least one value".into());
    }
    if prompts.contains(&AuthorizationPrompt::None) && prompts.len() > 1 {
        return Err("prompt: prompt=none cannot be combined with other prompt values".into());
    }
    Ok(prompts)
}

fn maximum_age(input: Option<&JsValue>) -> Result<Option<f64>, &'static str> {
    let Some(input) = input else { return Ok(None) };
    let value = match input {
        JsValue::Number(value) if value.is_finite() => *value,
        JsValue::String(value) => {
            let value = alibi_core::utils::javascript::trim(value);
            if value.is_empty() {
                return Err("max_age: Too small: expected string to have >=1 characters");
            }
            alibi_core::utils::javascript::string_to_number(value).unwrap_or(f64::NAN)
        }
        _ => return Err("max_age: Invalid input"),
    };
    if !value.is_finite() || value < 0.0 || value.fract() > 0.0 {
        return Err("max_age: max_age must be a non-negative integer");
    }
    Ok(Some(value))
}

fn authorization_resource_error(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let values = match value {
        Value::String(_) => vec![value],
        Value::Array(values) if values.is_empty() => {
            return Some("resource: Too small: expected array to have >=1 items".into());
        }
        Value::Array(values) => values.iter().collect(),
        _ => return Some("resource: Invalid input".into()),
    };
    // A type or absolute-URI failure aborts the union branch, even if another
    // array entry has a non-fatal fragment/scheme issue.
    let Some(parsed) = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(|text| url::Url::parse(text).ok().map(|uri| (text, uri)))
        })
        .collect::<Option<Vec<_>>>()
    else {
        return Some("resource: Invalid input".into());
    };
    for (index, (text, uri)) in parsed.iter().enumerate() {
        let description = if text.contains('#') {
            "resource must not contain a fragment"
        } else if ["javascript", "data", "vbscript"].contains(&uri.scheme()) {
            "resource cannot use javascript:, data:, or vbscript: scheme"
        } else {
            continue;
        };
        let field = if value.is_array() {
            format!("resource[{index}]")
        } else {
            "resource".into()
        };
        return Some(format!("{field}: {description}"));
    }
    None
}
fn encode_pairs(pairs: &[(String, String)]) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        _ = encoded.append_pair(name, value);
    }
    encoded.finish()
}
fn registered_redirect(metadata: &Value, requested: &str) -> bool {
    let Ok(parsed) = url::Url::parse(requested) else {
        return false;
    };
    if requested.contains('#')
        || !parsed.username().is_empty()
        || parsed
            .password()
            .is_some_and(|password| !password.is_empty())
    {
        return false;
    }
    let requested_without_port = loopback_without_port(requested);
    metadata
        .get("redirect_uris")
        .and_then(Value::as_array)
        .is_some_and(|uris| {
            uris.iter().filter_map(Value::as_str).any(|uri| {
                uri == requested
                    || requested_without_port.as_ref().is_some_and(|requested| {
                        loopback_without_port(uri).as_ref() == Some(requested)
                    })
            })
        })
}

/// Native HTTP callbacks may change their port, not any other raw URI byte.
fn loopback_without_port(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    let host = parsed.host_str()?.trim_matches(['[', ']']);
    let loopback = host == "localhost"
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
            std::net::IpAddr::V4(ip) => ip.is_loopback(),
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
            }
        });
    if parsed.scheme() != "http" || !loopback {
        return None;
    }
    let start = uri.find("://")? + 3;
    let end = start
        + uri
            .get(start..)?
            .find(['/', '?', '#'])
            .unwrap_or(uri.len() - start);
    let authority = uri.get(start..end)?;
    let port_start = if authority.starts_with('[') {
        let bracket = authority.find(']')?;
        if authority.as_bytes().get(bracket + 1) != Some(&b':') {
            return Some(uri.into());
        }
        bracket + 1
    } else if let Some(colon) = authority.rfind(':') {
        colon
    } else {
        return Some(uri.into());
    };
    if !authority
        .get(port_start + 1..)?
        .bytes()
        .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(format!(
        "{}{}",
        uri.get(..start + port_start)?,
        uri.get(end..)?
    ))
}
fn fragment_error_url(
    target: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    issuer: Option<&str>,
) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    _ = params.append_pair("error", error);
    _ = params.append_pair("error_description", description);
    if let Some(state) = state.filter(|state| !state.is_empty()) {
        _ = params.append_pair("state", state);
    }
    if let Some(issuer) = issuer.filter(|issuer| !issuer.is_empty()) {
        _ = params.append_pair("iss", issuer);
    }
    format!("{target}#{}", params.finish())
}

fn error_url(
    target: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
    issuer: Option<&str>,
) -> AuthResult<String> {
    let mut url =
        url::Url::parse(target).map_err(|error| AuthError::internal(error.to_string()))?;
    {
        let mut params = url.query_pairs_mut();
        _ = params.append_pair("error", error);
        _ = params.append_pair("error_description", description);
        if let Some(state) = state.filter(|state| !state.is_empty()) {
            _ = params.append_pair("state", state);
        }
        if let Some(issuer) = issuer {
            _ = params.append_pair("iss", issuer);
        }
    }
    Ok(url.into())
}
fn browser_redirect(req: &impl SessionRequest, target: &str) -> AuthResult<EndpointResponse> {
    let json = req.session_headers().iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("accept") && value.contains("application/json")
    });
    let fetch = req.physical_request().is_some_and(|request| {
        request
            .header("sec-fetch-mode")
            .is_some_and(|value| value == "cors")
    });
    if json || fetch {
        EndpointResponse::json(&json!({"redirect":true,"url":target}))
    } else {
        Ok(EndpointResponse::redirect(target).with_header("Content-Type", "application/json"))
    }
}

pub(super) fn verify_authorization_query(query: &str, secret: &str) -> AuthResult<bool> {
    let pairs = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();
    let signatures = pairs.iter().filter(|(k, _)| k == "sig").collect::<Vec<_>>();
    let [(_, signature_text)] = signatures.as_slice() else {
        return Ok(false);
    };
    if signature_text.is_empty() {
        return Ok(false);
    }
    let Some(exp) = pairs
        .iter()
        .find(|(k, _)| k == "exp")
        .and_then(|(_, v)| v.parse::<f64>().ok())
    else {
        return Ok(false);
    };
    if !exp.is_finite()
        || exp * 1000.0
            < json!(chrono::Utc::now().timestamp_millis())
                .as_f64()
                .ok_or_else(|| AuthError::internal("Invalid authorization timestamp"))?
    {
        return Ok(false);
    }
    let mut canonical = pairs
        .iter()
        .filter(|(k, _)| k != "sig")
        .cloned()
        .collect::<Vec<_>>();
    canonical.sort_by(|(a, av), (b, bv)| {
        a.encode_utf16()
            .cmp(b.encode_utf16())
            .then_with(|| av.encode_utf16().cmp(bv.encode_utf16()))
    });
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| AuthError::internal("Invalid authorization signing key"))?;
    mac.update(encode_pairs(&canonical).as_bytes());
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(signature_text) else {
        return Ok(false);
    };
    if base64::engine::general_purpose::STANDARD.encode(&signature) != *signature_text {
        return Ok(false);
    }
    Ok(mac.verify_slice(&signature).is_ok())
}
