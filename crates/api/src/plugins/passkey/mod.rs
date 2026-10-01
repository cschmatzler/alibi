use better_auth_core::{AuthContext, AuthError, AuthResult};
use better_auth_core::{AuthRequest, AuthResponse};

use better_auth_core::utils::cookie_utils::create_session_cookie;

mod authentication;
pub use authentication::{
    AuthenticationResult, PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, VerifiedPasskeyAuthentication,
};
pub(super) mod handlers;
mod registration;
pub(super) mod types;
pub(super) mod webauthn;
pub use registration::{
    PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyUserResolver,
    VerifiedPasskeyRegistration,
};

#[cfg(test)]
mod tests;

use handlers::*;
use types::*;

/// Passkey / WebAuthn authentication plugin.
///
/// Generates WebAuthn-compatible registration and authentication options,
/// stores challenge state via the auth store, and manages passkey CRUD.
pub struct PasskeyPlugin {
    config: PasskeyConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
#[plugin(name = "PasskeyPlugin")]
pub struct PasskeyConfig {
    #[config(default = String::new())]
    pub rp_id: String,
    #[config(default = "Better Auth".to_string())]
    pub rp_name: String,
    #[config(default = String::new())]
    pub origin: String,
    #[config(default = 300)]
    pub challenge_ttl_secs: i64,
    #[config(default = PasskeyRegistrationConfig::default())]
    pub registration: PasskeyRegistrationConfig,
    #[config(default = PasskeyAuthenticationConfig::default())]
    pub authentication: PasskeyAuthenticationConfig,
}

// -- Plugin --

impl PasskeyPlugin {
    // -- Handlers (delegate to core functions) --

    /// GET /passkey/generate-register-options
    async fn handle_generate_register_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        use better_auth_core::AuthUser;
        let session = self.registration_session(req, ctx).await?;
        let user = if let Some((user, _)) = session {
            let id = user.id().into_owned();
            let name = user
                .email()
                .filter(|email| !email.is_empty())
                .unwrap_or(&id)
                .to_owned();
            PasskeyRegistrationUser {
                id,
                name: name.clone(),
                display_name: Some(name),
            }
        } else {
            let Some(resolver) = &self.config.registration.resolve_user else {
                return Ok(AuthResponse::json(
                    400,
                    &serde_json::json!({"code":"RESOLVE_USER_REQUIRED","message":"Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false"}),
                )?);
            };
            let context = PasskeyRegistrationContext {
                request: req,
                auth_config: &ctx.config,
                extensions: &ctx.extensions,
            };
            match resolver
                .resolve_user(&context, req.query.get("context").map(String::as_str))
                .await
            {
                Ok(Some(user)) if !user.id.is_empty() && !user.name.is_empty() => user,
                Ok(_) => {
                    return Ok(AuthResponse::json(
                        400,
                        &serde_json::json!({"code":"RESOLVED_USER_INVALID","message":"Resolved user is invalid"}),
                    )?);
                }
                Err(error) if registration::is_application_error(&error) => return Err(error),
                Err(_) => return Ok(AuthResponse::new(500)),
            }
        };
        let passkey_name = req.query.get("name").map(|s| s.as_str());
        let authenticator_attachment = req.query.get("authenticatorAttachment").map(|s| s.as_str());
        let (result, cookie_header) = generate_register_options_core(
            &user,
            req.query.get("context").map(String::as_str),
            passkey_name,
            authenticator_attachment,
            &self.config,
            ctx,
        )
        .await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-registration
    async fn handle_verify_registration(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyRegistrationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let session = if self.config.registration.require_session {
            self.registration_session(req, ctx).await?
        } else {
            None
        };
        let owner_id = session
            .as_ref()
            .map(|(user, _)| better_auth_core::AuthUser::id(user).into_owned());
        match verify_registration_core(&body, req, owner_id.as_deref(), &self.config, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                let token = result
                    .get("session")
                    .and_then(|session| session.get("token"))
                    .and_then(serde_json::Value::as_str);
                let response = AuthResponse::json(200, &result)?;
                if let Some(token) = token {
                    use better_auth_core::utils::cookie_utils::{
                        create_session_cookie_with_max_age, create_session_like_cookie,
                        related_cookie_name, sign_cookie_value, verify_cookie_value,
                    };
                    let preference = related_cookie_name(&ctx.config, "dont_remember");
                    let dont_remember = crate::plugins::helpers::get_cookie(req, &preference)
                        .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
                        .is_some_and(|value| !value.is_empty());
                    let mut response = response.with_appended_header(
                        "Set-Cookie",
                        create_session_cookie_with_max_age(
                            Some(token),
                            if dont_remember {
                                None
                            } else {
                                Some(ctx.config.session.expires_in.num_seconds())
                            },
                            &ctx.config,
                        ),
                    );
                    if dont_remember {
                        response.headers.append(
                            "Set-Cookie",
                            create_session_like_cookie(
                                &preference,
                                &sign_cookie_value("true", &ctx.config.secret),
                                None,
                                &ctx.config,
                            ),
                        );
                    }
                    Ok(response)
                } else {
                    Ok(response)
                }
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    async fn registration_session<S: better_auth_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<(S::User, better_auth_core::wire::SessionView)>> {
        let session = match ctx.require_session(req).await {
            Ok(session) => Some(session),
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound)
                if !self.config.registration.require_session =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        if self.config.registration.require_session
            && let Some((_, session)) = &session
            && !ctx.session_manager().is_session_fresh(session)
        {
            return Err(AuthError::Upstream {
                status: 403,
                code: "SESSION_NOT_FRESH",
                message: "Session is not fresh",
            });
        }
        Ok(session)
    }

    /// GET /passkey/generate-authenticate-options
    async fn handle_generate_authenticate_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let maybe_user = ctx.require_session(req).await.ok().map(|(u, _)| u);
        let (result, cookie_header) =
            generate_authenticate_options_core(maybe_user.as_ref(), &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyAuthenticationRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let ip_address = req.headers.get("x-forwarded-for").cloned();
        let user_agent = req.headers.get("user-agent").cloned();
        match verify_authentication_core(&body, req, &self.config, ip_address, user_agent, ctx)
            .await?
        {
            PasskeyHandlerOutcome::Success((response, token)) => {
                let cookie_header = create_session_cookie(&token, &ctx.config);
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// GET /passkey/list-user-passkeys
    async fn handle_list_user_passkeys(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let result = list_user_passkeys_core(&user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/delete-passkey
    async fn handle_delete_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: DeletePasskeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        match delete_passkey_core(&body, &user, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                AuthResponse::json(200, &result).map_err(AuthError::from)
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// POST /passkey/update-passkey
    async fn handle_update_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = ctx.require_session(req).await?;
        let body: UpdatePasskeyRequest = match better_auth_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        match update_passkey_core(&body, &user, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                AuthResponse::json(200, &result).map_err(AuthError::from)
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }
}

better_auth_core::impl_auth_plugin! {
    PasskeyPlugin, "passkey";
    routes {
        get  "/passkey/generate-register-options"      => handle_generate_register_options,      "passkey_generate_register_options";
        post "/passkey/verify-registration"            => handle_verify_registration,            "passkey_verify_registration";
        get  "/passkey/generate-authenticate-options"  => handle_generate_authenticate_options,  "passkey_generate_authenticate_options";
        post "/passkey/verify-authentication"          => handle_verify_authentication,          "passkey_verify_authentication";
        get  "/passkey/list-user-passkeys"             => handle_list_user_passkeys,             "passkey_list_user_passkeys";
        post "/passkey/delete-passkey"                 => handle_delete_passkey,                 "passkey_delete_passkey";
        post "/passkey/update-passkey"                 => handle_update_passkey,                 "passkey_update_passkey";
    }
}
