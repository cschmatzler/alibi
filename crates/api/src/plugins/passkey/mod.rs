mod authentication;

pub(super) mod handlers;

mod raw_none;
mod source;

mod registration;

pub(super) mod types;

pub(super) mod webauthn;

use alibi_core::utils::cookie_utils::create_session_cookie;
use alibi_core::{AuthContext, AuthError, AuthResult};
use alibi_core::{AuthRequest, AuthResponse};
pub use authentication::{
    AuthenticationResult, PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, VerifiedPasskeyAuthentication,
};
use handlers::{
    PasskeyHandlerOutcome, delete_passkey_core, generate_authenticate_options_core,
    generate_register_options_core, list_user_passkeys_core, update_passkey_core,
    verify_authentication_core, verify_registration_core,
};
pub use registration::{
    PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyUserResolver,
    VerifiedPasskeyRegistration,
};
use types::{
    DeletePasskeyRequest, UpdatePasskeyRequest, VerifyAuthenticationRequest,
    VerifyRegistrationRequest,
};

/// Passkey / `WebAuthn` authentication plugin.
///
/// Generates WebAuthn-compatible registration and authentication options,
/// stores challenge state via the auth store, and manages passkey CRUD.
pub struct PasskeyPlugin {
    config: PasskeyConfig,
}

#[derive(Debug, Clone, alibi_core::PluginConfig)]
#[plugin(name = "PasskeyPlugin")]
pub struct PasskeyConfig {
    #[config(default = String::new())]
    pub rp_id: String,
    #[config(default = "Better Auth".to_owned())]
    pub rp_name: String,
    #[config(default = String::new())]
    pub origin: String,
    #[config(default = 300)]
    pub challenge_ttl_secs: i64,
    #[config(default = "better-auth-passkey".to_owned())]
    pub web_authn_challenge_cookie: String,
    /// Per-format PEM roots, matching the verifier SettingsService.
    /// Unspecified formats retain published defaults.
    #[config(default = None)]
    pub attestation_root_certificates: Option<std::collections::BTreeMap<String, Vec<String>>>,
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        use alibi_core::AuthUser;
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
        let passkey_name = req.query.get("name").map(String::as_str);
        let authenticator_attachment = req.query.get("authenticatorAttachment").map(String::as_str);
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyRegistrationRequest = match alibi_core::validate_request_body(req) {
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
            .map(|(user, _)| alibi_core::AuthUser::id(user).into_owned());
        match verify_registration_core(&body, req, owner_id.as_deref(), &self.config, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                let token = result
                    .get("session")
                    .and_then(|session_2| session_2.get("token"))
                    .and_then(serde_json::Value::as_str);
                let response = AuthResponse::json(200, &result)?;
                if let Some(token) = token {
                    use alibi_core::utils::cookie_utils::{
                        create_session_cookie_with_max_age, create_session_like_cookie,
                        related_cookie_name, sign_cookie_value, verify_cookie_value,
                    };
                    let preference = related_cookie_name(&ctx.config, "dont_remember");
                    let dont_remember = crate::plugins::helpers::get_cookie(req, &preference)
                        .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
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
                        )?,
                    );
                    if dont_remember {
                        response.headers.append(
                            "Set-Cookie",
                            create_session_like_cookie(
                                &preference,
                                &sign_cookie_value("true", ctx.config.current_secret()),
                                None,
                                &ctx.config,
                            )?,
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

    async fn registration_session<S: alibi_core::AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<
        Option<(
            alibi_core::AuthenticatedUser<S>,
            alibi_core::wire::SessionView,
        )>,
    > {
        let session = match ctx.require_cached_session(req).await {
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let maybe_user = ctx.require_cached_session(req).await.ok().map(|(u, _)| u);
        let (result, cookie_header) =
            generate_authenticate_options_core(maybe_user.as_ref(), &self.config, ctx).await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyAuthenticationRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        let metadata = alibi_core::RequestMeta::from_request(req);
        match verify_authentication_core(
            &body,
            req,
            &self.config,
            metadata.ip_address,
            metadata.user_agent,
            ctx,
        )
        .await?
        {
            PasskeyHandlerOutcome::Success((response, token)) => {
                let cookie_header = create_session_cookie(&token, &ctx.config)?;
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// GET /passkey/list-user-passkeys
    async fn handle_list_user_passkeys(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let result = list_user_passkeys_core(&user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/delete-passkey
    async fn handle_delete_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let body: DeletePasskeyRequest = match alibi_core::validate_request_body(req) {
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
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let body: UpdatePasskeyRequest = match alibi_core::validate_request_body(req) {
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

alibi_core::impl_auth_plugin! {
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

 extra {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self))
    }

    fn openapi_metadata(&self, ctx: &alibi_core::AuthInitContext<S>) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(<Self as alibi_core::AuthPlugin<S>>::name(self), &<Self as alibi_core::AuthPlugin<S>>::routes(self), ctx)
    }
 }
}

impl std::fmt::Debug for PasskeyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyPlugin").finish_non_exhaustive()
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    mod revocation;
    use super::*;
    use crate::plugins::test_helpers;
    use alibi_core::{CreatePasskey, CreateUser, HttpMethod};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Duration;
    use std::collections::HashMap;
    use std::fmt::Write;

    fn passkey_plugin() -> PasskeyPlugin {
        PasskeyPlugin::new()
            .rp_id("localhost")
            .rp_name("Better Auth Test")
            .origin("http://localhost:3000")
    }

    fn cookie_header(response: &AuthResponse) -> &str {
        response
            .headers
            .get("Set-Cookie")
            .expect("response should include a Set-Cookie header")
    }

    fn credential_id(label: &str) -> String {
        URL_SAFE_NO_PAD.encode(label.as_bytes())
    }

    #[test]
    fn test_extract_passkey_snapshot_fields_requires_all_expected_fields() {
        let value = serde_json::json!({
            "cred": {
                "counter": 7,
                "backup_state": true
            }
        });

        let err = webauthn::extract_passkey_snapshot_fields(&value).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Internal server error: Stored passkey JSON missing backup_eligible"
        );
    }

    #[test]
    fn test_extract_passkey_snapshot_fields_reads_expected_values() {
        let value = serde_json::json!({
            "cred": {
                "counter": 11,
                "backup_state": true,
                "backup_eligible": false
            }
        });

        let (counter, backed_up, backup_eligible) =
            webauthn::extract_passkey_snapshot_fields(&value).unwrap();
        assert_eq!(counter, 11);
        assert!(backed_up);
        assert!(!backup_eligible);
    }

    #[tokio::test]
    async fn test_generate_register_options_sets_cookie_and_uses_query_name() {
        let plugin = passkey_plugin();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: Some("Existing Key".to_owned()),
                credential_id: credential_id("cred-existing"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: Some("usb,nfc".to_owned()),
                credential: "invalid-stored-passkey".to_owned(),
                aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()),
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/passkey/generate-register-options",
            Some(&session.token),
            None,
            HashMap::from([
                ("name".to_owned(), "Custom Account Label".to_owned()),
                (
                    "authenticatorAttachment".to_owned(),
                    "cross-platform".to_owned(),
                ),
            ]),
        );

        let response = plugin
            .handle_generate_register_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(cookie_header(&response).contains("better-auth-passkey="));

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!((*(body).get("challenge").unwrap_or(&serde_json::Value::Null)).is_string());
        assert_eq!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("name")
                .unwrap_or(&serde_json::Value::Null)),
            "Custom Account Label"
        );
        assert_eq!(
            (*(*(body)
                .get("authenticatorSelection")
                .unwrap_or(&serde_json::Value::Null))
            .get("authenticatorAttachment")
            .unwrap_or(&serde_json::Value::Null)),
            "cross-platform"
        );
        assert_eq!(
            (*(*(*(body)
                .get("excludeCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("id")
            .unwrap_or(&serde_json::Value::Null)),
            credential_id("cred-existing")
        );
        assert_eq!(
            (*(*(*(*(body)
                .get("excludeCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("transports")
            .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null)),
            "usb"
        );
    }

    #[tokio::test]
    async fn test_generate_authenticate_options_is_get_and_sets_cookie_without_auth() {
        let plugin = passkey_plugin();
        let ctx = test_helpers::create_test_context().await;
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/passkey/generate-authenticate-options",
            None,
            None,
        );

        let response = plugin
            .handle_generate_authenticate_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(cookie_header(&response).contains("better-auth-passkey="));

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!((*(body).get("challenge").unwrap_or(&serde_json::Value::Null)).is_string());
        assert!(body.get("allowCredentials").is_none());
    }

    #[tokio::test]
    async fn test_generate_authenticate_options_with_auth_lists_allow_credentials() {
        let plugin = passkey_plugin();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: Some("Authenticator".to_owned()),
                credential_id: credential_id("cred-auth"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: Some("internal".to_owned()),
                credential: "invalid-stored-passkey".to_owned(),
                aaguid: None,
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/passkey/generate-authenticate-options",
            Some(&session.token),
            None,
        );

        let response = plugin
            .handle_generate_authenticate_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(*(*(body)
                .get("allowCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("id")
            .unwrap_or(&serde_json::Value::Null)),
            credential_id("cred-auth")
        );
        assert_eq!(
            (*(*(*(*(body)
                .get("allowCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("transports")
            .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null)),
            "internal"
        );
    }

    #[tokio::test]
    async fn test_verify_registration_without_challenge_cookie_returns_challenge_not_found() {
        let plugin = passkey_plugin();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        let body = serde_json::json!({
            "response": {
                "id": "fake-credential-id",
                "rawId": "ZmFrZS1yYXctaWQ",
                "response": {
                    "attestationObject": "ZmFrZS1hdHRlc3RhdGlvbg",
                    "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ"
                },
                "type": "public-key"
            }
        });
        let mut req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(body),
        );
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let response = plugin.handle_verify_registration(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);

        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
            "Challenge not found"
        );
    }

    #[tokio::test]
    async fn test_verify_authentication_without_challenge_cookie_returns_challenge_not_found() {
        let plugin = passkey_plugin();
        let ctx = test_helpers::create_test_context().await;

        let body = serde_json::json!({
            "response": {
                "id": credential_id("cred-auth"),
                "rawId": credential_id("cred-auth"),
                "response": {
                    "authenticatorData": "ZmFrZS1hdXRoLWRhdGE",
                    "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ",
                    "signature": "ZmFrZS1zaWduYXR1cmU"
                },
                "type": "public-key"
            }
        });
        let mut req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(body),
        );
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let response = plugin
            .handle_verify_authentication(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 400);

        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
            "Challenge not found"
        );
    }

    #[tokio::test]
    async fn test_list_user_passkeys_omits_updated_at_and_retains_sql_null_fields() {
        let plugin = passkey_plugin();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: None,
                credential_id: credential_id("cred-list"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: None,
                credential: "invalid-stored-passkey".to_owned(),
                aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()),
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/passkey/list-user-passkeys",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            (*(body).get(0).unwrap_or(&serde_json::Value::Null))
                .get("updatedAt")
                .is_none()
        );
        assert_eq!(
            (*(*(body).get(0).unwrap_or(&serde_json::Value::Null))
                .get("aaguid")
                .unwrap_or(&serde_json::Value::Null)),
            "00000000-0000-0000-0000-000000000000"
        );
        let passkey = body.get(0).unwrap();
        // The published SQL adapter returns nullable columns as own properties.
        assert_eq!(passkey.get("name"), Some(&serde_json::Value::Null));
        assert_eq!(passkey.get("transports"), Some(&serde_json::Value::Null));
    }

    #[tokio::test]
    async fn test_delete_passkey_non_owner_is_unauthorized() {
        let plugin = passkey_plugin();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("owner@example.com")
                .with_name("Owner"),
            Duration::hours(1),
        )
        .await;
        let other = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("other@example.com")
                .with_name("Other"),
        )
        .await;

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: other.id.clone(),
                name: Some("Other Key".to_owned()),
                credential_id: credential_id("cred-other-delete"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: None,
                credential: "invalid-stored-passkey".to_owned(),
                aaguid: None,
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/delete-passkey",
            Some(&session.token),
            Some(serde_json::json!({ "id": passkey.id })),
        );

        let response = plugin.handle_delete_passkey(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
        assert_eq!(response.body.len(), 0);
        let preserved = ctx
            .database
            .get_passkey_by_id(&passkey.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(preserved.name.as_deref(), Some("Other Key"));
    }

    #[tokio::test]
    async fn test_update_passkey_non_owner_is_unauthorized() {
        let plugin = passkey_plugin();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("owner@example.com")
                .with_name("Owner"),
            Duration::hours(1),
        )
        .await;
        let other = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("other@example.com")
                .with_name("Other"),
        )
        .await;

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: other.id.clone(),
                name: Some("Other Key".to_owned()),
                credential_id: credential_id("cred-other-update"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: None,
                credential: "invalid-stored-passkey".to_owned(),
                aaguid: None,
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/update-passkey",
            Some(&session.token),
            Some(serde_json::json!({
                "id": passkey.id,
                "name": "Hijacked",
            })),
        );

        let response = plugin.handle_update_passkey(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
        );
        let preserved = ctx
            .database
            .get_passkey_by_id(&passkey.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(preserved.name.as_deref(), Some("Other Key"));
    }

    /// Previously persisted ceremonies keep both their codec and original Required policy.
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn pending_registration_challenges_keep_original_verification_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use p256::elliptic_curve::{Generate as _, sec1::ToSec1Point as _};
        use serde_cbor_2::Value as Cbor;
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;
        use webauthn_rs::prelude::RegisterPublicKeyCredential;

        let config = PasskeyConfig {
            rp_id: "localhost".into(),
            origin: "http://localhost:3100".into(),
            ..Default::default()
        };
        let webauthn =
            webauthn::build_webauthn(&config, &alibi_core::AuthConfig::default(), &config.origin)?;
        let (options, legacy) = webauthn.start_passkey_registration(
            uuid::Uuid::new_v4(),
            "Legacy owner",
            "Legacy owner",
            None,
        )?;
        // This is the old externally persisted protocol, with a real library state.
        let stored = serde_json::to_string(&serde_json::json!({
            "user_id": "legacy-owner", "user": null, "context": "old-context", "state": legacy,
        }))?;
        let decoded: webauthn::StoredRegistrationState = serde_json::from_str(&stored)?;
        assert_eq!(decoded.user_id, "legacy-owner");
        assert_eq!(decoded.context.as_deref(), Some("old-context"));
        let webauthn::StoredRegistrationVerifier::Legacy(state) = decoded.state else {
            panic!("Old challenge changed verifier policy");
        };
        let secret = p256::SecretKey::generate();
        let point = secret.public_key().to_sec1_point(false);
        let key = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (
                Cbor::Integer(-2),
                Cbor::Bytes(point.x().ok_or("missing generated X coordinate")?.to_vec()),
            ),
            (
                Cbor::Integer(-3),
                Cbor::Bytes(point.y().ok_or("missing generated Y coordinate")?.to_vec()),
            ),
        ]));
        let core = webauthn::build_verification_core(
            &config,
            &alibi_core::AuthConfig::default(),
            &config.origin,
        )?;
        let builder = core
            .new_challenge_register_builder(b"actual-core-owner", "Core owner", "Core owner")?
            .user_verification_policy(webauthn_rs_core::proto::UserVerificationPolicy::Preferred);
        let (core_options, core_state) = core.generate_challenge_register(builder)?;
        let old_core_wire = serde_json::to_string(&serde_json::json!({
            "user_id": "core-owner", "user": null, "context": "old-core-context",
            "state": {"kind": "core", "state": core_state},
        }))?;
        let decoded_core: webauthn::StoredRegistrationState = serde_json::from_str(&old_core_wire)?;
        let webauthn::StoredRegistrationVerifier::Source(
            webauthn::StoredCoreRegistrationState::Core { state: old_core },
        ) = decoded_core.state
        else {
            panic!("Old Core protocol changed verifier");
        };
        let credential_id = b"actual-legacy-credential";
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create", "challenge": options.public_key.challenge,
            "origin": config.origin, "crossOrigin": false,
        }))?;
        for verified in [true, false] {
            let mut auth_data = Sha256::digest(config.rp_id.as_bytes()).to_vec();
            auth_data.push(if verified { 0x45 } else { 0x41 });
            auth_data.extend_from_slice(&[0; 20]);
            auth_data.extend_from_slice(&u16::try_from(credential_id.len())?.to_be_bytes());
            auth_data.extend_from_slice(credential_id);
            auth_data.extend_from_slice(&serde_cbor_2::to_vec(&key)?);
            let attestation = Cbor::Map(BTreeMap::from([
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
                (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
            ]));
            let response: RegisterPublicKeyCredential = serde_json::from_value(
                serde_json::json!({
                    "id": URL_SAFE_NO_PAD.encode(credential_id), "rawId": URL_SAFE_NO_PAD.encode(credential_id),
                    "type": "public-key", "clientExtensionResults": {}, "response": {
                        "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                        "attestationObject": URL_SAFE_NO_PAD.encode(serde_cbor_2::to_vec(&attestation)?),
                        "transports": ["internal"],
                    },
                }),
            )?;
            // Feed the historical Core wire's genuinely issued challenge to its
            // actual consumer. This old policy accepts UV absent as well as present.
            let core_client_data = serde_json::to_vec(&serde_json::json!({
                "type": "webauthn.create", "challenge": core_options.public_key.challenge,
                "origin": config.origin, "crossOrigin": false,
            }))?;
            let mut core_response = response.clone();
            core_response.response.client_data_json = core_client_data.into();
            let restored_core = webauthn::finish_core_registration(
                &core,
                &core_response,
                &old_core,
                &config.origin,
            )?;
            assert_eq!(restored_core.cred_id().as_ref(), credential_id);
            let stored_credential = serde_json::to_string(&restored_core)?;
            let raw_none::StoredCredential::Core(decoded_credential) =
                serde_json::from_str(&stored_credential)?
            else {
                panic!("historical typed credential must retain its codec")
            };
            assert_eq!(decoded_credential.cred_id(), restored_core.cred_id());
            let result = webauthn.finish_passkey_registration(&response, &state);
            if verified {
                let legacy_key = result?;
                assert_eq!(legacy_key.cred_id().as_ref(), credential_id);
                complete_historical_authentication(&config, &secret, &key, legacy_key).await?;
            } else {
                assert!(matches!(
                    result,
                    Err(webauthn_rs_core::error::WebauthnError::UserNotVerified)
                ));
            }
        }
        Ok(())
    }

    async fn complete_historical_authentication(
        config: &PasskeyConfig,
        secret: &p256::SecretKey,
        cose: &serde_cbor_2::Value,
        mut key: webauthn_rs::prelude::Passkey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use p256::pkcs8::EncodePrivateKey;
        use sha2::{Digest, Sha256};
        let (ctx, user, _) = test_helpers::create_test_context_with_user(
            CreateUser::new().with_email("legacy-auth@example.test"),
            Duration::hours(1),
        )
        .await;
        let plugin = PasskeyPlugin {
            config: config.clone(),
        };
        let webauthn = webauthn::build_webauthn(config, &ctx.config, &config.origin)?;
        let credential_id = URL_SAFE_NO_PAD.encode(key.cred_id().as_ref());
        let persisted = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: Some("Historical".into()),
                credential_id: credential_id.clone(),
                public_key: base64::engine::general_purpose::STANDARD
                    .encode(serde_cbor_2::to_vec(cose)?),
                credential: serde_json::to_string(&key)?,
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                aaguid: None,
            })
            .await?;
        let signing = openssl::pkey::PKey::private_key_from_der(secret.to_pkcs8_der()?.as_bytes())?;
        for (kind, counter, backup) in [
            ("passkey", 1_u32, 0x08_u8),
            ("discoverable", 2, 0x18),
            ("discoverable", 3, 0x08),
        ] {
            for verified in [false, true] {
                let (challenge, state) = if kind == "passkey" {
                    let (options, state) = webauthn.start_passkey_authentication(&[key.clone()])?;
                    (
                        options.public_key.challenge,
                        serde_json::json!({"kind":"passkey","state":state}),
                    )
                } else {
                    let (options, state) = webauthn.start_discoverable_authentication()?;
                    (
                        options.public_key.challenge,
                        serde_json::json!({"kind":"discoverable","state":state}),
                    )
                };
                let token = uuid::Uuid::new_v4().to_string();
                drop(
                    ctx.verifications()
                        .create(alibi_core::CreateVerification {
                            identifier: token.clone(),
                            value: serde_json::to_string(&state)?,
                            expires_at: chrono::Utc::now() + Duration::minutes(5),
                        })
                        .await?,
                );
                let cookie = webauthn::create_challenge_cookie(&ctx.config, 300, &token, config)?;
                let client = serde_json::to_vec(
                    &serde_json::json!({"type":"webauthn.get","challenge":challenge,"origin":config.origin}),
                )?;
                let mut data = Sha256::digest(config.rp_id.as_bytes()).to_vec();
                data.push(backup | if verified { 0x05 } else { 0x01 });
                data.extend_from_slice(&counter.to_be_bytes());
                let mut signer =
                    openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &signing)?;
                signer.update(&data)?;
                signer.update(&Sha256::digest(&client))?;
                let body = serde_json::json!({"response":{"id":credential_id,"rawId":credential_id,"type":"public-key","clientExtensionResults":{},"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"authenticatorData":URL_SAFE_NO_PAD.encode(data),"signature":URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?)}}});
                let mut request = test_helpers::create_auth_request(
                    HttpMethod::Post,
                    "/passkey/verify-authentication",
                    None,
                    Some(serde_json::to_vec(&body)?),
                    HashMap::new(),
                );
                drop(
                    request
                        .headers
                        .insert("cookie".into(), cookie.split(';').next().unwrap().into()),
                );
                drop(
                    request
                        .headers
                        .insert("origin".into(), config.origin.clone()),
                );
                let before = ctx
                    .database
                    .get_passkey_by_id(&persisted.id)
                    .await?
                    .unwrap();
                let sessions = ctx.database.get_user_sessions(&user.id).await?.len();
                let result = plugin.handle_verify_authentication(&request, &ctx).await?;
                assert_eq!(
                    result.status,
                    if verified { 200 } else { 400 },
                    "{kind}: {}",
                    String::from_utf8_lossy(&result.body)
                );
                let after = ctx
                    .database
                    .get_passkey_by_id(&persisted.id)
                    .await?
                    .unwrap();
                if verified {
                    assert_eq!(
                        ctx.database.get_user_sessions(&user.id).await?.len(),
                        sessions + 1
                    );
                    assert_eq!(after.counter, u64::from(counter));
                    let opaque: serde_json::Value = serde_json::from_str(&after.credential)?;
                    assert_eq!(
                        opaque.get("cred").and_then(|c| c.get("backup_eligible")),
                        Some(&serde_json::json!(true))
                    );
                    assert_eq!(
                        opaque.get("cred").and_then(|c| c.get("backup_state")),
                        Some(&serde_json::json!(backup == 0x18))
                    );
                    assert!(!after.backed_up);
                    assert_eq!(after.device_type, "singleDevice");
                    key = serde_json::from_str(&after.credential)?;
                    assert_eq!(
                        plugin
                            .handle_verify_authentication(&request, &ctx)
                            .await?
                            .status,
                        400
                    );
                } else {
                    assert_eq!(
                        serde_json::to_value(&after)?,
                        serde_json::to_value(&before)?
                    );
                    assert_eq!(
                        ctx.database.get_user_sessions(&user.id).await?.len(),
                        sessions
                    );
                }
                assert!(ctx.verifications().find(&token).await?.is_none());
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn raw_none_credential_sql_readback_keeps_original_key_and_hidden_codec()
    -> Result<(), Box<dyn std::error::Error>> {
        use serde_cbor_2::Value as Cbor;
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;
        // The raw storage owner also protects the usable mismatched-key codec.
        // SDK observations cannot read the Native-only hidden credential column.
        for (algorithm, curve) in [(-8, 8), (-7, 6)] {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
            let plugin = passkey_plugin();
            let (ctx, user, session) = test_helpers::create_test_context_with_user(
                CreateUser::new()
                    .with_email("raw-codec-owner@fixture.test")
                    .with_name("Raw codec owner"),
                Duration::hours(1),
            )
            .await;
            let request = test_helpers::create_auth_request(
                HttpMethod::Get,
                "/passkey/generate-register-options",
                Some(&session.token),
                None,
                HashMap::new(),
            );
            let options = plugin
                .handle_generate_register_options(&request, &ctx)
                .await?;
            let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
            let key = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                (Cbor::Integer(1), Cbor::Integer(1)),
                (Cbor::Integer(3), Cbor::Integer(algorithm)),
                (Cbor::Integer(-1), Cbor::Integer(curve)),
                (
                    Cbor::Integer(-2),
                    Cbor::Bytes(signing.verifying_key().as_bytes().to_vec()),
                ),
            ])))?;
            let id = b"raw-none-actual-persisted-credential";
            let mut data = Sha256::digest(b"localhost").to_vec();
            data.push(0x41);
            data.extend_from_slice(&25_u32.to_be_bytes());
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
            data.extend_from_slice(id);
            data.extend_from_slice(&key);
            let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
                (Cbor::Text("authData".into()), Cbor::Bytes(data)),
            ])))?;
            let proof = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{
                "clientDataJSON":URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":(*(issued).get("challenge").expect("fixture contains the requested index")),"origin":"http://localhost:3000"}))?),
                "attestationObject":URL_SAFE_NO_PAD.encode(attestation),"transports":["internal"],
            }});
            let mut request_2 = test_helpers::create_auth_request(
                HttpMethod::Post,
                "/passkey/verify-registration",
                Some(&session.token),
                Some(serde_json::to_vec(&serde_json::json!({"response":proof}))?),
                HashMap::new(),
            );
            let issued_cookie = cookie_header(&options)
                .split(';')
                .next()
                .ok_or("issued challenge cookie required")?;
            _ = write!(
                request_2
                    .headers
                    .get_mut("cookie")
                    .ok_or("signed owner cookie required")?,
                "; {issued_cookie}"
            );
            let result = plugin.handle_verify_registration(&request_2, &ctx).await?;
            assert_eq!(result.status, 200);
            let wire: serde_json::Value = serde_json::from_slice(&result.body)?;
            assert!(wire.get("credential").is_none());
            let row = ctx
                .database
                .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
                .await?
                .ok_or("actual credential row required")?;
            assert_eq!(row.user_id, user.id);
            assert_eq!(row.counter, 25);
            assert_eq!(
                row.public_key,
                base64::engine::general_purpose::STANDARD.encode(&key)
            );
            let raw_none::StoredCredential::Raw(raw) = serde_json::from_str(&row.credential)?
            else {
                panic!("actual raw codec required")
            };
            assert_eq!(raw.credential_id(), id);
            assert_eq!(raw.public_key(), key);
            assert_eq!(raw.snapshot()?.counter, 25);
            assert!(
                serde_json::from_str::<webauthn_rs::prelude::Passkey>(&row.credential).is_err()
            );
            if curve == 6 {
                use ed25519_dalek::Signer;
                let mut persisted = serde_json::to_value(&row)?;
                for control in [
                    "first",
                    "signature",
                    "counter",
                    "origin",
                    "challenge",
                    "rp",
                    "presence",
                    "backup",
                    "last",
                ] {
                    let successful = matches!(control, "first" | "last");
                    let counter = if matches!(control, "first" | "counter") {
                        26_u32
                    } else {
                        27_u32
                    };
                    let request = test_helpers::create_auth_request(
                        HttpMethod::Get,
                        "/passkey/generate-authenticate-options",
                        None,
                        None,
                        HashMap::new(),
                    );
                    let options = plugin
                        .handle_generate_authenticate_options(&request, &ctx)
                        .await?;
                    let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
                    let challenge = issued
                        .get("challenge")
                        .expect("issued authentication challenge");
                    let client = serde_json::to_vec(
                        &serde_json::json!({"type":"webauthn.get", "challenge":if control == "challenge" { serde_json::Value::String("Zm9yZWlnbg".into()) } else { challenge.clone() },"origin":if control == "origin" { "http://foreign.test" } else { "http://localhost:3000" }}),
                    )?;
                    let mut data = Sha256::digest(if control == "rp" {
                        b"foreign.test".as_slice()
                    } else {
                        b"localhost".as_slice()
                    })
                    .to_vec();
                    data.push(match control {
                        "presence" => 0,
                        "backup" => 0x11,
                        _ => 1,
                    });
                    data.extend_from_slice(&counter.to_be_bytes());
                    let mut signed = data.clone();
                    signed.extend_from_slice(&Sha256::digest(&client));
                    let mut signature = signing.sign(&signed).to_bytes();
                    if control == "signature" {
                        signature[0] ^= 1;
                    }
                    let response = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{
                        "clientDataJSON":URL_SAFE_NO_PAD.encode(client),"authenticatorData":URL_SAFE_NO_PAD.encode(data),"signature":URL_SAFE_NO_PAD.encode(signature)
                    }});
                    let mut request = test_helpers::create_auth_request(
                        HttpMethod::Post,
                        "/passkey/verify-authentication",
                        None,
                        Some(serde_json::to_vec(
                            &serde_json::json!({"response":response}),
                        )?),
                        HashMap::new(),
                    );
                    request.headers.insert(
                        "cookie".into(),
                        cookie_header(&options)
                            .split(';')
                            .next()
                            .ok_or("issued authentication cookie required")?
                            .into(),
                    );
                    let result = plugin.handle_verify_authentication(&request, &ctx).await?;
                    assert_eq!(
                        result.status,
                        if successful {
                            200
                        } else if control == "signature" {
                            401
                        } else {
                            400
                        },
                        "{control}"
                    );
                    let updated = ctx
                        .database
                        .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
                        .await?
                        .ok_or("updated raw row required")?;
                    if !successful {
                        let wire: serde_json::Value = serde_json::from_slice(&result.body)?;
                        assert_eq!(
                            wire.get("code"),
                            Some(&serde_json::json!("AUTHENTICATION_FAILED")),
                            "{control}"
                        );
                        assert!(
                            result
                                .headers
                                .get_all("set-cookie")
                                .all(|cookie| !cookie.contains("session_token="))
                        );
                        assert_eq!(serde_json::to_value(&updated)?, persisted, "{control}");
                        assert_eq!(ctx.database.get_user_sessions(&user.id).await?.len(), 2);
                        continue;
                    }
                    persisted = serde_json::to_value(&updated)?;
                    assert_eq!(updated.public_key, row.public_key);
                    assert_eq!(updated.credential_id, row.credential_id);
                    assert_eq!(updated.user_id, row.user_id);
                    assert_eq!(updated.counter, u64::from(counter));
                    let raw_none::StoredCredential::Raw(raw) =
                        serde_json::from_str(&updated.credential)?
                    else {
                        panic!("authentication must retain raw codec")
                    };
                    assert_eq!(raw.public_key(), key);
                    assert_eq!(raw.credential_id(), id);
                    assert_eq!(raw.snapshot()?.counter, u64::from(counter));
                    assert!(
                        serde_json::from_str::<webauthn_rs::prelude::Passkey>(&updated.credential)
                            .is_err()
                    );
                }
            }
            assert_eq!(
                ctx.database.get_user_sessions(&user.id).await?.len(),
                if curve == 6 { 3 } else { 1 }
            );
        }
        Ok(())
    }
}
// LCOV_EXCL_STOP
