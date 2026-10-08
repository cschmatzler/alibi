use super::StatusResponse;
use super::authentication_helpers::{JsonField, RequestBody, parse_body};
use super::helpers::{admin_plugin_enabled, delete_session_cookie_headers};
use alibi_core::SuccessResponse;
use alibi_core::entity::{AuthSession, AuthUser};
use alibi_core::wire::SessionView;
use alibi_core::{AuthContext, AuthPlugin, AuthRoute};
use alibi_core::{AuthError, AuthResult};
use alibi_core::{AuthRequest, AuthResponse, HttpMethod};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Session management plugin for handling session operations
pub struct SessionManagementPlugin {
    config: SessionManagementConfig,
}

#[derive(Debug, Clone, alibi_core::PluginConfig)]
#[plugin(name = "SessionManagementPlugin")]
pub struct SessionManagementConfig {
    #[config(default = true)]
    pub enable_session_listing: bool,
    #[config(default = true)]
    pub enable_session_revocation: bool,
    #[config(default = true)]
    pub require_authentication: bool,
}

// Request structures for session endpoints
#[derive(Debug, Deserialize)]
struct RevokeSessionRequest {
    token: String,
}

impl RequestBody for RevokeSessionRequest {
    const FIELDS: &'static [JsonField] = &[JsonField::string("token", true)];
}

#[derive(Debug, Serialize)]
struct GetSessionResponse<S, U> {
    session: S,
    user: U,
    #[serde(rename = "needsRefresh", skip_serializing_if = "Option::is_none")]
    needs_refresh: Option<bool>,
}

#[async_trait]
impl<S: alibi_core::AuthSchema> AuthPlugin<S> for SessionManagementPlugin {
    fn static_openapi_metadata(&self) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
        )
    }

    fn openapi_metadata(
        &self,
        ctx: &alibi_core::AuthInitContext<S>,
    ) -> alibi_core::PluginOpenApiMetadata {
        crate::metadata::instance_plugin_metadata(
            <Self as alibi_core::AuthPlugin<S>>::name(self),
            &<Self as alibi_core::AuthPlugin<S>>::routes(self),
            ctx,
        )
    }

    fn name(&self) -> &'static str {
        "session-management"
    }

    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get("/get-session", "get_session"),
            // Upstream declares `/get-session` as `method: ["GET", "POST"]`;
            // the POST form requires `session.defer_session_refresh`.
            AuthRoute::post("/get-session", "get_session"),
            AuthRoute::post("/sign-out", "sign_out"),
            AuthRoute::post("/update-session", "updateSession"),
            AuthRoute::get("/list-sessions", "list_sessions"),
            AuthRoute::post("/revoke-session", "revoke_session"),
            AuthRoute::post("/revoke-sessions", "revoke_sessions"),
            AuthRoute::post("/revoke-other-sessions", "revoke_other_sessions"),
        ]
    }

    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get | HttpMethod::Post, "/get-session") => {
                Ok(Some(self.handle_get_session(req, ctx).await?))
            }
            (HttpMethod::Post, "/sign-out") => Ok(Some(self.handle_sign_out(req, ctx).await?)),
            (HttpMethod::Post, "/update-session") => {
                Ok(Some(self.handle_update_session(req, ctx).await?))
            }
            (HttpMethod::Get, "/list-sessions") if self.config.enable_session_listing => {
                Ok(Some(self.handle_list_sessions(req, ctx).await?))
            }
            (HttpMethod::Post, "/revoke-session") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_session(req, ctx).await?))
            }
            (HttpMethod::Post, "/revoke-sessions") if self.config.enable_session_revocation => {
                Ok(Some(self.handle_revoke_sessions(req, ctx).await?))
            }
            (HttpMethod::Post, "/revoke-other-sessions")
                if self.config.enable_session_revocation =>
            {
                Ok(Some(self.handle_revoke_other_sessions(req, ctx).await?))
            }
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Old handler methods — delegate to core functions
// ---------------------------------------------------------------------------

impl SessionManagementPlugin {
    #[expect(
        clippy::too_many_lines,
        reason = "Keep validated session field updates and persistence callbacks in request order"
    )]
    async fn handle_update_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        use super::authentication_helpers::{json_type, validation_response};
        use alibi_core::field_policy::{FieldInputError, SessionFields};
        use alibi_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };
        use alibi_core::utils::json::JsValue;

        if req.body.is_some() {
            let content_type = req
                .header("content-type")
                .map(String::as_str)
                .unwrap_or_default();
            if !content_type
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_lowercase()
                .contains("application/json")
            {
                let message = if content_type.is_empty() {
                    "Content-Type is required. Allowed types: application/json".to_owned()
                } else {
                    format!(
                        "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
                    )
                };
                return Ok(AuthResponse::json(
                    415,
                    &serde_json::json!({"code":"UNSUPPORTED_MEDIA_TYPE","message":message}),
                )?);
            }
        }
        let value: Option<JsValue> = match req.body.as_ref() {
            Some(body) => match alibi_core::utils::json::from_slice(body) {
                Ok(value) => Some(value),
                Err(_) => {
                    return Ok(AuthResponse::json(
                        400,
                        &serde_json::json!({"code":"BAD_REQUEST","message":"Invalid JSON in request body"}),
                    )?);
                }
            },
            None => None,
        };
        let Some(input) = value.as_ref().and_then(JsValue::as_object) else {
            return Ok(validation_response(&format!(
                "[body] Invalid input: expected record, received {}",
                json_type(value.as_ref())
            )));
        };
        let (user, session) = match super::helpers::ordinary_session(req, ctx).await {
            Ok(session) => session,
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
                return Ok(AuthResponse::json(
                    401,
                    &serde_json::json!({"code":"UNAUTHORIZED","message":"Unauthorized"}),
                )?);
            }
            Err(error) => return Err(error),
        };
        let fields = ctx.extensions.get::<SessionFields>().map_or_else(
            || SessionFields(ctx.config.session.additional_fields.clone()),
            |fields| (*fields).clone(),
        );
        let allowed = match fields.parse_update(input) {
            Ok(allowed) => allowed,
            Err(FieldInputError::Validation { code, message }) => {
                return Ok(AuthResponse::json(
                    400,
                    &serde_json::json!({"code":code,"message":message}),
                )?);
            }
            Err(FieldInputError::Transform(AuthError::Internal(_))) => {
                return Ok(AuthResponse::new(500));
            }
            Err(FieldInputError::Transform(error)) => return Err(error),
        };
        if !allowed.has_input_fields() {
            return Ok(AuthResponse::json(
                400,
                &serde_json::json!({"message":"No fields to update"}),
            )?);
        }
        let updated = match ctx
            .database
            .update_session_fields_record(session.token(), allowed)
            .await
        {
            Ok(updated) => updated,
            Err(error @ AuthError::Internal(_)) => {
                return Err(AuthError::CallbackFailure(Box::new(error)));
            }
            Err(error) => return Err(error),
        };
        let Some(updated) = updated else {
            let mut response = AuthResponse::json(
                401,
                &serde_json::json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"}),
            )?;
            for cookie in delete_session_cookie_headers(&ctx.config)? {
                response.headers.append("Set-Cookie", cookie);
            }
            return Ok(response);
        };

        alibi_core::session::cookie_cache::runtime::emit_issuance(ctx, &user, &updated).await?;

        let preference = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = req.header("cookie").is_some_and(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .find(|cookie| cookie.name() == preference)
                .and_then(|cookie| verify_cookie_value(cookie.value(), ctx.config.current_secret()))
                .is_some_and(|value_2| !value_2.is_empty())
        });
        let mut response = AuthResponse::json(
            200,
            &serde_json::json!({"session":ctx.session_view(&updated)}),
        )?
        .with_appended_header(
            "Set-Cookie",
            create_session_cookie_with_max_age(
                Some(updated.token()),
                if dont_remember {
                    None
                } else {
                    Some(ctx.config.session.expires_in.num_seconds())
                },
                &ctx.config,
            )?,
        );
        if dont_remember {
            response = response.with_appended_header(
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
    }

    pub(in crate::plugins) async fn handle_get_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let response =
            if req.method() == &HttpMethod::Post && !ctx.config.session.defer_session_refresh {
                AuthError::Upstream {
                status: 405,
                code: "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
                message: "POST method requires deferSessionRefresh to be enabled in session config",
            }.to_auth_response()
            } else {
                match self.get_session_response(req, ctx).await {
                    Ok(response) => response,
                    Err(error @ (AuthError::Upstream { .. } | AuthError::Api { .. })) => {
                        error.to_auth_response()
                    }
                    Err(_) => AuthError::Upstream {
                        status: 500,
                        code: "FAILED_TO_GET_SESSION",
                        message: "Failed to get session",
                    }
                    .to_auth_response(),
                }
            };
        Ok(response
            .with_header("cache-control", "no-store")
            .with_header("pragma", "no-cache"))
    }

    async fn get_session_response(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let Some(read) =
            alibi_core::session::cookie_cache::runtime::authenticated(ctx, req, true).await?
        else {
            return Ok(AuthResponse::json(200, &serde_json::Value::Null)?);
        };
        Ok(AuthResponse::json(
            200,
            &GetSessionResponse {
                session: read.session,
                user: match read.user {
                    alibi_core::AuthenticatedUser::Stored(user) => ctx.user_view(&user),
                    alibi_core::AuthenticatedUser::Cached(user) => *user,
                },
                needs_refresh: read.needs_refresh,
            },
        )?)
    }

    async fn handle_sign_out(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body = if req.body.is_some() {
            match parse_body::<super::oauth::logout::SignOutRequest>(req) {
                Ok(body) => body,
                Err(response) => return Ok(response),
            }
        } else {
            super::oauth::logout::SignOutRequest::default()
        };
        let mut current_user = None;
        if let Some(token) = ctx.session_manager().extract_session_token(req) {
            if let Ok(Some(session)) = ctx.database.get_session(&token).await {
                // A stored session and user own provider selection; request account IDs
                // and cached account cookies never authorize disclosure of token hints.
                if ctx
                    .database
                    .get_user_by_id(&session.user_id())
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                {
                    current_user = Some(session.user_id().into_owned());
                }
                drop(sign_out_core(&session, ctx).await);
            } else {
                drop(ctx.database.delete_session(&token).await);
            }
        }

        let mut response = AuthResponse::json(200, &SuccessResponse { success: true })?;
        for cookie in delete_session_cookie_headers(&ctx.config)? {
            response.headers.append("Set-Cookie", cookie);
        }
        for (logical, account) in [("session_data", false), ("account_data", true)] {
            if account && !ctx.config.account.store_account_cookie {
                continue;
            }
            let base = alibi_core::utils::cookie_utils::related_cookie_name(&ctx.config, logical);
            for header in alibi_core::session::cookie_cache::runtime::chunked_cookie_headers(
                &base,
                "",
                Some(0.0),
                &ctx.config,
                &req.headers,
                account,
            )? {
                if !header.starts_with(&format!("{base}=")) {
                    response.headers.append("Set-Cookie", header);
                }
            }
        }
        if let Some(user_id) = current_user
            && let Some(url) = super::oauth::logout::provider_logout_url(&user_id, &body, ctx).await
        {
            let redirect = body.disable_redirect != Some(true);
            response.body = AuthResponse::json(
                200,
                &serde_json::json!({
                    "success": true, "url": url, "redirect": redirect,
                }),
            )?
            .body;
            if redirect {
                drop(response.headers.insert("Location", url));
            }
        }
        Ok(response)
    }

    async fn handle_list_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = super::helpers::ordinary_session(req, ctx).await?;
        if !ctx.session_manager().is_session_fresh(&session) {
            return Err(AuthError::Upstream {
                status: 403,
                code: "SESSION_NOT_FRESH",
                message: "Session is not fresh",
            });
        }
        let mut sessions = match list_sessions_core(user.id(), ctx).await {
            Ok(sessions) => sessions,
            Err(_) => {
                tracing::error!("Session listing failed");
                return Ok(AuthResponse::new(500).with_header("content-type", "application/json"));
            }
        };
        if admin_plugin_enabled(ctx) {
            sessions.retain(|session_2| session_2.impersonated_by.is_none());
        }
        Ok(AuthResponse::json(200, &sessions)?)
    }

    async fn handle_revoke_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let revoke_req: RevokeSessionRequest = match parse_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (user, _) = ctx
            .require_authoritative_cached_session(req)
            .await
            .map_err(session_authorization_error)?;
        let response = revoke_session_core(&user, &revoke_req.token, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx
            .require_authoritative_cached_session(req)
            .await
            .map_err(session_authorization_error)?;
        let response = revoke_sessions_core(user.id(), ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_other_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, current_session) = ctx
            .require_authoritative_cached_session(req)
            .await
            .map_err(session_authorization_error)?;
        let response = revoke_other_sessions_core(user.id(), &current_session, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }
}

impl std::fmt::Debug for SessionManagementPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManagementPlugin")
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Core functions — framework-agnostic business logic
// ---------------------------------------------------------------------------

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn sign_out_core(
    session: &impl AuthSession,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    ctx.database.delete_session(session.token()).await?;
    Ok(SuccessResponse { success: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_sessions_core(
    user_id: impl AsRef<str>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<Vec<SessionView>> {
    let sessions = ctx
        .database
        .get_active_user_sessions_record(user_id.as_ref())
        .await?;
    let now = chrono::Utc::now();
    Ok(sessions
        .iter()
        .filter(|session| session.expires_at() > now && session.active())
        .map(|session| ctx.session_view(session))
        .collect())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_session_core(
    user: &impl AuthUser,
    token: &str,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if let Some(session_to_revoke) = ctx.database.get_session(token).await?
        && session_to_revoke.user_id() == user.id()
    {
        ctx.database
            .delete_session(token)
            .await
            .map_err(revocation_storage_error)?;
    }
    Ok(StatusResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_sessions_core(
    user_id: impl AsRef<str>,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    ctx.database
        .delete_user_sessions(user_id.as_ref())
        .await
        .map_err(revocation_storage_error)?;
    Ok(StatusResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_other_sessions_core(
    user_id: impl AsRef<str>,
    current_session: &impl AuthSession,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let all_sessions = ctx.session_manager().list_user_sessions(user_id).await?;
    for session in all_sessions {
        if session.token() != current_session.token() {
            ctx.database.delete_session(session.token()).await?;
        }
    }
    Ok(StatusResponse { status: true })
}

fn revocation_storage_error(error: AuthError) -> AuthError {
    tracing::error!(error = %error, "Session revocation failed");
    AuthError::Upstream {
        status: 500,
        code: "INTERNAL_SERVER_ERROR",
        message: "Internal Server Error",
    }
}

fn session_authorization_error(error: AuthError) -> AuthError {
    if matches!(error, AuthError::Unauthenticated) {
        AuthError::Upstream {
            status: 401,
            code: "UNAUTHORIZED",
            message: "Unauthorized",
        }
    } else {
        error
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::test_helpers;
    use alibi_core::config::AccountConfig;
    use alibi_core::utils::cookie_utils::related_cookie_name;
    use alibi_core::wire::SessionView;
    use alibi_core::{CreateSession, CreateUser};
    use chrono::{Duration, Utc};

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_get_session_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/get-session",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_get_session(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(
            (*(*(response_data)
                .get("session")
                .unwrap_or(&serde_json::Value::Null))
            .get("token")
            .unwrap_or(&serde_json::Value::Null))
            .as_str()
            .unwrap(),
            session.token
        );
        assert_eq!(
            (*(*(response_data)
                .get("user")
                .unwrap_or(&serde_json::Value::Null))
            .get("email")
            .unwrap_or(&serde_json::Value::Null))
            .as_str()
            .map(ToOwned::to_owned),
            Some("test@example.com".to_owned())
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_get_session_unauthorized() {
        // /get-session returns 200 with null body when unauthenticated.
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, _session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req =
            test_helpers::create_auth_request_no_query(HttpMethod::Get, "/get-session", None, None);
        let response = plugin.handle_get_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid JSON");
        assert!(body.is_null());
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_sign_out_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/sign-out",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let response_data: SuccessResponse = serde_json::from_str(&body_str).unwrap();
        assert!(response_data.success);

        let session_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session_check.is_none());
    }

    #[tokio::test]
    async fn test_sign_out_clears_account_cookie_when_enabled() {
        let plugin = SessionManagementPlugin::new();
        let config = test_helpers::create_test_config().account(AccountConfig {
            store_account_cookie: true,
            ..Default::default()
        });
        let ctx = test_helpers::create_test_context_with_config(config).await;
        let (_user, session) = test_helpers::create_user_and_session(
            &ctx,
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/sign-out",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

        let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
        assert!(
            response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&account_cookie_name)),
            "sign-out should clear the account_data cookie when store_account_cookie is enabled"
        );
    }

    #[tokio::test]
    async fn test_sign_out_does_not_emit_account_cookie_when_disabled() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/sign-out",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.handle_sign_out(&req, &ctx).await.unwrap();

        let account_cookie_name = format!("{}=", related_cookie_name(&ctx.config, "account_data"));
        assert!(
            !response
                .headers
                .get_all("Set-Cookie")
                .any(|cookie| cookie.starts_with(&account_cookie_name)),
            "sign-out should not emit account_data clearing cookies when store_account_cookie is disabled"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_list_sessions_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_session2 = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("another-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        ctx.database.create_session(create_session2).await.unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/list-sessions",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[tokio::test]
    async fn test_list_sessions_filters_impersonated_sessions_when_admin_plugin_is_enabled() {
        let plugin = SessionManagementPlugin::new();
        let (mut ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;
        ctx.set_metadata("admin.enabled", serde_json::Value::Bool(true));

        let direct_session = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("another-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        ctx.database.create_session(direct_session).await.unwrap();

        let impersonated_session = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("10.0.0.5".to_owned()),
            user_agent: Some("impersonated-agent".to_owned()),
            impersonated_by: Some("admin-user".to_owned()),
            active_organization_id: None,
            active_team_id: None,
        };
        let impersonated = ctx
            .database
            .create_session(impersonated_session)
            .await
            .unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/list-sessions",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_sessions(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let body_str = String::from_utf8(response.body).unwrap();
        let sessions: Vec<SessionView> = serde_json::from_str(&body_str).unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(
            sessions
                .iter()
                .all(|candidate| candidate.token != impersonated.token),
            "impersonated sessions should not be returned from /list-sessions"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_revoke_session_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_session2 = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("another-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        let session2 = ctx.database.create_session(create_session2).await.unwrap();

        let body = serde_json::json!({ "token": session2.token });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-session",
            Some(&session.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let session2_check = ctx.database.get_session(&session2.token).await.unwrap();
        assert!(session2_check.is_none());

        let session1_check = ctx.database.get_session(&session.token).await.unwrap();
        assert!(session1_check.is_some());
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_revoke_session_forbidden_different_user() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user1, session1) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_user2 = CreateUser::new()
            .with_email("user2@example.com")
            .with_name("User Two");
        let user2 = ctx.database.create_user(create_user2).await.unwrap();

        let create_session2 = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user2.id,
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("another-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        let session2 = ctx.database.create_session(create_session2).await.unwrap();

        let body = serde_json::json!({ "token": session2.token });
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-session",
            Some(&session1.token),
            Some(body.to_string().into_bytes()),
        );

        let response = plugin.handle_revoke_session(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("status").unwrap_or(&serde_json::Value::Null)),
            true
        );

        let still_exists = ctx.database.get_session(&session2.token).await.unwrap();
        assert!(
            still_exists.is_some(),
            "other user's session must not be revoked"
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_revoke_sessions_success() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, user, session1) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let create_session2 = CreateSession {
            additional_fields: alibi_core::field_policy::FieldValues::default(),
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(24),
            ip_address: Some("192.168.1.1".to_owned()),
            user_agent: Some("another-agent".to_owned()),
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        };
        ctx.database.create_session(create_session2).await.unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-sessions",
            Some(&session1.token),
            Some(b"{}".to_vec()),
        );
        let response = plugin.handle_revoke_sessions(&req, &ctx).await.unwrap();

        assert_eq!(response.status, 200);

        let user_sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
        assert_eq!(user_sessions.len(), 0);
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_plugin_routes() {
        let plugin = SessionManagementPlugin::new();
        let routes = AuthPlugin::<
            alibi_seaorm::store::__private_test_support::bundled_schema::BundledSchema,
        >::routes(&plugin);

        assert_eq!(routes.len(), 8);
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/get-session" && r.method == HttpMethod::Get)
        );
        // Upstream serves `/get-session` on both methods.
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/get-session" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/sign-out" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/list-sessions" && r.method == HttpMethod::Get)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/revoke-session" && r.method == HttpMethod::Post)
        );
        assert!(
            routes
                .iter()
                .any(|r| r.path == "/revoke-sessions" && r.method == HttpMethod::Post)
        );
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_plugin_on_request_routing() {
        let plugin = SessionManagementPlugin::new();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        // Test valid route
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/get-session",
            Some(&session.token),
            None,
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().status, 200);

        // POST /get-session is served, but rejected with 405 until
        // `session.defer_session_refresh` is enabled.
        let req_2 = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/get-session",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response_2 = plugin.on_request(&req_2, &ctx).await.unwrap().unwrap();
        assert_eq!(response_2.status, 405);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response_2.body).unwrap(),
            serde_json::json!({
                "code": "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
                "message": "POST method requires deferSessionRefresh to be enabled in session config",
            }),
        );
        assert_eq!(
            response_2.headers.get("cache-control"),
            Some(&"no-store".to_owned())
        );
        assert_eq!(
            response_2.headers.get("pragma"),
            Some(&"no-cache".to_owned())
        );

        // Test invalid route
        let req_3 = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/invalid-route",
            Some(&session.token),
            None,
        );
        let response_3 = plugin.on_request(&req_3, &ctx).await.unwrap();
        assert!(response_3.is_none());
    }

    // Upstream reference: packages/better-auth/src/api/routes/session-api.test.ts :: describe("session") and packages/better-auth/src/api/routes/sign-out.test.ts :: describe("sign-out"); adapted to the Rust session-management plugin.
    #[tokio::test]
    async fn test_configuration() {
        let plugin = SessionManagementPlugin::new()
            .enable_session_listing(false)
            .enable_session_revocation(false)
            .require_authentication(false);

        assert!(!plugin.config.enable_session_listing);
        assert!(!plugin.config.enable_session_revocation);
        assert!(!plugin.config.require_authentication);

        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("test@example.com")
                .with_name("Test User"),
            Duration::hours(24),
        )
        .await;

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/list-sessions",
            Some(&session.token),
            None,
        );
        let response = plugin.on_request(&req, &ctx).await.unwrap();
        assert!(response.is_none());

        let req_2 = test_helpers::create_auth_request_no_query(
            HttpMethod::Post,
            "/revoke-session",
            Some(&session.token),
            Some(b"{}".to_vec()),
        );
        let response_2 = plugin.on_request(&req_2, &ctx).await.unwrap();
        assert!(response_2.is_none());
    }
}
// LCOV_EXCL_STOP
