#[cfg(test)]
mod tests;

use async_trait::async_trait;

use serde::{Deserialize, Serialize};

use better_auth_core::entity::{AuthSession, AuthUser};

use better_auth_core::wire::SessionView;

use better_auth_core::{AuthContext, AuthPlugin, AuthRoute};

use better_auth_core::{AuthError, AuthResult};

use better_auth_core::{AuthRequest, AuthResponse, HttpMethod};

use super::StatusResponse;

use super::authentication_helpers::{JsonField, RequestBody, parse_body};

use super::helpers::{admin_plugin_enabled, delete_session_cookie_headers};

use better_auth_core::SuccessResponse;

/// Session management plugin for handling session operations
pub struct SessionManagementPlugin {
    config: SessionManagementConfig,
}

#[derive(Debug, Clone, better_auth_core::PluginConfig)]
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
impl<S: better_auth_core::AuthSchema> AuthPlugin<S> for SessionManagementPlugin {
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
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        use super::authentication_helpers::{json_type, validation_response};

        use better_auth_core::field_policy::{FieldInputError, SessionFields};

        use better_auth_core::utils::json::JsValue;

        use better_auth_core::utils::cookie_utils::{
            create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
            sign_cookie_value, verify_cookie_value,
        };

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
            Some(body) => match better_auth_core::utils::json::from_slice(body) {
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
        let (_user, session) = match ctx.require_session(req).await {
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
            .update_session_fields(session.token(), allowed)
            .await
        {
            Ok(updated) => updated,
            Err(AuthError::Internal(_)) => return Ok(AuthResponse::new(500)),
            Err(error) => return Err(error),
        };
        let Some(updated) = updated else {
            let mut response = AuthResponse::json(
                401,
                &serde_json::json!({"code":"FAILED_TO_GET_SESSION","message":"Failed to get session"}),
            )?;
            for cookie in delete_session_cookie_headers(&ctx.config) {
                response.headers.append("Set-Cookie", cookie);
            }
            return Ok(response);
        };

        let preference = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = req.header("cookie").is_some_and(|header| {
            cookie::Cookie::split_parse(header)
                .flatten()
                .find(|cookie| cookie.name() == preference)
                .and_then(|cookie| verify_cookie_value(cookie.value(), &ctx.config.secret))
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
            ),
        );
        if dont_remember {
            response = response.with_appended_header(
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
    }

    async fn handle_get_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let Some(read) = better_auth_core::cache::runtime::authenticated(ctx, req, true).await?
        else {
            return Ok(AuthResponse::json(200, &serde_json::Value::Null)?);
        };
        Ok(AuthResponse::json(
            200,
            &GetSessionResponse {
                session: read.session,
                user: match read.user {
                    better_auth_core::AuthenticatedUser::Stored(user) => ctx.user_view(&user),
                    better_auth_core::AuthenticatedUser::Cached(user) => *user,
                },
                needs_refresh: read.needs_refresh,
            },
        )?)
    }

    async fn handle_sign_out(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Some(token) = ctx.session_manager().extract_session_token(req) {
            if let Ok(Some(session)) = ctx.database.get_session(&token).await {
                drop(sign_out_core(&session, ctx).await);
            } else {
                drop(ctx.database.delete_session(&token).await);
            }
        }

        let mut response = AuthResponse::json(200, &SuccessResponse { success: true })?;
        for cookie in delete_session_cookie_headers(&ctx.config) {
            response.headers.append("Set-Cookie", cookie);
        }
        Ok(response)
    }

    async fn handle_list_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, session) = ctx
            .require_session(req)
            .await
            .map_err(session_authorization_error)?;
        if !ctx.session_manager().is_session_fresh(&session) {
            return Err(AuthError::Upstream {
                status: 403,
                code: "SESSION_NOT_FRESH",
                message: "Session is not fresh",
            });
        }
        let mut sessions = list_sessions_core(user.id(), ctx).await?;
        if admin_plugin_enabled(ctx) {
            sessions.retain(|session_2| session_2.impersonated_by.is_none());
        }
        Ok(AuthResponse::json(200, &sessions)?)
    }

    async fn handle_revoke_session(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let revoke_req: RevokeSessionRequest = match parse_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };

        let (user, _) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(session_authorization_error)?;
        let response = revoke_session_core(&user, &revoke_req.token, ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) = ctx
            .require_authoritative_session(req)
            .await
            .map_err(session_authorization_error)?;
        let response = revoke_sessions_core(user.id(), ctx).await?;
        Ok(AuthResponse::json(200, &response)?)
    }

    async fn handle_revoke_other_sessions(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, current_session) = ctx
            .require_authoritative_session(req)
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
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<SuccessResponse> {
    ctx.database.delete_session(session.token()).await?;
    Ok(SuccessResponse { success: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn list_sessions_core(
    user_id: impl AsRef<str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<SessionView>> {
    let sessions = ctx.session_manager().list_user_sessions(user_id).await?;
    Ok(sessions
        .iter()
        .map(|session| ctx.session_view(session))
        .collect())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_session_core(
    user: &impl AuthUser,
    token: &str,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    if let Some(session_to_revoke) = ctx.database.get_session(token).await?
        && session_to_revoke.user_id() == user.id()
    {
        ctx.database.delete_session(token).await?;
    }
    Ok(StatusResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_sessions_core(
    user_id: impl AsRef<str>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    ctx.database.delete_user_sessions(user_id.as_ref()).await?;
    Ok(StatusResponse { status: true })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(in crate::plugins) async fn revoke_other_sessions_core(
    user_id: impl AsRef<str>,
    current_session: &impl AuthSession,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<StatusResponse> {
    let all_sessions = ctx.session_manager().list_user_sessions(user_id).await?;
    for session in all_sessions {
        if session.token() != current_session.token() {
            ctx.database.delete_session(session.token()).await?;
        }
    }
    Ok(StatusResponse { status: true })
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
