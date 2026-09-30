//! Browser-local selection and revocation of several authenticated accounts.

use async_trait::async_trait;
use better_auth_core::utils::cookie_utils::{
    create_clear_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name, sign_cookie_value, verify_cookie_value,
};
use better_auth_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, AuthUser, HttpMethod,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use super::authentication_helpers::{JsonField, RequestBody, parse_body};
use super::helpers::{delete_session_cookie_headers, response_session};

/// Number of distinct accounts retained in this browser's signed cookies.
#[derive(Clone, Debug)]
pub struct MultiSessionConfig {
    pub maximum_sessions: usize,
}

impl Default for MultiSessionConfig {
    fn default() -> Self {
        Self {
            maximum_sessions: 5,
        }
    }
}

#[derive(Clone, Default)]
pub struct MultiSessionPlugin {
    config: MultiSessionConfig,
}

impl MultiSessionPlugin {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_config(config: MultiSessionConfig) -> Self {
        Self { config }
    }

    fn cookie_name(&self, token: &str, ctx: &AuthContext<impl AuthSchema>) -> String {
        format!(
            "{}_multi-{}",
            ctx.config.session.cookie_name,
            token.to_lowercase()
        )
    }

    fn cookie_value(&self, req: &AuthRequest, name: &str) -> Option<String> {
        req.headers
            .get("cookie")
            .into_iter()
            .flat_map(|header| cookie::Cookie::split_parse(header).flatten())
            .filter(|cookie| cookie.name() == name)
            .map(|cookie| cookie.value().to_owned())
            .last()
    }

    fn set_active_cookie(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        token: &str,
        response: &mut AuthResponse,
    ) {
        let name = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = self
            .cookie_value(req, &name)
            .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
            .is_some_and(|value| !value.is_empty());
        response.headers.append(
            "set-cookie",
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
                "set-cookie",
                create_session_like_cookie(
                    &name,
                    &sign_cookie_value("true", &ctx.config.secret),
                    None,
                    &ctx.config,
                ),
            );
        }
    }

    fn multi_cookies(&self, req: &AuthRequest) -> Vec<(String, String)> {
        let mut cookies: Vec<(String, String)> = Vec::new();
        for cookie in req
            .headers
            .get("cookie")
            .into_iter()
            .flat_map(|header| cookie::Cookie::split_parse(header).flatten())
            .filter(|cookie| cookie.name().contains("_multi-"))
        {
            // Upstream parses to a Map: duplicate names use the last value,
            // while retaining the name's first insertion position.
            if let Some((_, value)) = cookies.iter_mut().find(|(name, _)| name == cookie.name()) {
                *value = cookie.value().to_owned();
            } else {
                cookies.push((cookie.name().to_owned(), cookie.value().to_owned()));
            }
        }
        cookies
    }

    fn signed_tokens(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> Vec<(String, String)> {
        self.multi_cookies(req)
            .into_iter()
            .filter_map(|(name, value)| {
                verify_cookie_value(&value, &ctx.config.secret).map(|token| (name, token))
            })
            .collect()
    }

    async fn list(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let mut sessions = Vec::new();
        let tokens = self
            .signed_tokens(req, ctx)
            .into_iter()
            .map(|(_, token)| token)
            .collect::<Vec<_>>();
        for session in ctx.database.get_sessions_by_tokens(&tokens).await? {
            if session.expires_at() > Utc::now()
                && session.active()
                && let Some(user) = ctx
                    .database
                    .get_user_by_id(session.user_id().as_ref())
                    .await?
            {
                sessions.push((session, user));
            }
        }
        let mut seen = std::collections::HashSet::new();
        let values:Vec<_>=sessions.into_iter().filter(|(_,user)|seen.insert(user.id().to_string()))
            .map(|(session,user)|json!({"session":ctx.session_view(&session),"user":ctx.user_view(&user)})).collect();
        Ok(AuthResponse::json(200, &values)?)
    }

    async fn select(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        revoke: bool,
    ) -> AuthResult<AuthResponse> {
        let body: SessionTokenRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let current = if revoke {
            Some(ctx.require_session(req).await?)
        } else {
            None
        };
        let name = self.cookie_name(&body.session_token, ctx);
        let token = self
            .cookie_value(req, &name)
            .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
            .ok_or_else(invalid_token)?;
        if revoke {
            ctx.database.delete_session(&token).await?;
            let mut response = AuthResponse::json(200, &json!({"status":true}))?;
            response
                .headers
                .append("set-cookie", create_clear_cookie(&name, &ctx.config));
            if current
                .as_ref()
                .is_some_and(|(_, session)| session.token() == token)
            {
                let mut next = None;
                let tokens = self
                    .signed_tokens(req, ctx)
                    .into_iter()
                    .map(|(_, token)| token)
                    .collect::<Vec<_>>();
                for session in ctx.database.get_sessions_by_tokens(&tokens).await? {
                    if session.expires_at() > Utc::now()
                        && ctx
                            .database
                            .get_user_by_id(session.user_id().as_ref())
                            .await?
                            .is_some()
                    {
                        next = Some(session);
                        break;
                    }
                }
                match next {
                    Some(session) => {
                        self.set_active_cookie(req, ctx, session.token(), &mut response)
                    }
                    None => {
                        for header in delete_session_cookie_headers(&ctx.config) {
                            response.headers.append("set-cookie", header);
                        }
                    }
                }
            }
            return Ok(response);
        }
        let session = ctx.database.get_session(&token).await?;
        let session = session.filter(|session| session.expires_at() > Utc::now());
        let Some(session) = session else {
            let mut response = invalid_token().to_auth_response();
            response
                .headers
                .append("set-cookie", create_clear_cookie(&name, &ctx.config));
            return Ok(response);
        };
        let user = ctx
            .database
            .get_user_by_id(session.user_id().as_ref())
            .await?
            .ok_or_else(invalid_token)?;
        let mut response = AuthResponse::json(
            200,
            &json!({"session":ctx.session_view(&session),"user":ctx.user_view(&user)}),
        )?;
        self.set_active_cookie(req, ctx, session.token(), &mut response);
        Ok(response)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionTokenRequest {
    session_token: String,
}
impl RequestBody for SessionTokenRequest {
    const FIELDS: &'static [JsonField] = &[JsonField::string("sessionToken", true)];
}

fn invalid_token() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_SESSION_TOKEN",
        message: "Invalid session token",
    }
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for MultiSessionPlugin {
    fn name(&self) -> &'static str {
        "multi-session"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::get(
                "/multi-session/list-device-sessions",
                "list_device_sessions",
            ),
            AuthRoute::post("/multi-session/set-active", "set_active_session"),
            AuthRoute::post("/multi-session/revoke", "revoke_device_session"),
        ]
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, "/multi-session/list-device-sessions") => {
                Ok(Some(self.list(req, ctx).await?))
            }
            (HttpMethod::Post, "/multi-session/set-active") => {
                Ok(Some(self.select(req, ctx, false).await?))
            }
            (HttpMethod::Post, "/multi-session/revoke") => {
                Ok(Some(self.select(req, ctx, true).await?))
            }
            _ => Ok(None),
        }
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if req.path() == "/sign-out" {
            for (name, token) in self.signed_tokens(req, ctx) {
                ctx.database.delete_session(&token).await?;
                response.headers.append(
                    "set-cookie",
                    create_clear_cookie(
                        &name.to_lowercase().replacen("__secure-", "__Secure-", 1),
                        &ctx.config,
                    ),
                );
            }
            return Ok(response);
        }
        let Some(issued) = response_session(ctx, &response).await? else {
            return Ok(response);
        };
        let name = self.cookie_name(issued.session.token(), ctx);
        if self
            .cookie_value(req, &name)
            .is_some_and(|value| !value.is_empty())
            || response.headers.get_all("set-cookie").any(|header| {
                cookie::Cookie::parse(header.clone()).is_ok_and(|cookie| cookie.name() == name)
            })
        {
            return Ok(response);
        }
        let cookies = self.signed_tokens(req, ctx);
        let mut removed = 0;
        for (old_name, token) in &cookies {
            if let Some(old) = ctx.database.get_session(token).await?
                && old.user_id() == issued.user.id()
            {
                ctx.database.delete_session(token).await?;
                response
                    .headers
                    .append("set-cookie", create_clear_cookie(old_name, &ctx.config));
                removed += 1;
            }
        }
        // Upstream counts every named cookie, including invalid signatures.
        let count = self.multi_cookies(req).len();
        if count.saturating_sub(removed) + 1 > self.config.maximum_sessions {
            return Ok(response);
        }
        let signed = sign_cookie_value(issued.session.token(), &ctx.config.secret);
        response.headers.append(
            "set-cookie",
            create_session_like_cookie(
                &name,
                &signed,
                Some(ctx.config.session.expires_in.num_seconds()),
                &ctx.config,
            ),
        );
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
