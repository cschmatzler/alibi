//! Browser-local selection and revocation of several authenticated accounts.

use super::authentication_helpers::{JsonField, RequestBody, parse_body};
use super::helpers::delete_session_cookie_headers;
use alibi_core::utils::cookie_utils::{
    create_derived_session_cookie, create_session_cookie_with_max_age, create_session_like_cookie,
    related_cookie_name, sign_cookie_value, verify_cookie_value,
};
use alibi_core::{
    AuthContext, AuthError, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, AuthUser, HttpMethod,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

/// Number of distinct accounts retained in this browser's signed cookies.
#[derive(Clone, Debug)]
pub struct MultiSessionConfig {
    /// Raw JavaScript number comparison: zero and negative limits suppress proofs,
    /// fractional limits admit their integer floor, and NaN/positive infinity
    /// admit every proof. No eviction or defaulting is performed.
    pub maximum_sessions: f64,
}

impl Default for MultiSessionConfig {
    fn default() -> Self {
        Self {
            maximum_sessions: 5.0,
        }
    }
}

#[derive(Clone, Default)]
pub struct MultiSessionPlugin {
    config: MultiSessionConfig,
}

impl std::fmt::Debug for MultiSessionPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiSessionPlugin").finish_non_exhaustive()
    }
}

impl MultiSessionPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub const fn with_config(config: MultiSessionConfig) -> Self {
        Self { config }
    }

    fn cookie_name(token: &str, ctx: &AuthContext<impl AuthSchema>) -> String {
        format!(
            "{}_multi-{}",
            related_cookie_name(&ctx.config, "session_token"),
            token.to_lowercase()
        )
    }

    fn cookie_value(req: &AuthRequest, name: &str) -> Option<String> {
        req.headers
            .get("cookie")
            .into_iter()
            .flat_map(|header| cookie::Cookie::split_parse(header).flatten())
            .filter(|cookie| cookie.name() == name)
            .map(|cookie| cookie.value().to_owned())
            .last()
    }

    fn set_active_cookie(
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        token: &str,
        response: &mut AuthResponse,
    ) -> AuthResult<()> {
        let name = related_cookie_name(&ctx.config, "dont_remember");
        let dont_remember = Self::cookie_value(req, &name)
            .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
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
            )?,
        );
        if dont_remember {
            response.headers.append(
                "set-cookie",
                create_session_like_cookie(
                    &name,
                    &sign_cookie_value("true", ctx.config.current_secret()),
                    None,
                    &ctx.config,
                )?,
            );
        }
        Ok(())
    }

    fn multi_cookies(req: &AuthRequest) -> Vec<(String, String)> {
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
                cookie.value().clone_into(value);
            } else {
                cookies.push((cookie.name().to_owned(), cookie.value().to_owned()));
            }
        }
        cookies
    }

    fn signed_tokens(
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> Vec<(String, String)> {
        Self::multi_cookies(req)
            .into_iter()
            .filter_map(|(name, value)| {
                verify_cookie_value(&value, ctx.config.current_secret()).map(|token| (name, token))
            })
            .collect()
    }

    async fn list(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let tokens = Self::session_tokens(req, ctx);
        let now = Utc::now();
        let mut seen_users = std::collections::HashSet::new();
        let mut listed = Vec::new();
        for session in ctx.database.get_sessions_by_tokens_record(&tokens).await? {
            if session.expires_at() > now
                && session.active()
                && let Some(user) = ctx.session_user(&session).await?
                && seen_users.insert(user.id().to_string())
            {
                listed.push(json!({
                    "session": ctx.session_view(&session),
                    "user": ctx.user_view(&user),
                }));
            }
        }
        Ok(AuthResponse::json(200, &listed)?)
    }

    fn session_tokens(req: &AuthRequest, ctx: &AuthContext<impl AuthSchema>) -> Vec<String> {
        Self::signed_tokens(req, ctx)
            .into_iter()
            .map(|(_, token)| token)
            .collect()
    }

    async fn emit_selected_snapshot<S: AuthSchema>(
        ctx: &AuthContext<S>,
        user: &S::User,
        session: &impl AuthSession,
    ) -> AuthResult<()> {
        let user_view = ctx.user_view(user);
        let session_view = ctx.session_view(session);
        alibi_core::session::cookie_cache::runtime::emit_issuance_snapshot(
            ctx,
            alibi_core::CacheVersionContext::created(
                user_view.clone(),
                session_view.clone(),
                user_view,
                session_view,
            ),
        )
        .await
    }

    /// The cookie name and verified token a request's `sessionToken` selects.
    fn selected_token(
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
        body: &SessionTokenRequest,
    ) -> AuthResult<(String, String)> {
        let name = Self::cookie_name(&body.session_token, ctx);
        let token = Self::cookie_value(req, &name)
            .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
            .filter(|token| !token.is_empty())
            .ok_or_else(invalid_token)?;
        Ok((name, token))
    }

    async fn set_active<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body: SessionTokenRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let (name, token) = Self::selected_token(req, ctx, &body)?;
        let session = ctx.database.get_session_record(&token).await?;
        let session = session.filter(|session| session.expires_at() > Utc::now());
        let Some(session) = session else {
            let mut response = invalid_token().to_auth_response();
            response.headers.append(
                "set-cookie",
                create_derived_session_cookie(&name, "", true, &ctx.config)?,
            );
            return Ok(response);
        };
        let user = ctx
            .session_user(&session)
            .await?
            .ok_or_else(invalid_token)?;
        let mut response = AuthResponse::json(
            200,
            &json!({"session":ctx.session_view(&session),"user":ctx.user_view(&user)}),
        )?;
        Self::emit_selected_snapshot(ctx, &user, &session).await?;
        Self::set_active_cookie(req, ctx, session.token(), &mut response)?;
        super::helpers::record_completed_session::<S>(&user, session.stored());
        Ok(response)
    }

    async fn revoke<S: AuthSchema>(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let body: SessionTokenRequest = match parse_body(req) {
            Ok(body) => body,
            Err(response) => return Ok(response),
        };
        let (_, current_session) = super::helpers::ordinary_session(req, ctx).await?;
        let (name, token) = Self::selected_token(req, ctx, &body)?;
        ctx.database.delete_session(&token).await?;
        let mut response = AuthResponse::json(200, &json!({"status":true}))?;
        response.headers.append(
            "set-cookie",
            create_derived_session_cookie(&name, "", true, &ctx.config)?,
        );
        if current_session.token() != token {
            return Ok(response);
        }
        let tokens = Self::session_tokens(req, ctx);
        let mut next = None;
        for session in ctx.database.get_sessions_by_tokens_record(&tokens).await? {
            if session.expires_at() > Utc::now() && ctx.session_user(&session).await?.is_some() {
                next = Some(session);
                break;
            }
        }
        if let Some(session) = next {
            let user = ctx
                .session_user(&session)
                .await?
                .ok_or(AuthError::UserNotFound)?;
            Self::emit_selected_snapshot(ctx, &user, &session).await?;
            Self::set_active_cookie(req, ctx, session.token(), &mut response)?;
        } else {
            for header in delete_session_cookie_headers(&ctx.config)? {
                response.headers.append("set-cookie", header);
            }
        }
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

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for MultiSessionPlugin {
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
        let response = match (req.method(), req.path()) {
            (HttpMethod::Get, "/multi-session/list-device-sessions") => self.list(req, ctx).await?,
            (HttpMethod::Post, "/multi-session/set-active") => self.set_active(req, ctx).await?,
            (HttpMethod::Post, "/multi-session/revoke") => self.revoke(req, ctx).await?,
            _ => return Ok(None),
        };
        Ok(Some(response))
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        mut response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        if req.path() == "/sign-out" {
            for (name, token) in Self::signed_tokens(req, ctx) {
                // The logout hook grants retirement only to truthy signed payloads.
                // List and fallback intentionally retain string-valued semantics.
                if token.is_empty() {
                    continue;
                }
                ctx.database.delete_session(&token).await?;
                response.headers.append(
                    "set-cookie",
                    create_derived_session_cookie(
                        &name.to_lowercase().replacen("__secure-", "__Secure-", 1),
                        "",
                        true,
                        &ctx.config,
                    )?,
                );
            }
            return Ok(response);
        }
        if response.headers.get_all("set-cookie").next().is_none() {
            return Ok(response);
        }
        let Some((user, session)) =
            alibi_core::session::cookie_cache::runtime::published_session(req)
        else {
            return Ok(response);
        };
        let name = Self::cookie_name(session.token(), ctx);
        if Self::cookie_value(req, &name).is_some_and(|value| !value.is_empty())
            || response.headers.get_all("set-cookie").any(|header| {
                cookie::Cookie::parse(header.clone()).is_ok_and(|cookie| cookie.name() == name)
            })
        {
            return Ok(response);
        }
        let cookies = Self::signed_tokens(req, ctx);
        let mut tokens_to_delete = Vec::new();
        for (old_name, token) in &cookies {
            if token.is_empty() {
                continue;
            }
            if let Some(old) = ctx.database.get_session_record(token).await?
                && old.user_id() == user.id()
            {
                tokens_to_delete.push(token);
                response.headers.append(
                    "set-cookie",
                    create_derived_session_cookie(old_name, "", true, &ctx.config)?,
                );
            }
        }
        // Resolve every proof before deleting: multiple names can carry the same token.
        for token in &tokens_to_delete {
            ctx.database.delete_session(token).await?;
        }
        let removed = tokens_to_delete.len();
        // Upstream counts every named cookie, including invalid signatures.
        let count = Self::multi_cookies(req).len();
        #[expect(
            clippy::cast_precision_loss,
            reason = "Match upstream JavaScript numeric comparison"
        )]
        let budget = (count.saturating_sub(removed) + 1) as f64;
        if budget > self.config.maximum_sessions {
            return Ok(response);
        }
        let signed = sign_cookie_value(session.token(), ctx.config.current_secret());
        response.headers.append(
            "set-cookie",
            create_derived_session_cookie(&name, &signed, false, &ctx.config)?,
        );
        Ok(response)
    }
}

const fn invalid_token() -> AuthError {
    AuthError::Upstream {
        status: 401,
        code: "INVALID_SESSION_TOKEN",
        message: "Invalid session token",
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "SQLite plugin contract assertions"
    )]

    use super::*;
    use crate::test_helpers::{
        create_auth_json_request_no_query, create_test_context, create_user_and_session,
    };
    use alibi_core::utils::cookie_utils::create_session_cookie;
    use alibi_core::{CreateSession, CreateUser};
    use chrono::Duration;

    fn request_with_cookies(
        method: HttpMethod,
        path: &str,
        cookies: &[String],
        body: Option<serde_json::Value>,
    ) -> AuthRequest {
        let mut request = create_auth_json_request_no_query(method, path, None, body);
        request.headers.insert("cookie".into(), cookies.join("; "));
        request
    }

    fn pair(header: &str) -> String {
        header.split(';').next().unwrap().to_owned()
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn signed_browser_sessions_select_other_accounts_and_reject_unrelated_tokens() {
        let ctx = create_test_context().await;
        let plugin = MultiSessionPlugin::new();
        let (bob, _) = create_user_and_session(
            &ctx,
            CreateUser::new().with_email("bob@example.test"),
            Duration::days(1),
        )
        .await;
        let (alice, _) = create_user_and_session(
            &ctx,
            CreateUser::new().with_email("alice@example.test"),
            Duration::days(1),
        )
        .await;
        let custom = |user_id: String, token: &str| CreateSession {
            user_id,
            token: Some(token.to_owned()),
            expires_at: Utc::now() + Duration::days(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: alibi_core::field_policy::FieldValues::default(),
        };
        let bob_session = ctx
            .database
            .create_session(custom(bob.id.clone(), "z-last"))
            .await
            .unwrap();
        let alice_session = ctx
            .database
            .create_session(custom(alice.id.clone(), "a-first"))
            .await
            .unwrap();
        let cookie_for = |token: &str| {
            format!(
                "{}={}",
                MultiSessionPlugin::cookie_name(token, &ctx),
                sign_cookie_value(token, &ctx.config.secret)
            )
        };
        let cookies = vec![
            pair(&create_session_cookie(&bob_session.token, &ctx.config).unwrap()),
            cookie_for(&bob_session.token),
            cookie_for(&alice_session.token),
        ];
        let request = request_with_cookies(
            HttpMethod::Get,
            "/multi-session/list-device-sessions",
            &cookies,
            None,
        );
        let listed = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
        let body: serde_json::Value = serde_json::from_slice(&listed.body).unwrap();
        assert_eq!(body.as_array().unwrap().len(), 2);
        assert_eq!(body[0]["user"]["id"], alice.id);
        assert_eq!(body[1]["user"]["id"], bob.id);
        let duplicate = request_with_cookies(
            HttpMethod::Get,
            "/multi-session/list-device-sessions",
            &[
                cookie_for(&alice_session.token),
                format!(
                    "{}=invalid-last",
                    MultiSessionPlugin::cookie_name(&alice_session.token, &ctx)
                ),
                cookie_for(&bob_session.token),
            ],
            None,
        );
        let duplicate = plugin.on_request(&duplicate, &ctx).await.unwrap().unwrap();
        let listed_2: serde_json::Value = serde_json::from_slice(&duplicate.body).unwrap();
        assert_eq!(listed_2.as_array().unwrap().len(), 1);
        assert_eq!(listed_2[0]["user"]["id"], bob.id);
        for (values, succeeds) in [
            (
                vec![
                    cookie_for(&alice_session.token),
                    format!(
                        "{}=invalid-last",
                        MultiSessionPlugin::cookie_name(&alice_session.token, &ctx)
                    ),
                ],
                false,
            ),
            (
                vec![
                    format!(
                        "{}=invalid-first",
                        MultiSessionPlugin::cookie_name(&alice_session.token, &ctx)
                    ),
                    cookie_for(&alice_session.token),
                ],
                true,
            ),
        ] {
            let selection = request_with_cookies(
                HttpMethod::Post,
                "/multi-session/set-active",
                &values,
                Some(json!({"sessionToken":alice_session.token})),
            );
            let result = plugin.on_request(&selection, &ctx).await;
            if succeeds {
                assert_eq!(result.unwrap().unwrap().status, 200);
            } else {
                assert_eq!(result.unwrap_err().status_code(), 401);
            }
        }
        for path in ["/multi-session/revoke", "/multi-session/set-active"] {
            let empty_proof = request_with_cookies(
                HttpMethod::Post,
                path,
                &[
                    pair(&create_session_cookie(&bob_session.token, &ctx.config).unwrap()),
                    format!(
                        "{}={}",
                        MultiSessionPlugin::cookie_name(&alice_session.token, &ctx),
                        sign_cookie_value("", &ctx.config.secret)
                    ),
                ],
                Some(json!({"sessionToken":alice_session.token})),
            );
            let rejected = plugin
                .on_request(&empty_proof, &ctx)
                .await
                .unwrap_or_else(|error| Some(error.to_auth_response()))
                .unwrap();
            assert_eq!(rejected.status, 401);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&rejected.body).unwrap()["code"],
                "INVALID_SESSION_TOKEN"
            );
            assert!(rejected.headers.get_all("set-cookie").next().is_none());
            assert!(
                ctx.database
                    .get_session(&alice_session.token)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                ctx.database
                    .get_session(&bob_session.token)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        let select = request_with_cookies(
            HttpMethod::Post,
            "/multi-session/set-active",
            &cookies,
            Some(json!({"sessionToken":alice_session.token})),
        );
        let selected = plugin.on_request(&select, &ctx).await.unwrap().unwrap();
        assert_eq!(selected.status, 200);
        let body_2: serde_json::Value = serde_json::from_slice(&selected.body).unwrap();
        assert_eq!(body_2["user"]["id"], alice.id);
        assert_eq!(body_2["session"]["userId"], alice.id);
        let unrelated = create_auth_json_request_no_query(
            HttpMethod::Post,
            "/multi-session/set-active",
            Some(&bob_session.token),
            Some(json!({"sessionToken":alice_session.token})),
        );
        assert_eq!(
            plugin
                .on_request(&unrelated, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(
            ctx.database
                .get_session(&alice_session.token)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn cookie_tampering_expiry_revocation_fallback_and_logout_preserve_state() {
        let ctx = create_test_context().await;
        let plugin = MultiSessionPlugin::new();
        let (_, one) = create_user_and_session(
            &ctx,
            CreateUser::new().with_email("one@example.test"),
            Duration::days(1),
        )
        .await;
        let (_, two) = create_user_and_session(
            &ctx,
            CreateUser::new().with_email("two@example.test"),
            Duration::days(1),
        )
        .await;
        let first = format!(
            "{}={}",
            MultiSessionPlugin::cookie_name(&one.token, &ctx),
            sign_cookie_value(&one.token, &ctx.config.secret)
        );
        let second = format!(
            "{}={}",
            MultiSessionPlugin::cookie_name(&two.token, &ctx),
            sign_cookie_value(&two.token, &ctx.config.secret)
        );
        let cookies = vec![
            pair(&create_session_cookie(&one.token, &ctx.config).unwrap()),
            first.clone(),
            second.clone(),
        ];
        let revoke = request_with_cookies(
            HttpMethod::Post,
            "/multi-session/revoke",
            &cookies,
            Some(json!({"sessionToken":one.token})),
        );
        let revoked = plugin.on_request(&revoke, &ctx).await.unwrap().unwrap();
        assert_eq!(revoked.status, 200);
        assert!(
            ctx.database
                .get_session(&one.token)
                .await
                .unwrap()
                .is_none()
        );
        let new_session_cookie = revoked
            .headers
            .get_all("set-cookie")
            .filter_map(|v| cookie::Cookie::parse(v.clone()).ok())
            .find(|v| v.name() == ctx.config.session.cookie_name)
            .unwrap();
        assert_eq!(
            verify_cookie_value(new_session_cookie.value(), &ctx.config.secret),
            Some(two.token.clone())
        );
        let tampered = vec![second.replace('=', "=tampered-")];
        let select = request_with_cookies(
            HttpMethod::Post,
            "/multi-session/set-active",
            &tampered,
            Some(json!({"sessionToken":two.token})),
        );
        assert_eq!(
            plugin
                .on_request(&select, &ctx)
                .await
                .unwrap_err()
                .status_code(),
            401
        );
        ctx.database
            .update_session_expiry(&two.token, Utc::now() - Duration::seconds(1))
            .await
            .unwrap();
        let expired = request_with_cookies(
            HttpMethod::Post,
            "/multi-session/set-active",
            std::slice::from_ref(&second),
            Some(json!({"sessionToken":two.token})),
        );
        let expired = plugin.on_request(&expired, &ctx).await.unwrap().unwrap();
        assert_eq!(expired.status, 401);
        assert!(
            expired
                .headers
                .get("set-cookie")
                .unwrap()
                .contains("Max-Age=0")
        );
        let signout = request_with_cookies(HttpMethod::Post, "/sign-out", &[second], None);
        _ = plugin
            .after_request(
                &signout,
                &ctx,
                AuthResponse::json(200, &json!({"success":true})).unwrap(),
            )
            .await
            .unwrap();
        assert!(
            ctx.database
                .get_session(&two.token)
                .await
                .unwrap()
                .is_none()
        );
    }
}
// LCOV_EXCL_STOP
