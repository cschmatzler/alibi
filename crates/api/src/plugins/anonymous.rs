//! Anonymous accounts and their cleanup when a proven account replaces them.

use std::sync::Arc;

use async_trait::async_trait;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRequest, AuthResponse, AuthResult, AuthRoute,
    AuthSchema, AuthSession, AuthUser, CreateUser, HttpMethod, RequestMeta,
};
use rand::distributions::{Alphanumeric, DistString};
use serde_json::json;

use super::helpers::{
    apply_default_role, delete_session_cookie_headers, issue_user_session, response_session,
};

/// Application-owned generation of anonymous display names and email addresses.
#[async_trait]
pub trait AnonymousIdentity: Send + Sync {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(None)
    }
    async fn name(&self, _request: &AuthRequest) -> AuthResult<Option<String>> {
        Ok(None)
    }
}

/// Both authenticated accounts involved in an anonymous account upgrade.
pub struct AnonymousLink {
    pub anonymous_user: UserView,
    pub anonymous_session: SessionView,
    pub new_user: UserView,
    pub new_session: SessionView,
}

/// Transfer application-owned data before the anonymous account is deleted.
#[async_trait]
pub trait LinkAnonymousAccount: Send + Sync {
    async fn link(&self, accounts: &AnonymousLink, request: &AuthRequest) -> AuthResult<()>;
}

#[derive(Clone, Default)]
pub struct AnonymousConfig {
    pub email_domain_name: Option<String>,
    pub identity: Option<Arc<dyn AnonymousIdentity>>,
    pub on_link_account: Option<Arc<dyn LinkAnonymousAccount>>,
    pub disable_delete_anonymous_user: bool,
}

#[derive(Clone, Default)]
pub struct AnonymousPlugin {
    config: AnonymousConfig,
}

impl AnonymousPlugin {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_config(config: AnonymousConfig) -> Self {
        Self { config }
    }

    async fn sign_in(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Some((current, _)) = anonymous_session(req, ctx).await
            && current.is_anonymous() == Some(true)
        {
            return Ok(error(
                400,
                "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY",
                "Anonymous users cannot sign in again anonymously",
            ));
        }
        let custom = match &self.config.identity {
            Some(identity) => identity.email().await?,
            None => None,
        };
        let email = match custom.filter(|value| !value.is_empty()) {
            Some(email) => {
                if !super::authentication_helpers::is_valid_email(&email) {
                    return Ok(error(
                        400,
                        "INVALID_EMAIL_FORMAT",
                        "Email was not generated in a valid format",
                    ));
                }
                email
            }
            None => {
                let id = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
                self.config
                    .email_domain_name
                    .as_ref()
                    .filter(|domain| !domain.is_empty())
                    .map(|domain| format!("temp-{id}@{domain}"))
                    .unwrap_or_else(|| format!("{id}@anonymous.placeholder.invalid"))
            }
        };
        let name = match &self.config.identity {
            Some(identity) => identity.name(req).await?,
            None => None,
        }
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "Anonymous".to_string());
        let mut create = CreateUser::new().with_email(email).with_name(name);
        create.is_anonymous = Some(true);
        create.email_verified = Some(false);
        apply_default_role(ctx, &mut create);
        let user = ctx.database.create_user(create).await?;
        let meta = RequestMeta::from_request(req);
        let issued = issue_user_session(ctx, user.id().as_ref(), meta.ip_address, meta.user_agent)
            .await
            .map_err(|cause| match cause.into_auth_error() {
                better_auth_core::AuthError::SessionCreationCancelled => {
                    better_auth_core::AuthError::Upstream {
                        status: 400,
                        code: "COULD_NOT_CREATE_SESSION",
                        message: "Could not create session",
                    }
                }
                cause => cause,
            })?;
        let mut response = AuthResponse::json(
            200,
            &json!({"token":issued.session.token(),"user":ctx.user_view(&issued.user)}),
        )?;
        response.headers.append(
            "set-cookie",
            better_auth_core::utils::cookie_utils::create_session_cookie(
                issued.session.token(),
                &ctx.config,
            ),
        );
        Ok(response)
    }

    async fn delete(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _) =
            ctx.require_authoritative_session(req)
                .await
                .map_err(|error| match error {
                    better_auth_core::AuthError::Unauthenticated => {
                        better_auth_core::AuthError::Upstream {
                            status: 401,
                            code: "UNAUTHORIZED",
                            message: "Unauthorized",
                        }
                    }
                    error => error,
                })?;
        if self.config.disable_delete_anonymous_user {
            return Ok(error(
                400,
                "DELETE_ANONYMOUS_USER_DISABLED",
                "Deleting anonymous users is disabled",
            ));
        }
        if user.is_anonymous() != Some(true) {
            return Ok(error(403, "USER_IS_NOT_ANONYMOUS", "User is not anonymous"));
        }
        if let Err(cause) = ctx.database.delete_user_sessions(user.id().as_ref()).await {
            tracing::error!(%cause, "Failed to delete anonymous user sessions");
            return Ok(error(
                500,
                "FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS",
                "Failed to delete anonymous user sessions",
            ));
        }
        if let Err(cause) = ctx.database.delete_user(user.id().as_ref()).await {
            tracing::error!(%cause, "Failed to delete anonymous user");
            return Ok(error(
                500,
                "FAILED_TO_DELETE_ANONYMOUS_USER",
                "Failed to delete anonymous user",
            ));
        }
        let mut response = AuthResponse::json(200, &json!({"success":true}))?;
        for cookie in delete_session_cookie_headers(&ctx.config) {
            response.headers.append("set-cookie", cookie);
        }
        Ok(response)
    }
}

// Source's nested get-session disables refresh, catches failed resolution, and
// retains its real expiry cleanup/response-cookie effects on the request.
async fn anonymous_session<S: AuthSchema>(
    req: &AuthRequest,
    ctx: &AuthContext<S>,
) -> Option<(S::User, SessionView)> {
    let mut read = req.clone();
    let _ = read.query.insert("disableRefresh".into(), "true".into());
    ctx.require_session(&read).await.ok()
}

fn error(status: u16, code: &'static str, message: &'static str) -> AuthResponse {
    better_auth_core::AuthError::Upstream {
        status,
        code,
        message,
    }
    .to_auth_response()
}

#[async_trait]
impl<S: AuthSchema> AuthPlugin<S> for AnonymousPlugin {
    fn name(&self) -> &'static str {
        "anonymous"
    }
    fn routes(&self) -> Vec<AuthRoute> {
        vec![
            AuthRoute::post("/sign-in/anonymous", "sign_in_anonymous"),
            AuthRoute::post("/delete-anonymous-user", "delete_anonymous_user"),
        ]
    }
    async fn on_init(&self, ctx: &mut AuthInitContext<S>) -> AuthResult<()> {
        ctx.set_metadata("anonymous.enabled", json!(true));
        ctx.register_user_create_transform(|mut input| {
            if input.is_anonymous.is_none() {
                input.is_anonymous = Some(false);
            }
            Ok(input)
        });
        Ok(())
    }
    async fn on_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Post, "/sign-in/anonymous") => Ok(Some(self.sign_in(req, ctx).await?)),
            (HttpMethod::Post, "/delete-anonymous-user") => Ok(Some(self.delete(req, ctx).await?)),
            _ => Ok(None),
        }
    }
    async fn after_request(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<S>,
        response: AuthResponse,
    ) -> AuthResult<AuthResponse> {
        let matches = [
            "/sign-in",
            "/sign-up",
            "/callback",
            "/magic-link/verify",
            "/email-otp/verify-email",
            "/one-tap/callback",
            "/passkey/verify-authentication",
            "/phone-number/verify",
            "/verify-email",
        ]
        .iter()
        .any(|prefix| req.path().starts_with(prefix));
        if !matches {
            return Ok(response);
        }
        let Some(issued) = response_session(ctx, &response).await? else {
            return Ok(response);
        };
        let Some((old_user, old_session)) = anonymous_session(req, ctx).await else {
            return Ok(response);
        };
        if old_user.is_anonymous() != Some(true) {
            return Ok(response);
        }
        if let Some(linker) = &self.config.on_link_account {
            linker
                .link(
                    &AnonymousLink {
                        anonymous_user: ctx.user_view(&old_user),
                        anonymous_session: ctx.session_view(&old_session),
                        new_user: ctx.user_view(&issued.user),
                        new_session: ctx.session_view(&issued.session),
                    },
                    req,
                )
                .await?;
        }
        if self.config.disable_delete_anonymous_user
            || old_user.id() == issued.user.id()
            || issued.user.is_anonymous() == Some(true)
        {
            return Ok(response);
        }
        if let Err(error) = ctx.database.delete_user(old_user.id().as_ref()).await {
            tracing::error!(user_id=%old_user.id(),error=%error,"Failed to clean up anonymous account");
        }
        Ok(response)
    }
}
