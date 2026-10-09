use alibi_core::utils::cookie_utils::{
    create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
    sign_cookie_value, verify_cookie_value,
};
use alibi_core::{
    AuthAccount, AuthConfig, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult,
    AuthSchema, AuthSession, AuthUser, CreateVerification, UpdateUser,
};
use chrono::{Duration, Utc};
use serde_json::Value;

/// Whether the request carries the signed `dont_remember` preference cookie.
pub(crate) fn dont_remember_preference(req: &AuthRequest, config: &AuthConfig) -> bool {
    crate::helpers::get_cookie(req, &related_cookie_name(config, "dont_remember"))
        .and_then(|value| verify_cookie_value(&value, config.current_secret()))
        .is_some_and(|value| !value.is_empty())
}

/// Append the session cookie, plus the signed preference cookie that keeps a
/// `dont_remember` session browser-scoped.
pub(crate) fn with_session_cookies(
    response: AuthResponse,
    config: &AuthConfig,
    token: &str,
    dont_remember: bool,
) -> AuthResult<AuthResponse> {
    let max_age = (!dont_remember).then(|| config.session.expires_in.num_seconds());
    let mut response = response.with_appended_header(
        "Set-Cookie",
        create_session_cookie_with_max_age(Some(token), max_age, config)?,
    );
    if dont_remember {
        response.headers.append(
            "Set-Cookie",
            create_session_like_cookie(
                &related_cookie_name(config, "dont_remember"),
                &sign_cookie_value("true", config.current_secret()),
                None,
                config,
            )?,
        );
    }
    Ok(response)
}

pub(crate) async fn session_response<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    user: alibi_core::AdapterRecord<S::User>,
) -> AuthResult<(Value, AuthResponse)> {
    session_response_with_remember(ctx, req, user, None).await
}

pub(crate) async fn session_response_with_remember<S: AuthSchema>(
    ctx: &AuthContext<S>,
    req: &AuthRequest,
    user: alibi_core::AdapterRecord<S::User>,
    remember_me: Option<bool>,
) -> AuthResult<(Value, AuthResponse)> {
    let dont_remember = remember_me.map_or_else(
        || dont_remember_preference(req, &ctx.config),
        |remember| !remember,
    );
    let mut config = (*ctx.config).clone();
    if remember_me == Some(false) {
        config.session.expires_in = Duration::days(1);
    }
    let issuing_context = AuthContext {
        config: std::sync::Arc::new(config),
        database: std::sync::Arc::clone(&ctx.database),
        email_provider: ctx.email_provider.clone(),
        metadata: ctx.metadata.clone(),
        extensions: ctx.extensions.clone(),
    };
    let meta = alibi_core::RequestMeta::from_request(req);
    let issued = crate::helpers::issue_selected_user_session_record(
        &issuing_context,
        user,
        meta.ip_address,
        meta.user_agent,
    )
    .await
    .map_err(crate::helpers::SessionIssueError::into_auth_error)?;
    let token = issued.session.token();
    let user = serde_json::to_value(ctx.user_view(&issued.user))?;
    let session = serde_json::to_value(ctx.session_view(&issued.session))?;
    let payload = serde_json::json!({"token":token,"user":user,"session":session});
    let response = with_session_cookies(
        AuthResponse::json(200, &serde_json::json!({"token":token,"user":user}))?,
        &ctx.config,
        token,
        dont_remember,
    )?;
    Ok((payload, response))
}

/// Email-primary proof replaces access accrued before mailbox ownership was
/// proven. The database reservation serializes cleanup across auth instances.
pub(crate) async fn revoke_unproven_access<S: AuthSchema>(
    ctx: &AuthContext<S>,
    user_id: &str,
) -> AuthResult<Option<alibi_core::AdapterRecord<S::User>>> {
    let identifier = format!("revoke-unproven-account-access:{user_id}");
    let reserved = ctx
        .verifications()
        .reserve(CreateVerification {
            identifier: identifier.clone(),
            value: user_id.to_owned(),
            expires_at: Utc::now() + Duration::seconds(5),
        })
        .await;
    // The pinned mailbox-promotion helper deliberately proceeds without a
    // reservation when verification storage is secondary-only. Other failures
    // still stop cleanup and publication.
    let reserved = match reserved {
        Ok(value) => value,
        Err(AuthError::Internal(message))
            if message
                == "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values." =>
        {
            true
        }
        Err(error) => return Err(error),
    };
    if !reserved {
        for _ in 0..8 {
            if ctx.verifications().find(&identifier).await?.is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        return ctx.database.get_user_by_id_record(user_id).await;
    }
    let result = async {
        let Some(user) = ctx.database.get_user_by_id_record(user_id).await? else {
            return Ok(None);
        };
        if user.email_verified() {
            return Ok(Some(user));
        }
        for account in ctx.database.get_user_accounts(user_id).await? {
            ctx.database.delete_account(&account.id()).await?;
        }
        ctx.database.delete_user_sessions(user_id).await?;
        ctx.database
            .update_user_record(
                user_id,
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await
            .map(Some)
    }
    .await;
    _ = ctx.verifications().delete(&identifier).await;
    result
}
