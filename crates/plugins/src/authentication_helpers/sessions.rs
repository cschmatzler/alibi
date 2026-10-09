use alibi_core::{
    AuthAccount, AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema,
    AuthSession, AuthUser, CreateVerification, UpdateUser,
};
use chrono::{Duration, Utc};
use serde_json::Value;

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
    use alibi_core::utils::cookie_utils::{
        create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
        sign_cookie_value, verify_cookie_value,
    };
    let inherited =
        crate::helpers::get_cookie(req, &related_cookie_name(&ctx.config, "dont_remember"))
            .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
            .is_some_and(|value| !value.is_empty());
    let dont_remember = remember_me.map_or(inherited, |value| !value);
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
    let mut response = AuthResponse::json(200, &serde_json::json!({"token":token,"user":user}))?
        .with_header(
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
                &related_cookie_name(&ctx.config, "dont_remember"),
                &sign_cookie_value("true", ctx.config.current_secret()),
                None,
                &ctx.config,
            )?,
        );
    }
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
