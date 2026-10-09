use super::{
    AuthContext, AuthError, AuthResult, AuthSession, CreateAccount, LinkSocialOutcome,
    LinkSocialRequest, OAuthIdTokenRequest, OAuthIdentity, OAuthProcessPolicy, OAuthProvider,
    OAuthSignInError, OAuthStateLink, OAuthTokenSet, OAuthUserInfo, OAuthUserInfoRequest,
    SocialSignInRequest, SocialSignInResponse, UpdateAccount, UpdateUser, UserValidationAction,
    UserValidationData, UserValidationSource, Utc, encrypt_provider_token_set, encrypt_token_set,
    fetch_user_info_from_provider, oauth_disable_sign_up_option, process_oauth_sign_in,
    provider_candidate, provider_token_nulls, resolve_oauth_account_key, validate_user_info,
};
use alibi_core::AuthAccount;
use alibi_core::AuthUser;
pub(crate) async fn complete_link_social(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    profile: &serde_json::Value,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<(), OAuthSignInError> {
    complete_link_social_with_raw_email(
        provider_name,
        user_info,
        profile,
        tokens,
        link,
        ctx,
        (None, None),
    )
    .await
    .map(|_| ())
}

pub(in crate::oauth::handlers) async fn complete_link_social_with_raw_email(
    provider_name: &str,
    user_info: &OAuthUserInfo,
    profile: &serde_json::Value,
    tokens: &OAuthTokenSet,
    link: &OAuthStateLink,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    (raw_email, raw_policy): (
        Option<&serde_json::Value>,
        Option<&super::super::providers::OAuthAuthorizationPolicy>,
    ),
) -> Result<LinkSocialOutcome, OAuthSignInError> {
    // Explicit linking validates fresh provider data before its trust/email
    // guards or account lookup. The candidate retains the selected local ID.
    let mut candidate = provider_candidate(user_info, &link.user_id);
    candidate.email = (!user_info.email.is_empty()).then(|| user_info.email.clone());
    validate_user_info(
        &ctx.config,
        &mut UserValidationData {
            user: candidate,
            source: UserValidationSource::oauth(
                provider_name,
                profile,
                UserValidationAction::LinkAccount,
            ),
        },
    )
    .await
    .map_err(OAuthSignInError::from_identity_denial)?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == provider_name);

    if !linking.enabled || (!trusted_provider && !user_info.email_verified) {
        return Err("unable_to_link_account".to_owned().into());
    }

    if raw_email.is_some_and(|email| !email.is_null() && !email.is_string()) {
        return Ok(LinkSocialOutcome::InvalidRawEmail);
    }

    if !linking.allow_different_emails && !user_info.email.eq_ignore_ascii_case(&link.email) {
        return Err("email_does_not_match".to_owned().into());
    }

    if let Some(existing_account) = ctx
        .database
        .get_account(provider_name, &user_info.id)
        .await
        .map_err(OAuthSignInError::from_account_lookup)?
    {
        if existing_account.user_id() != link.user_id {
            return Err("account_already_linked_to_different_user".to_owned().into());
        }

        let token_bundle = encrypt_provider_token_set(ctx, tokens, raw_policy)
            .await
            .map_err(|error| error.to_string())?;

        drop(
            ctx.database
                .update_account_record(
                    &existing_account.id(),
                    UpdateAccount {
                        provider_token_nulls: provider_token_nulls(tokens, raw_policy),
                        access_token: token_bundle.access_token,
                        refresh_token: token_bundle.refresh_token,
                        id_token: token_bundle.id_token,
                        access_token_expires_at: tokens.access_token_expires_at,
                        refresh_token_expires_at: tokens.refresh_token_expires_at,
                        scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                            .then(|| tokens.scopes.join(",")),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?,
        );

        return Ok(LinkSocialOutcome::Linked);
    }

    let token_bundle = encrypt_provider_token_set(ctx, tokens, raw_policy)
        .await
        .map_err(|error| error.to_string())?;

    drop(
        ctx.database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: link.user_id.clone(),
                account_id: user_info.id.clone(),
                provider_id: provider_name.to_owned(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                    .then(|| tokens.scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| "unable_to_link_account".to_owned())?,
    );

    Ok(LinkSocialOutcome::Linked)
}

pub(in crate::oauth::handlers) async fn sign_in_with_id_token_core(
    body: &SocialSignInRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    meta: &alibi_core::RequestMeta,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    if provider.disable_id_token_sign_in
        || provider.verify_id_token.is_none() && provider.id_token.is_none()
    {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    }
    if !super::super::id_token::verify_provider_token(
        provider,
        &id_token.token,
        id_token.nonce.as_deref(),
    )
    .await
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }

    let mut user_info = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            user: id_token.user.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if user_info.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    resolve_oauth_account_key(
        provider,
        &OAuthTokenSet {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            id_token: Some(id_token.token.clone()),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            ..Default::default()
        },
        &mut user_info,
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    let outcome = process_oauth_sign_in(
        OAuthIdentity {
            provider_name: &body.provider,
            user: &user_info.user,
            profile: &user_info.data,
        },
        &OAuthProcessPolicy::for_provider(provider, body.callback_url.clone()),
        &OAuthTokenSet {
            access_token: id_token.access_token.clone(),
            id_token: Some(id_token.token.clone()),
            ..Default::default()
        },
        provider.disable_implicit_sign_up && !body.request_sign_up.unwrap_or(false)
            || oauth_disable_sign_up_option(provider).unwrap_or(false)
            || provider.disable_sign_up,
        meta,
        ctx,
    )
    .await
    .map_err(|error| match error {
        OAuthSignInError::IdentityDenied { code, message } => AuthError::Api {
            status: 403,
            code: Some(code),
            message,
        },
        OAuthSignInError::AccountLookup(error) => error,
        OAuthSignInError::EmailNotVerified => AuthError::Upstream {
            status: 403,
            code: "EMAIL_NOT_VERIFIED",
            message: "Email not verified",
        },
        OAuthSignInError::Generic(message) | OAuthSignInError::Banned(message) => AuthError::Api {
            status: 401,
            code: Some("OAUTH_LINK_ERROR".into()),
            message,
        },
        OAuthSignInError::SessionAuth(error) => AuthError::Api {
            status: 401,
            code: Some("OAUTH_LINK_ERROR".into()),
            message: error.to_string(),
        },
    })?;

    Ok(SocialSignInResponse {
        url: None,
        redirect: false,
        status: None,
        token: Some(outcome.session.token().to_owned()),
        user: Some(outcome.user),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep provider proof validation and account ownership checks adjacent to the linking write"
)]
pub(in crate::oauth::handlers) async fn link_with_id_token_core(
    body: &LinkSocialRequest,
    id_token: &OAuthIdTokenRequest,
    provider: &OAuthProvider,
    session: &impl AuthSession,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<SocialSignInResponse> {
    if provider.disable_id_token_sign_in
        || provider.verify_id_token.is_none() && provider.id_token.is_none()
    {
        return Err(AuthError::Upstream {
            status: 404,
            code: "ID_TOKEN_NOT_SUPPORTED",
            message: "id_token not supported",
        });
    }
    if !super::super::id_token::verify_provider_token(
        provider,
        &id_token.token,
        id_token.nonce.as_deref(),
    )
    .await
    {
        return Err(AuthError::Upstream {
            status: 401,
            code: "INVALID_TOKEN",
            message: "Invalid token",
        });
    }

    let mut response = fetch_user_info_from_provider(
        provider,
        OAuthUserInfoRequest {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            id_token: Some(id_token.token.clone()),
            user: id_token.user.clone(),
            ..Default::default()
        },
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    if response.user.email.is_empty() {
        return Err(AuthError::Upstream {
            status: 401,
            code: "USER_EMAIL_NOT_FOUND",
            message: "User email not found",
        });
    }

    resolve_oauth_account_key(
        provider,
        &OAuthTokenSet {
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            access_token_expires_at: id_token
                .expires_at
                .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
            id_token: Some(id_token.token.clone()),
            scopes: id_token.scopes.clone().unwrap_or_default(),
            ..Default::default()
        },
        &mut response,
    )
    .await
    .map_err(|_error| AuthError::Upstream {
        status: 401,
        code: "FAILED_TO_GET_USER_INFO",
        message: "Failed to get user info",
    })?;

    let linked_account = ctx
        .database
        .get_account(&body.provider, &response.user.id)
        .await?;
    if linked_account
        .as_ref()
        .is_some_and(|account| account.user_id() != session.user_id())
    {
        return Err(AuthError::Upstream {
            status: 409,
            code: "SOCIAL_ACCOUNT_ALREADY_LINKED",
            message: "Social account already linked",
        });
    }
    let existing_accounts = ctx.database.get_user_accounts(&session.user_id()).await?;
    if existing_accounts.iter().any(|account| {
        account.provider_id() == body.provider && account.account_id() == response.user.id
    }) {
        return Ok(SocialSignInResponse {
            url: Some(String::new()),
            redirect: false,
            status: Some(true),
            token: None,
            user: None,
        });
    }

    let current_user = ctx
        .session_user(session)
        .await?
        .ok_or(AuthError::UserNotFound)?;
    let current_email = current_user
        .email()
        .ok_or_else(|| AuthError::forbidden("User email not found"))?;
    let linking = &ctx.config.account.account_linking;
    let trusted_provider = linking
        .trusted_providers
        .iter()
        .any(|trusted| trusted == &body.provider);

    if !linking.enabled || (!trusted_provider && !response.user.email_verified) {
        return Err(AuthError::forbidden(
            "Account not linked - linking not allowed",
        ));
    }
    if !linking.allow_different_emails && !response.user.email.eq_ignore_ascii_case(current_email) {
        return Err(AuthError::forbidden(
            "Account not linked - different emails not allowed",
        ));
    }

    let token_bundle = encrypt_token_set(
        ctx,
        id_token.access_token.clone(),
        id_token.refresh_token.clone(),
        Some(id_token.token.clone()),
    )?;
    drop(
        ctx.database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: session.user_id().to_string(),
                provider_id: body.provider.clone(),
                account_id: response.user.id,
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: id_token
                    .expires_at
                    .and_then(|timestamp| chrono::DateTime::<Utc>::from_timestamp(timestamp, 0)),
                refresh_token_expires_at: None,
                scope: id_token.scopes.as_ref().map(|scopes| scopes.join(",")),
                password: None,
            })
            .await
            .map_err(|_error| {
                AuthError::bad_request("Account not linked - unable to create account")
            })?,
    );

    if linking.update_user_info_on_link {
        drop(
            ctx.database
                .update_user_record(
                    &session.user_id(),
                    UpdateUser {
                        name: response.user.name.clone(),
                        image: response.user.image.clone(),
                        ..Default::default()
                    },
                )
                .await,
        );
    }

    Ok(SocialSignInResponse {
        url: Some(String::new()),
        redirect: false,
        status: Some(true),
        token: None,
        user: None,
    })
}
