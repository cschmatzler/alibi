//! Authentication writes selected by an enterprise application resolver.
use super::identity::{identity_source, provider_fields, validate_provider_identity};
use super::{OAuthProcessPolicy, OAuthSignInError, ProcessOAuthUserResult};
use crate::oauth::providers::{OAuthTokenSet, OAuthUserInfo};
use crate::sso::{SsoResolvedProfile, SsoUserResolution};
use alibi_core::user_validation::UserValidationAction;
use alibi_core::{
    AdapterRecord, AuthAccount, AuthContext, AuthError, AuthResult, AuthSchema, AuthTransaction,
    AuthUser, CreateAccount, CreateUser, RequestMeta, UpdateAccount, UpdateUser,
};
use serde_json::Value;
pub(crate) struct Identity<'a, S: AuthSchema> {
    pub provider: &'a str,
    pub user: &'a OAuthUserInfo,
    pub profile: &'a Value,
    pub policy: &'a OAuthProcessPolicy,
    pub tokens: &'a OAuthTokenSet,
    pub disable_signup: bool,
    pub meta: &'a RequestMeta,
    pub ctx: &'a AuthContext<S>,
}
pub(crate) struct Authenticated<S: AuthSchema> {
    pub issued: crate::helpers::IssuedSessionRecord<S>,
    pub account: AdapterRecord<S::Account>,
    pub is_register: bool,
}
fn error(code: &str, message: &str) -> AuthError {
    AuthError::Api {
        status: 403,
        code: Some(code.into()),
        message: message.into(),
    }
}
fn oauth_error(error: OAuthSignInError) -> AuthError {
    match error {
        OAuthSignInError::SessionAuth(error @ AuthError::Api { code: Some(_), .. }) => error,
        error => {
            let (code, message) = error.redirect_parts();
            self::error(&code, message.unwrap_or_default())
        }
    }
}
pub(crate) async fn authenticate<S: AuthSchema>(
    input: &Identity<'_, S>,
    decision: &SsoUserResolution,
    database: &dyn AuthTransaction<S>,
) -> AuthResult<Authenticated<S>> {
    let Identity {
        provider,
        user,
        profile,
        policy,
        tokens,
        disable_signup,
        meta,
        ctx,
    } = input;
    let original_account = database.get_account_record(provider, &user.id).await?;
    let selected = if let SsoUserResolution::Link { user_id, .. } = decision {
        Some(user_id.as_str())
    } else {
        None
    };
    let mut existing = if let Some(account) = &original_account {
        let owner = database
            .get_user_by_id_record(&account.user_id())
            .await?
            .ok_or_else(|| error("unable_to_link_account", ""))?;
        if selected.is_some_and(|id| id != owner.id().as_ref()) {
            return Err(error(
                "account_ownership_conflict",
                "Account is already linked to another user",
            ));
        }
        Some(owner)
    } else if let Some(id) = selected {
        Some(
            database
                .get_user_by_id_record(id)
                .await?
                .ok_or_else(|| error("user_not_found", "User not found"))?,
        )
    } else {
        database
            .get_user_by_email_record(&user.email.to_lowercase())
            .await?
    };
    let token_bundle =
        crate::oauth::encryption::encrypt_provider_token_set(ctx, tokens, None).await?;
    let is_register = existing.is_none();
    let account = if let Some(existing_user) = existing.as_ref() {
        if original_account.is_none() && selected.is_none() {
            let linking = &ctx.config.account.account_linking;
            let trusted = linking.trusted_providers.iter().any(|id| id == provider);
            if !linking.enabled
                || linking.disable_implicit_linking
                || (!trusted && !user.email_verified)
                || (linking.require_local_email_verified && !existing_user.email_verified())
            {
                return Err(error("account_not_linked", ""));
            }
        }
        validate_provider_identity(
            provider,
            profile,
            user,
            &existing_user.id(),
            if original_account.is_some() {
                UserValidationAction::SignIn
            } else {
                UserValidationAction::LinkAccount
            },
            policy,
            ctx,
        )
        .await
        .map_err(oauth_error)?;
        if let Some(account) = original_account {
            if ctx.config.account.update_account_on_sign_in {
                database
                    .update_account_record(
                        &account.id(),
                        UpdateAccount {
                            access_token: token_bundle.access_token,
                            refresh_token: token_bundle.refresh_token,
                            id_token: token_bundle.id_token,
                            access_token_expires_at: tokens.access_token_expires_at,
                            refresh_token_expires_at: tokens.refresh_token_expires_at,
                            provider_token_nulls: crate::oauth::encryption::provider_token_nulls(
                                tokens, None,
                            ),
                            ..Default::default()
                        },
                    )
                    .await?
            } else {
                account
            }
        } else {
            database
                .create_account_record(CreateAccount {
                    additional_fields: alibi_core::field_policy::FieldValues::default(),
                    user_id: existing_user.id().to_string(),
                    account_id: user.id.clone(),
                    provider_id: (*provider).into(),
                    access_token: token_bundle.access_token,
                    refresh_token: token_bundle.refresh_token,
                    id_token: token_bundle.id_token,
                    access_token_expires_at: tokens.access_token_expires_at,
                    refresh_token_expires_at: tokens.refresh_token_expires_at,
                    scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                        .then(|| tokens.scopes.join(" ")),
                    password: None,
                })
                .await?
        }
    } else {
        if *disable_signup {
            return Err(error("signup_disabled", ""));
        }
        let mut data = CreateUser::new()
            .with_email(user.email.to_lowercase())
            .with_name(user.name.as_deref().unwrap_or_default())
            .with_email_verified(user.email_verified);
        crate::authentication_helpers::apply_creation_input_defaults(ctx, &mut data);
        crate::helpers::apply_default_role(ctx, &mut data);
        data.image = user.image.clone();
        data.additional_fields = provider_fields(user, true, ctx).map_err(oauth_error)?;
        let created = database
            .create_user_with_source_record(
                data,
                identity_source(provider, profile, UserValidationAction::CreateUser, policy),
            )
            .await?;
        let account = database
            .create_account_record(CreateAccount {
                additional_fields: alibi_core::field_policy::FieldValues::default(),
                user_id: created.id().to_string(),
                account_id: user.id.clone(),
                provider_id: (*provider).into(),
                access_token: token_bundle.access_token,
                refresh_token: token_bundle.refresh_token,
                id_token: token_bundle.id_token,
                access_token_expires_at: tokens.access_token_expires_at,
                refresh_token_expires_at: tokens.refresh_token_expires_at,
                scope: (tokens.raw.is_some() || !tokens.scopes.is_empty())
                    .then(|| tokens.scopes.join(" ")),
                password: None,
            })
            .await?;
        existing = Some(created);
        account
    };
    let mut actual_user = existing.ok_or_else(|| error("unable_to_create_user", ""))?;
    if account.account_id() != user.id
        || account.provider_id() != *provider
        || account.user_id() != actual_user.id().as_ref()
    {
        return Err(error(
            "account_hook_binding_conflict",
            "Account hook changed the selected authentication binding",
        ));
    }
    let update_profile = match decision {
        SsoUserResolution::Link { profile, .. } => *profile == SsoResolvedProfile::Update,
        _ => policy.override_user_info,
    };
    if !is_register && update_profile {
        let verified = if actual_user
            .email()
            .is_some_and(|email| email.eq_ignore_ascii_case(&user.email))
        {
            actual_user.email_verified() || user.email_verified
        } else {
            user.email_verified
        };
        actual_user = database
            .update_user_record(
                &actual_user.id(),
                UpdateUser {
                    email: Some(user.email.to_lowercase()),
                    name: Some(user.name.clone().unwrap_or_default()),
                    image: user.image.clone(),
                    email_verified: Some(verified),
                    additional_fields: provider_fields(user, false, ctx).map_err(oauth_error)?,
                    ..Default::default()
                },
            )
            .await?;
    } else if !is_register
        && selected.is_none()
        && user.email_verified
        && !actual_user.email_verified()
        && actual_user
            .email()
            .is_some_and(|email| email.eq_ignore_ascii_case(&user.email))
    {
        actual_user = database
            .update_user_record(
                &actual_user.id(),
                UpdateUser {
                    email_verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
    }
    let issued = crate::helpers::issue_selected_user_session_in_transaction(
        ctx,
        database,
        actual_user,
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(|error| oauth_error(OAuthSignInError::from(error)))?;
    Ok(Authenticated {
        issued,
        account,
        is_register,
    })
}
pub(crate) async fn publish<S: AuthSchema>(
    ctx: &AuthContext<S>,
    authenticated: Authenticated<S>,
) -> AuthResult<ProcessOAuthUserResult> {
    crate::helpers::publish_committed_session(ctx, &authenticated.issued).await?;
    Ok(ProcessOAuthUserResult {
        session: ctx.session_view(&authenticated.issued.session),
        user: ctx.user_view(&authenticated.issued.user),
        is_register: authenticated.is_register,
        account_cookie: ctx.config.account.store_account_cookie.then(|| {
            crate::oauth::state::AccountCookiePayload::from_account(&authenticated.account)
        }),
    })
}
