use super::{
    AccountCookiePayload, AuthContext, AuthError, AuthUser, CreateAccount, CreateUser,
    OAuthIdentity, OAuthProcessPolicy, OAuthSignInError, OAuthTokenSet, OAuthUserInfo,
    ProcessOAuthUserResult, UpdateAccount, UpdateUser, UserValidationAction, UserValidationData,
    UserValidationSource, account_cookie_max_age, account_cookie_name, apply_default_role,
    encrypt_provider_token_set, issue_selected_user_session_record, provider_token_nulls,
    raw_truthy, validate_user_info,
};
use alibi_core::AuthAccount;
pub(in crate::oauth::handlers) async fn finish_oauth_session<S: alibi_core::AuthSchema>(
    user: &alibi_core::AdapterRecord<S::User>,
    is_register: bool,
    policy: &OAuthProcessPolicy,
    meta: &alibi_core::RequestMeta,
    ctx: &AuthContext<S>,
) -> Result<crate::helpers::IssuedSessionRecord<S>, OAuthSignInError> {
    if !user.email_verified() {
        let config = ctx
            .extensions
            .get::<crate::email_verification::EmailVerificationConfig>();
        let should_send = if is_register {
            config
                .as_ref()
                .and_then(|config| config.send_on_sign_up)
                .unwrap_or(policy.require_email_verification)
        } else {
            policy.require_email_verification
                && config.as_ref().is_some_and(|config| config.send_on_sign_in)
        };
        if should_send {
            if let Some(config) = config {
                // OAuth delivery completes after identity/account commit, before a session.
                if config.send_verification_email.is_some() {
                    if let Some(email) = user.email() {
                        let plugin =
                            crate::email_verification::EmailVerificationPlugin::with_config(
                                (*config).clone(),
                            );
                        plugin
                            .send_verification_email_for_user(
                                user,
                                email,
                                policy.callback_url.as_deref(),
                                ctx,
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                    }
                } else if let Some(sender) = ctx.email_verification_override() {
                    crate::authentication_helpers::run_notification(sender.0.send(
                        &ctx.user_view(user),
                        None,
                        ctx,
                    ))
                    .await;
                }
            } else if let Some(sender) = ctx.email_verification_override() {
                crate::authentication_helpers::run_notification(sender.0.send(
                    &ctx.user_view(user),
                    None,
                    ctx,
                ))
                .await;
            }
        }
        if policy.require_email_verification {
            return Err(OAuthSignInError::EmailNotVerified);
        }
    }
    issue_selected_user_session_record(
        ctx,
        user.clone(),
        meta.ip_address.clone(),
        meta.user_agent.clone(),
    )
    .await
    .map_err(OAuthSignInError::from)
}

pub(in crate::oauth::handlers) fn provider_fields(
    user_info: &OAuthUserInfo,
    creation: bool,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<alibi_core::field_policy::FieldValues, OAuthSignInError> {
    let registered = ctx.extensions.get::<alibi_core::field_policy::UserFields>();
    let fallback =
        alibi_core::field_policy::SessionFields(ctx.config.user.additional_fields.clone());
    let fields = registered.as_ref().map_or(&fallback, |fields| &fields.0);
    let input = user_info
        .additional_fields
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "id" | "email" | "emailVerified" | "name" | "image"
            ) && fields.0.get(*name).is_some_and(|field| field.input)
        })
        .map(|(name, value)| {
            (
                name.clone(),
                alibi_core::utils::json::JsValue::from(value.clone()),
            )
        })
        .collect();
    let result = if creation {
        fields.parse_create(&input)
    } else {
        fields.parse_update(&input)
    };
    result.map_err(|error| match error {
        alibi_core::field_policy::FieldInputError::Validation { code, message } => {
            OAuthSignInError::IdentityDenied {
                code: code.into(),
                message,
            }
        }
        alibi_core::field_policy::FieldInputError::Transform(error) => match error {
            AuthError::Api { .. } | AuthError::Upstream { .. } => {
                OAuthSignInError::from_identity_denial(error)
            }
            _ if creation => OAuthSignInError::Generic("unable to create user".into()),
            _ => OAuthSignInError::Generic(error.to_string()),
        },
    })
}

pub(in crate::oauth::handlers) fn provider_candidate(
    user_info: &OAuthUserInfo,
    user_id: &str,
) -> CreateUser {
    let mut candidate = CreateUser::new();
    candidate.id = Some(user_id.to_owned());
    candidate.email = Some(user_info.email.to_lowercase());
    candidate.name = user_info.name.clone();
    candidate.image = user_info.image.clone();
    candidate.email_verified = Some(user_info.email_verified);
    candidate
}

pub(in crate::oauth::handlers) async fn validate_provider_identity(
    provider: &str,
    profile: &serde_json::Value,
    user: &OAuthUserInfo,
    user_id: &str,
    action: UserValidationAction,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<(), OAuthSignInError> {
    let mut data = UserValidationData {
        user: provider_candidate(user, user_id),
        source: UserValidationSource::oauth(provider, profile, action),
    };
    // Sign-in completion supplies an empty name before the shared policy.
    // Explicit linking validates the original mapped optional name instead.
    data.user.name = Some(user.name.as_deref().unwrap_or_default().to_owned());
    validate_user_info(&ctx.config, &mut data)
        .await
        .map_err(OAuthSignInError::from_identity_denial)
}

pub(in crate::oauth::handlers) fn verification_override(
    user: &impl AuthUser,
    email: &str,
    incoming: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    incoming.map(|incoming| {
        if user
            .email()
            .is_some_and(|stored| stored.eq_ignore_ascii_case(email))
            && user.email_verified()
        {
            user.adapter_snapshot()
                .and_then(|output| output.values().get("emailVerified"))
                .cloned()
                .unwrap_or(serde_json::Value::Bool(true))
        } else {
            incoming.clone()
        }
    })
}

pub(crate) async fn process_oauth_sign_in(
    identity: OAuthIdentity<'_>,
    policy: &OAuthProcessPolicy,
    tokens: &OAuthTokenSet,
    disable_sign_up: bool,
    meta: &alibi_core::RequestMeta,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    process_oauth_sign_in_with_output(
        identity,
        policy,
        tokens,
        disable_sign_up,
        meta,
        ctx,
        (None, None),
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep OAuth account matching, linking policy, and signup branches together for review"
)]
pub(crate) async fn process_oauth_sign_in_with_output(
    identity: OAuthIdentity<'_>,
    policy: &OAuthProcessPolicy,
    tokens: &OAuthTokenSet,
    disable_sign_up: bool,
    meta: &alibi_core::RequestMeta,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    (raw_output, raw_policy): (
        Option<&alibi_core::field_policy::FieldOutput>,
        Option<&super::super::providers::OAuthAuthorizationPolicy>,
    ),
) -> Result<ProcessOAuthUserResult, OAuthSignInError> {
    let raw_verification = raw_output.and_then(|output| output.get("emailVerified"));
    let OAuthIdentity {
        provider_name,
        user: user_info,
        profile,
    } = identity;
    if user_info.email.is_empty() {
        return Err(OAuthSignInError::Generic("email not found".to_owned()));
    }

    let linked_account = ctx
        .database
        .get_account_record(provider_name, &user_info.id)
        .await
        .map_err(OAuthSignInError::from_account_lookup)?;

    let token_bundle = encrypt_provider_token_set(ctx, tokens, raw_policy)
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing_account) = linked_account {
        let existing_user = ctx
            .database
            .get_user_by_id_record(&existing_account.user_id())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "unable to link account".to_owned())?;
        validate_provider_identity(
            provider_name,
            profile,
            user_info,
            &existing_user.id(),
            UserValidationAction::SignIn,
            ctx,
        )
        .await?;
        if ctx.config.account.update_account_on_sign_in {
            drop(
                ctx.database
                    .update_account_record(
                        &existing_account.id(),
                        UpdateAccount {
                            provider_token_nulls: provider_token_nulls(tokens, raw_policy),
                            access_token: token_bundle.access_token.clone(),
                            refresh_token: token_bundle.refresh_token.clone(),
                            id_token: token_bundle.id_token.clone(),
                            access_token_expires_at: tokens.access_token_expires_at,
                            refresh_token_expires_at: tokens.refresh_token_expires_at,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }

        let mut user = existing_user;

        if user_info.email_verified
            && !user.email_verified()
            && user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            let updated = ctx
                .database
                .update_user_record(
                    &user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if policy.use_updated_user {
                user = updated;
            }
        }

        if policy.override_user_info {
            let additional_fields = provider_fields(user_info, false, ctx)?;
            let verification = verification_override(&user, &user_info.email, raw_verification);
            user = ctx
                .database
                .update_user_record(
                    &user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        additional_fields,
                        email_verified: Some(verification.as_ref().map_or_else(
                            || {
                                (user.email().is_some_and(|email| {
                                    email.eq_ignore_ascii_case(&user_info.email)
                                }) && user.email_verified())
                                    || user_info.email_verified
                            },
                            raw_truthy,
                        )),
                        provider_email_verified: verification,
                        provider_name: raw_output.and_then(|output| output.get("name")).cloned(),
                        provider_image: raw_output.and_then(|output| output.get("image")).cloned(),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let issued = finish_oauth_session(&user, false, policy, meta, ctx).await?;
        let account_cookie = ctx.config.account.store_account_cookie.then(|| {
            if !ctx.config.account.update_account_on_sign_in {
                return AccountCookiePayload::from_account(&existing_account);
            }
            AccountCookiePayload {
                id: Some(existing_account.id().to_string()),
                user_id: existing_account.user_id().to_string(),
                provider_id: provider_name.to_owned(),
                account_id: existing_account.account_id().to_owned(),
                access_token: token_bundle.access_token.or_else(|| {
                    (!provider_token_nulls(tokens, raw_policy)[0])
                        .then(|| existing_account.access_token().map(str::to_owned))
                        .flatten()
                }),
                refresh_token: token_bundle.refresh_token.or_else(|| {
                    (!provider_token_nulls(tokens, raw_policy)[1])
                        .then(|| existing_account.refresh_token().map(str::to_owned))
                        .flatten()
                }),
                id_token: token_bundle.id_token.or_else(|| {
                    (!provider_token_nulls(tokens, raw_policy)[2])
                        .then(|| existing_account.id_token().map(str::to_owned))
                        .flatten()
                }),
                access_token_expires_at: tokens
                    .access_token_expires_at
                    .or_else(|| existing_account.access_token_expires_at()),
                refresh_token_expires_at: tokens
                    .refresh_token_expires_at
                    .or_else(|| existing_account.refresh_token_expires_at()),
                scope: existing_account.scope().map(str::to_owned),
                password: existing_account.password().map(str::to_owned),
                created_at: Some(existing_account.created_at()),
                updated_at: Some(existing_account.updated_at()),
                ..AccountCookiePayload::from_account(&existing_account)
            }
        });

        return Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&user)
            },
            is_register: false,
            account_cookie,
        });
    }

    let existing_user = ctx
        .database
        .get_user_by_email_record(&user_info.email.to_lowercase())
        .await
        .map_err(|error| error.to_string())?;

    if let Some(existing_user) = existing_user {
        let linking = &ctx.config.account.account_linking;
        let trusted_provider = linking
            .trusted_providers
            .iter()
            .any(|trusted| trusted == provider_name);

        // Mirrors upstream's linking guard, including the local-account check:
        // an unverified local account is not implicitly linkable.
        if !linking.enabled
            || linking.disable_implicit_linking
            || (!trusted_provider && !user_info.email_verified)
            || (linking.require_local_email_verified && !existing_user.email_verified())
        {
            return Err(OAuthSignInError::Generic("account not linked".to_owned()));
        }

        let mut linked_user = existing_user;
        validate_provider_identity(
            provider_name,
            profile,
            user_info,
            &linked_user.id(),
            UserValidationAction::LinkAccount,
            ctx,
        )
        .await?;
        let created_account = ctx
            .database
            .create_account_record(CreateAccount {
                additional_fields: Default::default(),
                user_id: linked_user.id().to_string(),
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
            .map_err(|_error| "unable to link account".to_owned())?;

        if user_info.email_verified
            && !linked_user.email_verified()
            && linked_user
                .email()
                .is_some_and(|email| email.eq_ignore_ascii_case(&user_info.email))
        {
            let updated = ctx
                .database
                .update_user_record(
                    &linked_user.id(),
                    UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if policy.use_updated_user {
                linked_user = updated;
            }
        }

        if linking.update_user_info_on_link {
            match ctx
                .database
                .update_user_record(
                    &linked_user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        ..Default::default()
                    },
                )
                .await
            {
                Ok(updated) => linked_user = updated,
                Err(error) => tracing::warn!(%error, "Could not update user info on account link"),
            }
        }

        if policy.override_user_info {
            let additional_fields = provider_fields(user_info, false, ctx)?;
            let verification =
                verification_override(&linked_user, &user_info.email, raw_verification);
            linked_user = ctx
                .database
                .update_user_record(
                    &linked_user.id(),
                    UpdateUser {
                        name: user_info.name.clone(),
                        image: user_info.image.clone(),
                        email: Some(user_info.email.to_lowercase()),
                        additional_fields,
                        email_verified: Some(verification.as_ref().map_or_else(
                            || {
                                (linked_user.email().is_some_and(|email| {
                                    email.eq_ignore_ascii_case(&user_info.email)
                                }) && linked_user.email_verified())
                                    || user_info.email_verified
                            },
                            raw_truthy,
                        )),
                        provider_email_verified: verification,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }

        let issued = finish_oauth_session(&linked_user, false, policy, meta, ctx).await?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&created_account));

        Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&linked_user)
            },
            is_register: false,
            account_cookie,
        })
    } else {
        if disable_sign_up {
            return Err(OAuthSignInError::Generic("signup disabled".to_owned()));
        }

        let mut create_user = CreateUser::new()
            .with_email(user_info.email.to_lowercase())
            .with_name(user_info.name.as_deref().unwrap_or_default())
            .with_email_verified(user_info.email_verified);
        crate::authentication_helpers::apply_creation_input_defaults(ctx, &mut create_user);
        apply_default_role(ctx, &mut create_user);
        create_user.provider_email_verified =
            raw_verification.filter(|value| !value.is_null()).cloned();
        create_user.image = user_info.image.clone();
        create_user.additional_fields = provider_fields(user_info, true, ctx)?;

        let mut create_account = CreateAccount {
            additional_fields: Default::default(),
            user_id: String::new(),
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
        };
        let source =
            UserValidationSource::oauth(provider_name, profile, UserValidationAction::CreateUser);
        // OAuth registration commits its identity and provider binding together.
        // Notifications and session creation follow the committed transaction.
        let (persisted_user, persisted_account) =
            alibi_core::store::transaction(ctx.database.as_ref(), move |tx| {
                Box::pin(async move {
                    let user = tx
                        .create_user_with_source_record(create_user, source)
                        .await?;
                    create_account.user_id = user.id().to_string();
                    let account = tx.create_account_record(create_account).await?;
                    Ok((user, account))
                })
            })
            .await
            .map_err(|error| {
                if error.status_code() == 403 {
                    OAuthSignInError::from_identity_denial(error)
                } else {
                    OAuthSignInError::Generic("unable to create user".to_owned())
                }
            })?;

        if ctx.config.account.store_account_cookie {
            let age = account_cookie_max_age(&ctx.config);
            // Published registration commits the identity first, then catches
            // account-cookie configuration failures before issuing a session.
            if !age.is_finite()
                || alibi_core::utils::cookie_utils::create_account_cookie_header(
                    &account_cookie_name(&ctx.config),
                    &account_cookie_name(&ctx.config),
                    "",
                    age,
                    &ctx.config,
                )
                .is_err()
            {
                return Err(OAuthSignInError::Generic("unable to create user".into()));
            }
        }
        let issued = finish_oauth_session(&persisted_user, true, policy, meta, ctx).await?;
        let account_cookie = ctx
            .config
            .account
            .store_account_cookie
            .then(|| AccountCookiePayload::from_account(&persisted_account));

        Ok(ProcessOAuthUserResult {
            session: ctx.session_view(&issued.session),
            user: if policy.use_updated_user {
                ctx.user_view(&issued.user)
            } else {
                ctx.user_view(&persisted_user)
            },
            is_register: true,
            account_cookie,
        })
    }
}
