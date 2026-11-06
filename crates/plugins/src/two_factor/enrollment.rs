use super::*;
use alibi_core::error::codes;
#[expect(
    clippy::too_many_lines,
    reason = "Keep factor enrollment, backup generation, and session replacement in their callback order"
)]
pub(in crate::two_factor) async fn enable_core(
    body: &EnableTwoFactorInput,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> Result<(TwoFactorEnabled, Vec<String>), BackupOperationError> {
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config.allow_passwordless,
    )
    .await?;
    if body.method == TwoFactorMethod::Otp {
        if config.send_otp.is_none() {
            return Err(AuthError::Upstream {
                status: 400,
                code: codes::OTP_NOT_CONFIGURED,
                message: "OTP is not available",
            }
            .into());
        }
        let updated_user = ctx
            .database
            .update_user_record(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides_record(
            ctx,
            updated_user.id().as_ref(),
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
            current_session,
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(current_session.token()).await?;
        return Ok((
            TwoFactorEnabled::Otp,
            vec![create_session_cookie(issued.session.token(), &ctx.config)?],
        ));
    }
    if config.totp_disabled {
        return Err(AuthError::Upstream {
            status: 400,
            code: codes::TOTP_NOT_CONFIGURED,
            message: "TOTP is not available",
        }
        .into());
    }

    let existing = ctx
        .database
        .get_two_factor_by_user_id(user.id().as_ref())
        .await?;
    if existing
        .as_ref()
        .is_some_and(|factor| factor.verified() != Some(false))
    {
        return Err(AuthError::Upstream {
            status: 400,
            code: codes::TOTP_ALREADY_ENABLED,
            message: "TOTP is already enabled",
        }
        .into());
    }

    let secret = generate_secret();
    let encrypted_secret = encrypt_value(&ctx.config, &secret)?;
    let (backup_codes, encrypted_backup_codes) = generate_backup_codes(config, &ctx.config).await?;

    let mut set_cookie_headers = Vec::new();
    if config.skip_verification_on_enable {
        let updated_user = ctx
            .database
            .update_user_record(
                user.id().as_ref(),
                UpdateUser {
                    two_factor_enabled: Some(true),
                    ..Default::default()
                },
            )
            .await?;
        let issued = issue_user_session_with_overrides_record(
            ctx,
            updated_user.id().as_ref(),
            current_session.ip_address().map(str::to_owned),
            current_session.user_agent().map(str::to_owned),
            current_session,
        )
        .await
        .map_err(SessionIssueError::into_auth_error)?;
        ctx.database.delete_session(current_session.token()).await?;
        set_cookie_headers.push(create_session_cookie(issued.session.token(), &ctx.config)?);
    }

    if let Some(existing) = existing {
        _ = ctx
            .database
            .update_two_factor(
                existing.id().as_ref(),
                UpdateTwoFactor {
                    secret: Some(encrypted_secret),
                    backup_codes: Some(encrypted_backup_codes),
                    verified: Some(config.skip_verification_on_enable),
                },
            )
            .await?;
    } else {
        _ = ctx
            .database
            .create_two_factor(CreateTwoFactor {
                user_id: user.id().to_string(),
                secret: encrypted_secret,
                backup_codes: encrypted_backup_codes,
                verified: Some(config.skip_verification_on_enable),
                ..Default::default()
            })
            .await?;
    }

    let issuer = body
        .issuer
        .as_deref()
        .filter(|value| !value.is_empty())
        .or_else(|| config.issuer.as_deref().filter(|value| !value.is_empty()))
        .unwrap_or(&ctx.config.app_name);
    let totp_uri = totp_uri(
        config,
        &secret,
        issuer,
        user.email().unwrap_or("user"),
        true,
    )?;
    Ok((
        TwoFactorEnabled::Totp {
            totp_uri,
            backup_codes,
        },
        set_cookie_headers,
    ))
}

pub(in crate::two_factor) async fn disable_core(
    body: &DisableTwoFactorInput,
    user: &impl AuthUser,
    current_session: &impl AuthSession,
    req: &impl alibi_core::session::SessionRequest,
    config: &TwoFactorConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<(StatusResponse, Vec<String>)> {
    verify_user_password(
        ctx,
        user,
        body.password.as_deref(),
        config.allow_passwordless,
    )
    .await?;

    let updated_user = ctx
        .database
        .update_user_record(
            user.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;

    ctx.database.delete_two_factor(user.id().as_ref()).await?;

    let issued = issue_user_session_with_overrides_record(
        ctx,
        updated_user.id().as_ref(),
        current_session.ip_address().map(str::to_owned),
        current_session.user_agent().map(str::to_owned),
        current_session,
    )
    .await
    .map_err(SessionIssueError::into_auth_error)?;
    ctx.database.delete_session(current_session.token()).await?;

    let dont_remember = read_signed_cookie(req, DONT_REMEMBER_COOKIE_SUFFIX, ctx)
        .is_some_and(|value| !value.is_empty());
    let mut set_cookie_headers = vec![create_session_cookie_for_dont_remember(
        issued.session.token(),
        dont_remember,
        &ctx.config,
    )?];
    if dont_remember {
        set_cookie_headers.push(create_signed_cookie_header(
            ctx.config.current_secret(),
            &ctx.config,
            DONT_REMEMBER_COOKIE_SUFFIX,
            "true",
            None,
        )?);
    }

    if let Some(trust_cookie) = read_signed_cookie(req, TRUST_DEVICE_COOKIE_SUFFIX, ctx)
        && !trust_cookie.is_empty()
    {
        if let Some(trust_identifier) = trust_cookie.split('!').nth(1)
            && !trust_identifier.is_empty()
        {
            ctx.verifications().delete(trust_identifier).await?;
        }
        set_cookie_headers.push(clear_cookie_header(
            &ctx.config,
            TRUST_DEVICE_COOKIE_SUFFIX,
        )?);
    }

    Ok((StatusResponse { status: true }, set_cookie_headers))
}

pub(in crate::two_factor) async fn mark_factor_verified(
    two_factor: &TwoFactor,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<()> {
    if two_factor.verified() != Some(true) {
        _ = ctx
            .database
            .update_two_factor(
                two_factor.id().as_ref(),
                UpdateTwoFactor {
                    verified: Some(true),
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok(())
}

pub(in crate::two_factor) async fn verify_user_password(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user: &impl AuthUser,
    password: Option<&str>,
    allow_passwordless: bool,
) -> AuthResult<()> {
    verify_password_inner(ctx, user, password, allow_passwordless, false).await
}

pub(in crate::two_factor) async fn check_user_password(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user: &impl AuthUser,
    password: Option<&str>,
    allow_passwordless: bool,
) -> AuthResult<()> {
    verify_password_inner(ctx, user, password, allow_passwordless, true).await
}

async fn verify_password_inner(
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
    user: &impl AuthUser,
    password: Option<&str>,
    allow_passwordless: bool,
    hash_missing: bool,
) -> AuthResult<()> {
    let stored_hash = get_credential_password_hash(ctx, user).await?;
    if allow_passwordless && stored_hash.as_deref().is_none_or(str::is_empty) {
        return Ok(());
    }
    let password = password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    let password_config = ctx
        .extensions
        .get::<super::super::email_password::EmailPasswordConfig>();
    let maximum = password_config
        .as_ref()
        .map_or(128, |config| config.password_max_length);
    if password.encode_utf16().count() > maximum {
        return Err(AuthError::bad_request("Password too long"));
    }
    let hasher = password_config
        .as_ref()
        .and_then(|config| config.password_hasher.as_ref());
    let Some(stored_hash) = stored_hash.filter(|hash| !hash.is_empty()) else {
        if hash_missing {
            _ = ctx.hash_password(hasher, password).await?;
        }
        return Err(AuthError::bad_request("Invalid password"));
    };
    match alibi_core::verify_password(hasher, password, &stored_hash).await {
        Ok(()) => Ok(()),
        Err(AuthError::InvalidCredentials) => Err(AuthError::bad_request("Invalid password")),
        Err(error) => Err(error),
    }
}

pub(in crate::two_factor) fn parse_password_body<T: serde::de::DeserializeOwned + 'static>(
    req: &AuthRequest,
    allow_passwordless: bool,
    include_issuer: bool,
) -> Result<T, AuthResponse> {
    use super::super::authentication_helpers::{JsonField, JsonFieldKind, parse_body_with_fields};
    let fields = [
        JsonField::string("password", !allow_passwordless),
        JsonField {
            name: "method",
            kind: JsonFieldKind::OneOf(&["otp", "totp"]),
            required: false,
        },
        JsonField::string("issuer", false),
    ];
    parse_body_with_fields(
        req,
        if include_issuer {
            &fields[..]
        } else {
            &fields[..1]
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alibi_core::AuthPlugin;

    #[tokio::test]
    async fn password_check_hashes_missing_credentials_without_verifying() {
        struct CountingHasher(std::sync::atomic::AtomicUsize);
        #[async_trait]
        impl alibi_core::PasswordHasher for CountingHasher {
            async fn hash(&self, password: &str) -> AuthResult<String> {
                assert_eq!(password, "password123");
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok("dummy-hash".into())
            }
            async fn verify(&self, _: &str, _: &str) -> AuthResult<bool> {
                panic!("missing credentials must not reach verification")
            }
        }
        let mut ctx = crate::test_helpers::create_test_context().await;
        let user = crate::test_helpers::create_user(
            &ctx,
            alibi_core::CreateUser::new()
                .with_email("passwordless@example.com")
                .with_name("Passwordless"),
        )
        .await;
        let hasher = Arc::new(CountingHasher(std::sync::atomic::AtomicUsize::new(0)));
        let mut init =
            alibi_core::AuthInitContext::new(Arc::clone(&ctx.config), Arc::clone(&ctx.database));
        crate::EmailPasswordPlugin::new()
            .password_hasher(Arc::<CountingHasher>::clone(&hasher))
            .on_init(&mut init)
            .await
            .unwrap();
        ctx.extensions = init.into_parts().extensions;
        let error = check_user_password(&ctx, &user, Some("password123"), false)
            .await
            .unwrap_err();
        assert_eq!(error.error_payload().1.as_deref(), Some("INVALID_PASSWORD"));
        assert_eq!(hasher.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        verify_user_password(&ctx, &user, Some("password123"), false)
            .await
            .unwrap_err();
        check_user_password(&ctx, &user, Some("password123"), true)
            .await
            .unwrap();
        check_user_password(&ctx, &user, Some(""), false)
            .await
            .unwrap_err();
        assert_eq!(hasher.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
