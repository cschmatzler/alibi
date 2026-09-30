use super::*;
use crate::plugins::test_helpers;
use better_auth_core::AuthPlugin;
use better_auth_core::wire::{SessionView, UserView};
use better_auth_core::{CreateAccount, CreateUser, HttpMethod};
use chrono::Duration;
use cookie::Cookie;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[tokio::test]
async fn skip_enrollment_hooks_retain_factor_generation_and_current_token_on_rejection() {
    use better_auth_core::{AuthConfig, CreateSession};
    use better_auth_seaorm::{Database, HookControl, SeaOrmHookContext, SeaOrmHooks, SeaOrmStore};
    struct PolicyHook {
        cancel_session: bool,
        observed: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }
    #[async_trait]
    impl SeaOrmHooks<TestSchema> for PolicyHook {
        async fn before_update_user(
            &self,
            id: &str,
            update: &mut UpdateUser,
            context: &SeaOrmHookContext<'_>,
        ) -> AuthResult<HookControl> {
            if context
                .request
                .as_ref()
                .is_some_and(|request| request.path.ends_with("/two-factor/enable"))
            {
                self.observed
                    .lock()
                    .unwrap()
                    .push(("user".into(), id.into()));
                assert_eq!(update.two_factor_enabled, Some(true));
                if !self.cancel_session {
                    return Err(AuthError::Upstream {
                        status: 400,
                        code: "USER_UPDATE_DENIED",
                        message: "Configured user update denied",
                    });
                }
            }
            Ok(HookControl::Continue)
        }
        async fn before_create_session(
            &self,
            session: &mut CreateSession,
            context: &SeaOrmHookContext<'_>,
        ) -> AuthResult<HookControl> {
            if context
                .request
                .as_ref()
                .is_some_and(|request| request.path.ends_with("/two-factor/enable"))
            {
                self.observed
                    .lock()
                    .unwrap()
                    .push(("session".into(), session.user_id.clone()));
                assert_eq!(
                    session.active_organization_id.as_deref(),
                    Some("retained-org")
                );
                assert_eq!(session.active_team_id.as_deref(), Some("retained-team"));
                assert_eq!(session.impersonated_by.as_deref(), Some("retained-admin"));
                assert_eq!(session.ip_address.as_deref(), Some("127.0.0.9"));
                assert_eq!(session.user_agent.as_deref(), Some("retained-agent"));
                return Ok(HookControl::Cancel);
            }
            Ok(HookControl::Continue)
        }
    }
    let password_hash = better_auth_core::hash_password(None, "password123")
        .await
        .unwrap();
    for cancel_session in [false, true] {
        for existing in [false, true] {
            let db = Database::connect("sqlite::memory:").await.unwrap();
            better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&db)
                .await
                .unwrap();
            let config = Arc::new(AuthConfig::new("skip-hook-secret-at-least-32-characters"));
            let mut ctx = AuthContext::new(
                config.clone(),
                Arc::new(SeaOrmStore::<TestSchema>::new(config.clone(), db.clone())),
            );
            let user = ctx
                .database
                .create_user(
                    CreateUser::new()
                        .with_name("Hook Owner")
                        .with_email("hook-owner@fixture.test"),
                )
                .await
                .unwrap();
            _ = ctx
                .database
                .create_account(CreateAccount {
                    user_id: user.id.clone(),
                    account_id: user.id.clone(),
                    provider_id: "credential".into(),
                    password: Some(password_hash.clone()),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await
                .unwrap();
            let session = ctx
                .database
                .create_session(CreateSession {
                    token: None,
                    user_id: user.id.clone(),
                    expires_at: Utc::now() + ctx.config.session.expires_in,
                    active_organization_id: Some("retained-org".into()),
                    active_team_id: Some("retained-team".into()),
                    impersonated_by: Some("retained-admin".into()),
                    ip_address: Some("127.0.0.9".into()),
                    user_agent: Some("retained-agent".into()),
                })
                .await
                .unwrap();
            let factor = if existing {
                Some(
                    ctx.database
                        .create_two_factor(CreateTwoFactor {
                            user_id: user.id.clone(),
                            secret: encrypt_value(&ctx.config.secret, "historical-secret").unwrap(),
                            backup_codes: encrypt_value(
                                &ctx.config.secret,
                                "[\"historical-backup\"]",
                            )
                            .unwrap(),
                            verified: Some(false),
                            failed_verification_count: Some(0.5),
                            locked_until: Some(Utc::now() + Duration::minutes(1)),
                        })
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
            ctx.database = Arc::new(
                SeaOrmStore::<TestSchema>::new(config, db.clone()).with_hooks(vec![Arc::new(
                    PolicyHook {
                        cancel_session,
                        observed: observed.clone(),
                    },
                )]),
            );
            let plugin = TwoFactorPlugin::with_config(TwoFactorConfig {
                skip_verification_on_enable: true,
                ..Default::default()
            });
            let mut init =
                better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
            plugin.on_init(&mut init).await.unwrap();
            crate::plugins::OrganizationPlugin::with_config(
                crate::plugins::organization::OrganizationConfig {
                    teams: crate::plugins::organization::TeamsConfig {
                        enabled: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .on_init(&mut init)
            .await
            .unwrap();
            crate::plugins::AdminPlugin::new()
                .on_init(&mut init)
                .await
                .unwrap();
            ctx.database = init.database_with_registered_transforms();
            let parts = init.into_parts();
            ctx.metadata = parts.metadata;
            ctx.extensions = parts.extensions;
            let cookie = create_session_cookie(&session.token, &ctx.config);
            let mut request = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
            _ = request
                .headers
                .insert("cookie".into(), cookie.split(';').next().unwrap().into());
            request.body = Some(br#"{"password":"password123"}"#.to_vec());
            let error = better_auth_core::with_request_hook_context(
                &request,
                plugin.on_request(&request, &ctx),
            )
            .await
            .unwrap_err();
            assert_eq!(error.status_code(), if cancel_session { 403 } else { 400 });
            let expected = if cancel_session {
                vec![
                    ("user".into(), user.id.clone()),
                    ("session".into(), user.id.clone()),
                ]
            } else {
                vec![("user".into(), user.id.clone())]
            };
            assert_eq!(*observed.lock().unwrap(), expected);
            assert_eq!(
                serde_json::to_value(
                    ctx.database
                        .get_two_factor_by_user_id(&user.id)
                        .await
                        .unwrap()
                )
                .unwrap(),
                serde_json::to_value(factor).unwrap()
            );
            let stored_user = ctx
                .database
                .get_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored_user.two_factor_enabled(), cancel_session);
            let sessions = ctx.database.get_user_sessions(&user.id).await.unwrap();
            assert_eq!(sessions.len(), 1);
            assert_eq!(
                serde_json::to_value(&sessions[0]).unwrap(),
                serde_json::to_value(&session).unwrap()
            );
            let (current_user, current_session) = ctx.require_session(&request).await.unwrap();
            assert_eq!(current_user.id, user.id);
            assert_eq!(current_session.token, session.token);
            db.close().await.unwrap();
        }
    }
}

#[tokio::test]
async fn signed_empty_factor_challenge_cannot_read_a_seeded_empty_identifier() {
    let (ctx, user, _) =
        create_test_context_with_credential_user("empty-challenge@fixture.test", true).await;
    let seeded = ctx
        .database
        .create_verification(CreateVerification {
            identifier: String::new(),
            value: user.id.clone(),
            expires_at: Utc::now() + Duration::minutes(5),
        })
        .await
        .unwrap();
    let signed = better_auth_core::utils::cookie_utils::sign_cookie_value("", &ctx.config.secret);
    assert_eq!(
        better_auth_core::utils::cookie_utils::verify_cookie_value(&signed, &ctx.config.secret),
        Some(String::new())
    );
    let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-otp");
    _ = req.headers.insert(
        "cookie".into(),
        format!(
            "{}={signed}",
            related_cookie_name(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)
        ),
    );
    let error = resolve_two_factor_state(&req, &ctx)
        .await
        .err()
        .expect("An empty signed challenge must be rejected");
    assert_eq!(error.status_code(), 401);
    let untouched = ctx
        .database
        .get_verification_by_identifier("")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(untouched.id(), seeded.id());
    assert_eq!(untouched.value(), seeded.value());
    assert_eq!(untouched.expires_at(), seeded.expires_at());
    assert_eq!(
        ctx.database
            .get_user_sessions(&user.id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn pending_factor_preferences_authenticate_the_first_cookie_and_preserve_issued_expiry() {
    let (ctx, user, _) =
        create_test_context_with_credential_user("preferences@fixture.test", true).await;
    let preference_name = related_cookie_name(&ctx.config, DONT_REMEMBER_COOKIE_SUFFIX);
    let empty = better_auth_core::utils::cookie_utils::sign_cookie_value("", &ctx.config.secret);
    let signed =
        better_auth_core::utils::cookie_utils::sign_cookie_value("true", &ctx.config.secret);
    let foreign =
        better_auth_core::utils::cookie_utils::sign_cookie_value("true", "foreign-secret");
    for (preference, temporary) in [
        (empty.clone(), false),
        (signed.clone(), true),
        (foreign, false),
        ("true".to_owned(), false),
        (format!("{empty}; {preference_name}={signed}"), false),
        (format!("{signed}; {preference_name}={empty}"), true),
    ] {
        let challenge = begin_sign_in_challenge(&user, None, &ctx).await.unwrap();
        let challenge_cookie = challenge
            .set_cookie_headers
            .iter()
            .find(|header| {
                header.starts_with(&format!(
                    "{}=",
                    related_cookie_name(&ctx.config, TWO_FACTOR_COOKIE_SUFFIX)
                ))
            })
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-otp");
        _ = req.headers.insert(
            "cookie".into(),
            format!("{challenge_cookie}; {preference_name}={preference}"),
        );
        let ResolvedTwoFactorState::Pending(pending) =
            resolve_two_factor_state(&req, &ctx).await.unwrap()
        else {
            panic!("A signed pending challenge must resolve without a session cookie");
        };
        assert_eq!(pending.dont_remember, temporary);
        let (completed, headers) = finalize_pending_two_factor(pending, &req, false, true, &ctx)
            .await
            .unwrap();
        let before = ctx
            .database
            .get_session(&completed.token)
            .await
            .unwrap()
            .unwrap();
        let lifetime = before.expires_at() - before.created_at();
        assert!(
            (lifetime - Duration::days(if temporary { 1 } else { 7 }))
                .num_milliseconds()
                .abs()
                < 1000
        );
        let mut read = AuthRequest::new(HttpMethod::Get, "/get-session");
        let cookies = headers
            .iter()
            .filter(|header| !header.contains("Max-Age=0"))
            .map(|header| header.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        _ = read.headers.insert("cookie".into(), cookies);
        let (authenticated_user, authenticated_session) = ctx.require_session(&read).await.unwrap();
        assert_eq!(authenticated_user.id(), user.id);
        assert_eq!(authenticated_session.token, completed.token);
        assert_eq!(authenticated_session.expires_at, before.expires_at());
        let after = ctx
            .database
            .get_session(&completed.token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.expires_at(), before.expires_at());
        assert_eq!(after.updated_at(), before.updated_at());
    }
}

async fn create_test_context_with_credential_user(
    email: &str,
    two_factor_enabled: bool,
) -> (AuthContext<TestSchema>, UserView, SessionView) {
    let mut ctx = test_helpers::create_test_context().await;
    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    TwoFactorPlugin::new().on_init(&mut init).await.unwrap();
    ctx.database = init.database_with_registered_transforms();
    let parts = init.into_parts();
    ctx.metadata = parts.metadata;
    ctx.extensions = parts.extensions;
    let user = test_helpers::create_user(
        &ctx,
        CreateUser::new()
            .with_email(email)
            .with_name("Two Factor Tester"),
    )
    .await;

    let password_hash = better_auth_core::hash_password(None, "password123")
        .await
        .unwrap();
    _ = ctx
        .database
        .create_account(CreateAccount {
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".to_string(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some(password_hash),
        })
        .await
        .unwrap();

    let user = if two_factor_enabled {
        UserView::from(
            &ctx.database
                .update_user(
                    &user.id,
                    better_auth_core::UpdateUser {
                        two_factor_enabled: Some(true),
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
        )
    } else {
        user
    };

    let session = test_helpers::create_session(&ctx, user.id.clone(), Duration::hours(1)).await;
    (ctx, user, session)
}

fn cookie_value(header: &str) -> String {
    Cookie::parse(header)
        .expect("Set-Cookie header should parse")
        .value()
        .to_string()
}

#[test]
fn test_signed_cookie_round_trip_and_tamper_rejection() {
    let signed = sign_cookie_value("secret-value", "payload-value").unwrap();
    let verified = verify_signed_cookie_value("secret-value", &signed).unwrap();
    assert_eq!(verified.as_deref(), Some("payload-value"));

    let tampered = signed.replacen("payload-value", "other-value", 1);
    let tampered_verified = verify_signed_cookie_value("secret-value", &tampered).unwrap();
    assert!(tampered_verified.is_none());
}

#[tokio::test]
async fn test_begin_sign_in_challenge_sets_pending_cookie_and_remember_choice() {
    let (ctx, user, _session) =
        create_test_context_with_credential_user("challenge@example.com", true).await;

    let challenge = begin_sign_in_challenge(&user, Some(false), &ctx)
        .await
        .unwrap();
    assert!(challenge.response.two_factor_redirect);

    let two_factor_cookie = challenge
        .set_cookie_headers
        .iter()
        .find(|header| header.starts_with("better-auth.two_factor="))
        .cloned()
        .expect("challenge should set the two-factor cookie");
    let dont_remember_cookie = challenge
        .set_cookie_headers
        .iter()
        .find(|header| header.starts_with("better-auth.dont_remember="))
        .cloned()
        .expect("challenge should set the remember-choice cookie");

    let two_factor_req = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Post,
        "/two-factor/verify-otp",
        None,
        None,
    );
    let mut req = two_factor_req;
    req.headers.insert(
        "cookie".to_string(),
        format!(
            "better-auth.two_factor={}; better-auth.dont_remember={}",
            cookie_value(&two_factor_cookie),
            cookie_value(&dont_remember_cookie)
        ),
    );

    let identifier = read_signed_cookie(&req, TWO_FACTOR_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .expect("signed cookie should verify");
    let verification = ctx
        .database
        .get_verification_by_identifier(&identifier)
        .await
        .unwrap()
        .expect("challenge should persist a pending verification");
    assert_eq!(verification.value(), user.id);
}

#[tokio::test]
async fn test_inspect_trusted_device_rotates_server_state() {
    let (ctx, user, _session) =
        create_test_context_with_credential_user("trusted@example.com", true).await;

    let trust_cookie = create_trust_device_cookie_header(&user, &ctx)
        .await
        .unwrap();
    let mut req = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Post,
        "/sign-in/email",
        None,
        None,
    );
    req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.trust_device={}", cookie_value(&trust_cookie)),
    );

    let original_cookie = read_signed_cookie(&req, TRUST_DEVICE_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .expect("trust cookie should verify");
    let original_identifier = original_cookie
        .split_once('!')
        .expect("trust cookie should include the identifier")
        .1
        .to_string();

    let result = inspect_trusted_device(&req, &user, &ctx).await.unwrap();
    assert!(result.trusted);
    assert_eq!(result.set_cookie_headers.len(), 1);

    let rotated_cookie = result.set_cookie_headers[0].clone();
    let mut rotated_req = test_helpers::create_auth_request_no_query(
        better_auth_core::HttpMethod::Post,
        "/sign-in/email",
        None,
        None,
    );
    rotated_req.headers.insert(
        "cookie".to_string(),
        format!("better-auth.trust_device={}", cookie_value(&rotated_cookie)),
    );
    let rotated_value = read_signed_cookie(&rotated_req, TRUST_DEVICE_COOKIE_SUFFIX, &ctx)
        .unwrap()
        .expect("rotated trust cookie should verify");
    let rotated_identifier = rotated_value
        .split_once('!')
        .expect("rotated cookie should include the identifier")
        .1
        .to_string();

    assert_ne!(original_identifier, rotated_identifier);
    assert!(
        ctx.database
            .get_verification_by_identifier(&original_identifier)
            .await
            .unwrap()
            .is_none(),
        "the previous trust-device record should be deleted during rotation",
    );
    assert!(
        ctx.database
            .get_verification_by_identifier(&rotated_identifier)
            .await
            .unwrap()
            .is_some(),
        "the rotated trust-device record should be persisted",
    );
}

#[tokio::test]
async fn totp_enrollment_and_real_verification_apply_user_hooks_and_preserve_rotation_owner() {
    let (mut ctx, user, session) =
        create_test_context_with_credential_user("reissue@example.com", false).await;
    ctx.database.delete_session(&session.token).await.unwrap();
    let session = ctx
        .database
        .create_session(better_auth_core::CreateSession {
            token: None,
            user_id: user.id.clone(),
            expires_at: session.expires_at,
            ip_address: Some("127.0.0.7".into()),
            user_agent: Some("configured-agent".into()),
            active_organization_id: Some("configured-organization".into()),
            active_team_id: Some("configured-team".into()),
            impersonated_by: Some("configured-admin".into()),
        })
        .await
        .unwrap();
    let plugin = TwoFactorPlugin::new();
    let mut configured =
        better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    plugin.on_init(&mut configured).await.unwrap();
    crate::plugins::OrganizationPlugin::with_config(
        crate::plugins::organization::OrganizationConfig {
            teams: crate::plugins::organization::TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .on_init(&mut configured)
    .await
    .unwrap();
    crate::plugins::AdminPlugin::new()
        .on_init(&mut configured)
        .await
        .unwrap();
    ctx.metadata = configured.into_parts().metadata;
    let cookie = create_session_cookie(&session.token, &ctx.config);
    let mut enrollment = AuthRequest::new(HttpMethod::Post, "/two-factor/enable");
    _ = enrollment
        .headers
        .insert("cookie".into(), cookie.split(';').next().unwrap().into());
    enrollment.body = Some(br#"{"password":"password123"}"#.to_vec());
    let enabled = plugin.on_request(&enrollment, &ctx).await.unwrap().unwrap();
    assert_eq!(enabled.status, 200);
    let factor = ctx
        .database
        .get_two_factor_by_user_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(factor.verified, Some(false));

    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = captured.clone();
    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    init.register_user_update_transform(move |id, mut update| {
        observed
            .lock()
            .unwrap()
            .push((id.to_owned(), update.two_factor_enabled));
        if update.two_factor_enabled == Some(true) {
            update.name = Some("Hook Updated Owner".into());
        }
        Ok(update)
    });
    ctx.database = init.database_with_registered_transforms();
    let plaintext = decrypt_value(&ctx.config.secret, &factor.secret).unwrap();
    let code = plugin.generate_totp(&plaintext).unwrap();
    let mut verification = AuthRequest::new(HttpMethod::Post, "/two-factor/verify-totp");
    verification.headers = enrollment.headers;
    verification.body = Some(serde_json::to_vec(&serde_json::json!({"code":code})).unwrap());
    let response = plugin
        .on_request(&verification, &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    let payload: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(payload["user"]["twoFactorEnabled"], false);
    // Upstream returns the old snapshot while rotating the browser cookie.
    assert_eq!(payload["token"], session.token);
    let set_cookie_headers = response.headers.get_all("Set-Cookie").collect::<Vec<_>>();
    let rotated = better_auth_core::utils::cookie_utils::verify_cookie_value(
        &cookie_value(set_cookie_headers[0]),
        &ctx.config.secret,
    )
    .expect("the session cookie must authenticate its token");
    assert_ne!(rotated, session.token);
    assert_eq!(set_cookie_headers.len(), 1);
    assert!(
        ctx.database
            .get_session(&session.token)
            .await
            .unwrap()
            .is_none(),
        "the original session should be deleted after re-issuing",
    );
    assert!(
        ctx.database.get_session(&rotated).await.unwrap().is_some(),
        "the new session token should be persisted",
    );
    assert_eq!(
        *captured.lock().unwrap(),
        vec![(user.id.clone(), Some(true))]
    );
    let stored_user = ctx
        .database
        .get_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_user.two_factor_enabled, Some(true));
    assert_eq!(stored_user.name.as_deref(), Some("Hook Updated Owner"));
    let verified_factor = ctx
        .database
        .get_two_factor_by_user_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(verified_factor.id, factor.id);
    assert_eq!(verified_factor.secret, factor.secret);
    assert_eq!(verified_factor.backup_codes, factor.backup_codes);
    assert_eq!(verified_factor.verified, Some(true));
    let mut browser = AuthRequest::new(HttpMethod::Get, "/get-session");
    _ = browser.headers.insert(
        "cookie".into(),
        set_cookie_headers[0].split(';').next().unwrap().into(),
    );
    let (current_user, current_session) = ctx.require_session(&browser).await.unwrap();
    assert_eq!(current_user.id, user.id);
    assert_eq!(current_user.name.as_deref(), Some("Hook Updated Owner"));
    assert_eq!(current_session.token, rotated);
    assert_eq!(current_session.ip_address, session.ip_address);
    assert_eq!(current_session.user_agent, session.user_agent);
    assert_eq!(
        current_session.active_organization_id,
        session.active_organization_id
    );
    assert_eq!(current_session.active_team_id, session.active_team_id);
    assert_eq!(current_session.impersonated_by, session.impersonated_by);
}

#[tokio::test]
async fn test_view_backup_codes_returns_decrypted_codes() {
    let plugin = TwoFactorPlugin::new();
    let (ctx, user, _session) =
        create_test_context_with_credential_user("view-codes@example.com", true).await;

    let expected_codes = vec!["ABCDE-12345".to_string(), "FGHIJ-67890".to_string()];
    let encrypted = encrypt_value(
        &ctx.config.secret,
        &serde_json::to_string(&expected_codes).unwrap(),
    )
    .unwrap();
    _ = ctx
        .database
        .create_two_factor(better_auth_core::CreateTwoFactor {
            user_id: user.id.clone(),
            secret: encrypt_value(&ctx.config.secret, "totp-secret").unwrap(),
            backup_codes: encrypted,
            ..Default::default()
        })
        .await
        .unwrap();

    let backup_codes = plugin.view_backup_codes(&user.id, &ctx).await.unwrap();
    assert_eq!(backup_codes, expected_codes);
}

#[tokio::test]
async fn test_view_backup_codes_rejects_invalid_stored_json() {
    let plugin = TwoFactorPlugin::new();
    let (ctx, user, _session) =
        create_test_context_with_credential_user("invalid-view-codes@example.com", true).await;

    _ = ctx
        .database
        .create_two_factor(better_auth_core::CreateTwoFactor {
            user_id: user.id.clone(),
            secret: encrypt_value(&ctx.config.secret, "totp-secret").unwrap(),
            backup_codes: encrypt_value(&ctx.config.secret, "\"not-an-array\"").unwrap(),
            ..Default::default()
        })
        .await
        .unwrap();

    let err = plugin.view_backup_codes(&user.id, &ctx).await.unwrap_err();
    assert_eq!(err.to_string(), "Invalid backup code");
}

#[test]
fn test_routes_do_not_expose_view_backup_codes() {
    let plugin = TwoFactorPlugin::new();
    assert!(
        <TwoFactorPlugin as AuthPlugin<TestSchema>>::routes(&plugin)
            .iter()
            .all(|route| route.path != "/two-factor/view-backup-codes"),
        "view-backup-codes must stay server-only",
    );
}

#[tokio::test]
async fn disable_preserves_persisted_extensions_and_removes_all_matching_trust_records() {
    let (mut ctx, user, first_session) =
        create_test_context_with_credential_user("disable-extensions@fixture.test", true).await;
    let mut init = better_auth_core::AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    crate::plugins::admin::AdminPlugin::new()
        .on_init(&mut init)
        .await
        .unwrap();
    crate::plugins::organization::OrganizationPlugin::with_config(
        crate::plugins::organization::OrganizationConfig {
            teams: crate::plugins::organization::TeamsConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .on_init(&mut init)
    .await
    .unwrap();
    ctx.metadata.extend(init.into_parts().metadata);
    ctx.database
        .delete_session(&first_session.token)
        .await
        .unwrap();
    let current = ctx
        .database
        .create_session(better_auth_core::CreateSession {
            token: None,
            user_id: user.id.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: Some("192.0.2.45".to_owned()),
            user_agent: Some("fixture-agent".to_owned()),
            impersonated_by: Some("trusted-impersonator".to_owned()),
            active_organization_id: Some("trusted-organization".to_owned()),
            active_team_id: Some("trusted-team".to_owned()),
            additional_fields: Default::default(),
        })
        .await
        .unwrap();
    ctx.database
        .create_two_factor(CreateTwoFactor {
            user_id: user.id.clone(),
            secret: "stored-secret".to_owned(),
            backup_codes: "stored-codes".to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
    for _ in 0..2 {
        ctx.database
            .create_verification(CreateVerification {
                identifier: "trusted-device-record".to_owned(),
                value: user.id.clone(),
                expires_at: Utc::now() + Duration::days(30),
            })
            .await
            .unwrap();
    }
    let session_cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
        current.token(),
        &ctx.config.secret,
    );
    let trust_cookie = better_auth_core::utils::cookie_utils::sign_cookie_value(
        "trust-token!trusted-device-record",
        &ctx.config.secret,
    );
    let mut req = AuthRequest::new(HttpMethod::Post, "/two-factor/disable");
    req.body = Some(serde_json::to_vec(&serde_json::json!({"password":"password123"})).unwrap());
    _ = req.headers.insert(
        "cookie".to_owned(),
        format!(
            "{}={session_cookie}; {}={trust_cookie}",
            ctx.config.session.cookie_name,
            related_cookie_name(&ctx.config, TRUST_DEVICE_COOKIE_SUFFIX)
        ),
    );
    let response = TwoFactorPlugin::new()
        .on_request(&req, &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    let stored = ctx.database.get_user_sessions(&user.id).await.unwrap();
    assert_eq!(stored.len(), 1);
    let replacement = &stored[0];
    assert_ne!(replacement.token(), current.token());
    assert_eq!(
        replacement.active_organization_id(),
        Some("trusted-organization")
    );
    assert_eq!(replacement.active_team_id(), Some("trusted-team"));
    assert_eq!(replacement.impersonated_by(), Some("trusted-impersonator"));
    assert_eq!(replacement.ip_address(), current.ip_address());
    assert_eq!(replacement.user_agent(), current.user_agent());
    assert!(
        ctx.database
            .get_session(current.token())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !ctx.database
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .two_factor_enabled()
    );
    assert!(
        ctx.database
            .get_two_factor_by_user_id(&user.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        ctx.database
            .get_verification_by_identifier("trusted-device-record")
            .await
            .unwrap()
            .is_none()
    );
}
