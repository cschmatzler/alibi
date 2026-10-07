//! Trusted Rust entry points have distinct authority and publication contracts
//! from HTTP routes. Exercise the public dispatcher with real stores and cookies.
mod hooks;

use super::*;
use alibi::plugins::api_key::{ApiKeyPlugin, CreateKeyRequest};
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpPlugin, EmailOtpType};
use alibi::plugins::jwt::JwtPlugin;
use alibi::plugins::one_time_token::{OneTimeTokenConfig, OneTimeTokenPlugin};
use alibi::plugins::organization::OrganizationPlugin;
use alibi::plugins::organization::types::{
    AddOrganizationMemberRequest, CreateOrganizationRequest, DeleteOrganizationRequest,
    RemoveMemberRequest, RoleInput,
};
use alibi_core::endpoint::EndpointOptions;
use alibi_core::utils::json::parse_value;

backend_tests!(
    server_otp_can_bootstrap_a_password_without_replacing_sessions,
    server_jwt_signatures_are_usable_by_an_independent_consumer,
    server_one_time_token_distinguishes_logical_and_client_requests,
    server_organization_authority_and_member_lifecycle
);
postgres_tests!(
    server_otp_can_bootstrap_a_password_without_replacing_sessions,
    server_jwt_signatures_are_usable_by_an_independent_consumer,
    server_one_time_token_distinguishes_logical_and_client_requests,
    server_organization_authority_and_member_lifecycle
);

fn credentials(cookie: &str) -> EndpointOptions {
    EndpointOptions {
        headers: Some([("cookie".into(), cookie.into())].into_iter().collect()),
        ..Default::default()
    }
}

#[derive(Clone, Default)]
struct PasswordPolicyProbe {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
#[async_trait::async_trait]
impl alibi_core::PasswordHasher for PasswordPolicyProbe {
    async fn hash(&self, password: &str) -> alibi_core::AuthResult<String> {
        self.events.lock().unwrap().push("hasher");
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(alibi_core::AuthError::forbidden("Hasher rejected"));
        }
        alibi_core::PasswordHasher::hash(&alibi_core::ScryptHasher, password).await
    }
    async fn verify(&self, hash: &str, password: &str) -> alibi_core::AuthResult<bool> {
        alibi_core::PasswordHasher::verify(&alibi_core::ScryptHasher, hash, password).await
    }
}
#[async_trait::async_trait]
impl alibi_core::PasswordHashHook for PasswordPolicyProbe {
    async fn before_hash(
        &self,
        _: &str,
        context: Option<&alibi_core::PasswordHashContext>,
    ) -> alibi_core::AuthResult<()> {
        assert_eq!(context.unwrap().path.as_deref(), Some("virtual:"));
        self.events.lock().unwrap().push("hook");
        Ok(())
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> alibi_core::AuthPlugin<S> for PasswordPolicyProbe {
    fn name(&self) -> &'static str {
        "application-password-policy"
    }
    fn routes(&self) -> Vec<alibi_core::AuthRoute> {
        Vec::new()
    }
    async fn on_request(
        &self,
        _: &AuthRequest,
        _: &alibi_core::AuthContext<S>,
    ) -> alibi_core::AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
    async fn on_init(
        &self,
        context: &mut alibi_core::AuthInitContext<S>,
    ) -> alibi_core::AuthResult<()> {
        context.register_password_hash_hook(Arc::new(self.clone()));
        Ok(())
    }
}

async fn server_otp_can_bootstrap_a_password_without_replacing_sessions<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(EmailOtpPlugin::new(EmailOtpConfig::default()))
        .build()
        .await?;
    let email = "server-otp@example.test";
    let generated = auth
        .dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(email, EmailOtpType::SignIn),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert_eq!(generated.len(), 6);
    assert!(generated.bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(db.count("users").await?, 0);
    assert_eq!(db.count("verifications").await?, 1);
    assert_eq!(
        auth.dispatch_endpoint(
            EmailOtpPlugin::get_verification_otp_endpoint(email, EmailOtpType::SignIn),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .otp
        .as_deref(),
        Some(generated.as_str())
    );
    assert!(
        auth.dispatch_endpoint(
            EmailOtpPlugin::get_verification_otp_endpoint(email, EmailOtpType::ForgetPassword),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .otp
        .is_none()
    );
    let accepted = call(
        &auth,
        request(
            "/sign-in/email-otp",
            Some(json!({"email":email,"otp":generated})),
            "",
        ),
        200,
    )
    .await;
    let cookie = cookies(&accepted);
    authenticated(&auth, &cookie, email).await;
    assert!(
        auth.dispatch_endpoint(
            EmailOtpPlugin::get_verification_otp_endpoint(email, EmailOtpType::SignIn),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .otp
        .is_none()
    );
    let original_sessions = db.table("sessions").await?;
    assert_eq!(db.count("accounts").await?, 0);
    let context = auth.context();
    let authorized = request("/server-only", None, &cookie);
    for (cookie, password, status) in [
        ("", PASSWORD, 401),
        ("better-auth.session_token=forged", PASSWORD, 401),
        (&*cookie, "short", 400),
    ] {
        let denied = alibi::plugins::password_management::set_password(
            &request("/server-only", None, cookie),
            password,
            context,
        )
        .await
        .unwrap_err();
        assert_eq!(denied.status_code(), status);
        assert_eq!(db.count("accounts").await?, 0);
    }
    alibi::plugins::password_management::set_password(&authorized, PASSWORD, context).await?;
    assert_eq!(db.count("accounts").await?, 1);
    assert_eq!(db.table("sessions").await?, original_sessions);
    let accounts = db.table("accounts").await?;
    let denied = alibi::plugins::password_management::set_password(
        &authorized,
        "a-different-password",
        context,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        denied,
        alibi_core::AuthError::Upstream {
            code: "PASSWORD_ALREADY_SET",
            ..
        }
    ));
    assert_eq!(db.table("accounts").await?, accounts);
    let login = call(
        &auth,
        request(
            "/sign-in/email",
            Some(json!({"email":email,"password":PASSWORD})),
            "",
        ),
        200,
    )
    .await;
    authenticated(&auth, &cookies(&login), email).await;
    authenticated(&auth, &cookie, email).await;
    let probe = PasswordPolicyProbe::default();
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.session.cookie_cache = Some(alibi_core::config::CookieCacheConfig {
        enabled: true,
        ..Default::default()
    });
    let configured = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .plugin(
            EmailPasswordPlugin::new()
                .password_min_length(8)
                .password_max_length(10)
                .password_hasher(Arc::new(probe.clone())),
        )
        .plugin(SessionManagementPlugin::new())
        .plugin(EmailOtpPlugin::new(EmailOtpConfig::default()))
        .plugin(probe.clone())
        .build()
        .await?;
    let policy_email = "server-hash-policy@example.test";
    let code = configured
        .dispatch_endpoint(
            EmailOtpPlugin::create_verification_otp_endpoint(policy_email, EmailOtpType::SignIn),
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    let issued = call(
        &configured,
        request(
            "/sign-in/email-otp",
            Some(json!({"email":policy_email,"otp":code})),
            "",
        ),
        200,
    )
    .await;
    let policy_cookie = cookies(&issued);
    assert!(policy_cookie.contains("session_data="));
    let user = body(&issued)["user"]["id"].as_str().unwrap().to_owned();
    let credential = configured
        .store()
        .create_account(alibi_core::CreateAccount {
            user_id: user.clone(),
            account_id: user.clone(),
            provider_id: "credential".into(),
            password: Some(String::new()),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            additional_fields: Default::default(),
        })
        .await?;
    let empty_accounts = db.table("accounts").await?;
    let sessions = db.table("sessions").await?;
    let input = request(
        "/caller-path-is-not-the-logical-identity",
        None,
        &policy_cookie,
    );
    for (password, expected) in [
        ("😀😀😀a", "PASSWORD_TOO_SHORT"),
        ("😀😀😀😀😀😀", "PASSWORD_TOO_LONG"),
    ] {
        let error = alibi::plugins::password_management::set_password(
            &input,
            password,
            configured.context(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error,alibi_core::AuthError::Upstream {code,..} if code==expected));
        assert_eq!(db.table("accounts").await?, empty_accounts);
    }
    assert!(probe.events.lock().unwrap().is_empty());
    probe.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let failed =
        alibi::plugins::password_management::set_password(&input, "😀😀😀😀", configured.context())
            .await
            .unwrap_err();
    assert_eq!(failed.status_code(), 403);
    assert_eq!(db.table("accounts").await?, empty_accounts);
    probe.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    alibi::plugins::password_management::set_password(&input, "😀😀😀😀", configured.context())
        .await?;
    use alibi_core::entity::AuthAccount;
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM accounts WHERE user_id=$1", &[&user])
            .await?,
        1
    );
    let saved = configured.store().get_user_accounts(&user).await?;
    assert_eq!(saved[0].id(), credential.id());
    assert!(
        alibi_core::PasswordHasher::verify(
            &alibi_core::ScryptHasher,
            saved[0].password().unwrap(),
            "😀😀😀😀"
        )
        .await?
    );
    assert_eq!(db.table("sessions").await?, sessions);
    let saved_accounts = db.table("accounts").await?;
    let duplicate = alibi::plugins::password_management::set_password(
        &input,
        "😀😀😀😀😀",
        configured.context(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        duplicate,
        alibi_core::AuthError::Upstream {
            code: "PASSWORD_ALREADY_SET",
            ..
        }
    ));
    assert_eq!(
        *probe.events.lock().unwrap(),
        vec!["hook", "hasher", "hook", "hasher", "hook", "hasher"]
    );
    assert_eq!(db.table("accounts").await?, saved_accounts);
    let login = call(
        &configured,
        request(
            "/sign-in/email",
            Some(json!({"email":policy_email,"password":"😀😀😀😀"})),
            "",
        ),
        200,
    )
    .await;
    authenticated(&configured, &cookies(&login), policy_email).await;
    configured
        .store()
        .delete_session(body(&issued)["token"].as_str().unwrap())
        .await?;
    // Cached presentation still works, but cannot authorize credential changes.
    authenticated(&configured, &policy_cookie, policy_email).await;
    let denied =
        alibi::plugins::password_management::set_password(&input, "😀😀😀😀", configured.context())
            .await
            .unwrap_err();
    assert_eq!(denied.status_code(), 401);
    assert_eq!(probe.events.lock().unwrap().len(), 6);
    assert_eq!(db.table("accounts").await?, saved_accounts);
    B::close(connection).await
}

async fn server_jwt_signatures_are_usable_by_an_independent_consumer<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(
            ApiKeyPlugin::builder()
                .enable_session_for_api_keys(true)
                .build(),
        )
        .plugin(JwtPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "jwt-server@example.test").await;
    for (options, status) in [(EndpointOptions::default(), 400), (credentials(""), 401)] {
        assert_eq!(
            auth.dispatch_endpoint(JwtPlugin::token_endpoint(), options)
                .await
                .unwrap_err()
                .error
                .status_code(),
            status
        );
    }
    let session_token = auth
        .dispatch_endpoint(JwtPlugin::token_endpoint(), credentials(&cookies(&owner)))
        .await?
        .decode()?
        .token;
    let key = auth
        .dispatch_endpoint(
            ApiKeyPlugin::create_endpoint(&CreateKeyRequest {
                user_id: Some(body(&owner)["user"]["id"].as_str().unwrap().into()),
                remaining: Some(2.0),
                ..Default::default()
            })?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    let virtual_options = || EndpointOptions {
        headers: Some(
            [("x-api-key".into(), key.key.clone())]
                .into_iter()
                .collect(),
        ),
        ..Default::default()
    };
    let original_sessions = db.table("sessions").await?;
    let virtual_token = auth
        .dispatch_endpoint(JwtPlugin::token_endpoint(), virtual_options())
        .await?
        .decode()?
        .token;
    assert_eq!(
        auth.store()
            .get_api_key_by_id(&key.api_key.id)
            .await?
            .unwrap()
            .remaining,
        Some(1.0)
    );
    assert_eq!(db.table("sessions").await?, original_sessions);
    let deleted = call(
        &auth,
        request(
            "/api-key/delete",
            Some(json!({"keyId":key.api_key.id})),
            &cookies(&owner),
        ),
        200,
    )
    .await;
    assert_eq!(body(&deleted)["success"], true);
    assert!(
        auth.dispatch_endpoint(JwtPlugin::token_endpoint(), virtual_options())
            .await
            .is_err()
    );
    assert_eq!(db.count("api_keys").await?, 0);
    assert_eq!(db.table("sessions").await?, original_sessions);
    let signed = auth
        .dispatch_endpoint(
            JwtPlugin::sign_endpoint(parse_value(r#"{"sub":"service-worker","task":"export"}"#)?),
            EndpointOptions::default(),
        )
        .await?
        .decode()?
        .token;
    let published = auth
        .dispatch_endpoint(JwtPlugin::jwks_endpoint(), EndpointOptions::default())
        .await?
        .decode()?;
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(published.clone())?;
    assert_eq!(db.count("jwks").await?, 1);
    assert!(
        published["keys"]
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key.get("d").is_none())
    );
    for (token, subject) in [
        (&session_token, body(&owner)["user"]["id"].as_str().unwrap()),
        (&signed, "service-worker"),
        (&virtual_token, body(&owner)["user"]["id"].as_str().unwrap()),
    ] {
        let header = jsonwebtoken::decode_header(token)?;
        let key = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&[ORIGIN]);
        validation.set_audience(&[ORIGIN]);
        let claims = jsonwebtoken::decode::<Value>(
            token,
            &jsonwebtoken::DecodingKey::from_jwk(key)?,
            &validation,
        )?
        .claims;
        assert_eq!(claims["sub"], subject);
        if subject == "service-worker" {
            assert_eq!(claims["task"], "export");
        }
    }
    Box::pin(verify_jwt_overrides(&auth, &jwks, &db)).await?;
    // Signature damage remains a verification denial through the typed entry point.
    let mut damaged = signed.into_bytes();
    let signature = damaged.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    damaged[signature] = if damaged[signature] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert!(
        auth.dispatch_endpoint(
            JwtPlugin::verify_endpoint(String::from_utf8(damaged)?, None),
            EndpointOptions::default()
        )
        .await?
        .decode()?
        .payload
        .is_none()
    );
    B::close(connection).await
}

async fn server_one_time_token_distinguishes_logical_and_client_requests<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
            disable_client_request: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "ott-server@example.test").await;
    let cookie = cookies(&owner);
    let physical = request("/one-time-token/generate", None, &cookie);
    let denied = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::generate_endpoint(),
            EndpointOptions {
                request: Some(physical.clone()),
                ..credentials(&cookie)
            },
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(db.count("verifications").await?, 0);
    let _ = call(&auth, physical, 400).await;
    let token = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::generate_endpoint(),
            credentials(&cookie),
        )
        .await?
        .decode()?
        .token;
    assert_eq!(db.count("verifications").await?, 1);
    let original_sessions = db.table("sessions").await?;
    let verified = auth
        .dispatch_endpoint(
            OneTimeTokenPlugin::verify_endpoint(&token),
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(verified.decode()?.user.id, body(&owner)["user"]["id"]);
    let republished = verified
        .headers()
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    authenticated(&auth, &republished, "ott-server@example.test").await;
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.table("sessions").await?, original_sessions);
    assert_eq!(
        auth.dispatch_endpoint(
            OneTimeTokenPlugin::verify_endpoint(token),
            EndpointOptions::default()
        )
        .await
        .unwrap_err()
        .error
        .status_code(),
        400
    );
    B::close(connection).await
}

async fn server_organization_authority_and_member_lifecycle<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "org-owner@example.test").await;
    let member = signup(&auth, "org-member@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let member_id = body(&member)["user"]["id"].as_str().unwrap().to_owned();
    let create = CreateOrganizationRequest {
        additional_fields: Default::default(),
        name: "Server organization".into(),
        slug: "server-org".into(),
        logo: None,
        metadata: None,
        keep_current_active_organization: None,
    };
    // Only a trusted, headerless call may use the explicit owner fallback.
    let denied = auth
        .dispatch_endpoint(
            OrganizationPlugin::create_endpoint(&create, Some(&owner_id))?,
            credentials(""),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.error.status_code(), 401);
    assert_eq!(db.count("organization").await?, 0);
    let created = auth
        .dispatch_endpoint(
            OrganizationPlugin::create_endpoint(&create, Some(&owner_id))?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    let organization_id = created.organization.id;
    assert_eq!(db.count("organization").await?, 1);
    assert_eq!(db.count_where("SELECT COUNT(*) FROM member WHERE organization_id = $1 AND user_id = $2 AND role = 'owner'", &[&organization_id, &owner_id]).await?, 1);
    let member_input = AddOrganizationMemberRequest {
        user_id: member_id.clone(),
        role: RoleInput::One("member".into()),
        organization_id: Some(organization_id.clone()),
        team_id: None,
    };
    let admitted = auth
        .dispatch_endpoint(
            OrganizationPlugin::add_member_endpoint(&member_input)?,
            EndpointOptions::default(),
        )
        .await?
        .decode()?;
    assert_eq!(admitted.user_id, member_id);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id = $1 AND user_id = $2",
            &[&organization_id, &member_id]
        )
        .await?,
        1
    );
    let delete = DeleteOrganizationRequest {
        organization_id: organization_id.clone(),
    };
    assert_eq!(
        auth.dispatch_endpoint(
            OrganizationPlugin::delete_endpoint(&delete)?,
            credentials(&cookies(&member))
        )
        .await
        .unwrap_err()
        .error
        .status_code(),
        403
    );
    assert_eq!(db.count("organization").await?, 1);
    let remove = RemoveMemberRequest {
        member_id_or_email: admitted.id,
        organization_id: Some(organization_id.clone()),
    };
    let retained = db.tables(&["organization", "member", "sessions"]).await?;
    for options in [EndpointOptions::default(), credentials(&cookies(&member))] {
        let denied = auth
            .dispatch_endpoint(
                OrganizationPlugin::remove_member_endpoint(&remove)?,
                options,
            )
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 401);
        assert_eq!(
            db.tables(&["organization", "member", "sessions"]).await?,
            retained
        );
    }
    let _removed = auth
        .dispatch_endpoint(
            OrganizationPlugin::remove_member_endpoint(&remove)?,
            credentials(&cookies(&owner)),
        )
        .await?
        .decode()?;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id = $1 AND user_id = $2",
            &[&organization_id, &member_id]
        )
        .await?,
        0
    );
    let _deleted = auth
        .dispatch_endpoint(
            OrganizationPlugin::delete_endpoint(&delete)?,
            credentials(&cookies(&owner)),
        )
        .await?
        .decode()?;
    assert_eq!(db.count("organization").await?, 0);
    assert_eq!(db.count("member").await?, 0);
    assert_eq!(db.count("users").await?, 2);
    B::close(connection).await
}

async fn verify_jwt_overrides<S: AuthSchema>(
    auth: &BetterAuth<S>,
    jwks: &jsonwebtoken::jwk::JwkSet,
    db: &Db,
) -> TestResult {
    // Per-call options must affect independently verifiable claims without
    // changing the installed plugin or persisting invalid key configuration.
    let issued_at = chrono::Utc::now().timestamp();
    for (expiration, seconds) in [
        (json!(issued_at + 120), 120),
        (json!("+ 2 minutes"), 120),
        (json!("1 hour from now"), 3600),
        (json!("1 minute ago"), -60),
    ] {
        let payload = json!({"payload":{"sub":"override-worker","iat":issued_at},"overrideOptions":{"jwt":{"issuer":"https://issuer.test","audience":["consumer-a","consumer-b"],"expirationTime":expiration},"jwks":{"keyPairConfig":{"alg":"EdDSA"},"keyPairConfigs":[],"rotationInterval":3600,"gracePeriod":7200,"disablePrivateKeyEncryption":false}}});
        let endpoint = JwtPlugin::sign_endpoint(parse_value("{}")?)
            .with_body_value(parse_value(&payload.to_string())?);
        let token = Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
            .await?
            .decode()?
            .token;
        let header = jsonwebtoken::decode_header(&token)?;
        let key = jwks.find(header.kid.as_deref().unwrap()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["https://issuer.test"]);
        validation.set_audience(&["consumer-b"]);
        validation.validate_exp = false;
        let claims = jsonwebtoken::decode::<Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_jwk(key)?,
            &validation,
        )?
        .claims;
        assert_eq!(claims["sub"], "override-worker");
        assert_eq!(claims["aud"], json!(["consumer-a", "consumer-b"]));
        assert_eq!(
            claims["exp"].as_f64().unwrap() - claims["iat"].as_f64().unwrap(),
            f64::from(seconds)
        );
    }
    let stored_keys = db.table("jwks").await?;
    for overrides in [
        json!({"jwt":{"issuer":42}}),
        json!({"jwt":{"expirationTime":true}}),
        json!({"jwt":{"expirationTime":"+1 minute ago"}}),
        json!({"jwks":{"keyPairConfig":{"alg":"unsupported"}}}),
        json!({"jwks":{"keyPairConfig":{"alg":"RS256","modulusLength":2048.5}}}),
        json!({"jwks":{"rotationInterval":1e100}}),
    ] {
        let input = json!({"payload":{"sub":"invalid"},"overrideOptions":overrides});
        let endpoint = JwtPlugin::sign_endpoint(parse_value("{}")?)
            .with_body_value(parse_value(&input.to_string())?);
        assert!(
            Box::pin(auth.dispatch_endpoint(endpoint, EndpointOptions::default()))
                .await
                .is_err()
        );
        assert_eq!(db.table("jwks").await?, stored_keys);
    }
    let default_token = Box::pin(auth.dispatch_endpoint(
        JwtPlugin::sign_endpoint(parse_value(r#"{"sub":"default-after-overrides"}"#)?),
        EndpointOptions::default(),
    ))
    .await?
    .decode()?
    .token;
    let header = jsonwebtoken::decode_header(&default_token)?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&[ORIGIN]);
    validation.set_audience(&[ORIGIN]);
    assert_eq!(
        jsonwebtoken::decode::<Value>(
            &default_token,
            &jsonwebtoken::DecodingKey::from_jwk(
                jwks.find(header.kid.as_deref().unwrap()).unwrap()
            )?,
            &validation
        )?
        .claims["sub"],
        "default-after-overrides"
    );
    Ok(())
}
