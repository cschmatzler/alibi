//! Last-login tracking across passwordless and passkey sign-in, application
//! resolvers and cookie attributes.
use super::passkey_attestation::{Shape, client};
use super::passkey_matrix::{ATTESTED, Authenticator, USER_PRESENT, USER_VERIFIED};
use super::passwordless::Mailbox;
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::anonymous::{AnonymousConfig, AnonymousIdentity};
use alibi::plugins::email_otp::{EmailOtpConfig, EmailOtpDelivery, EmailOtpPlugin};
use alibi::plugins::last_login_method::{
    LastLoginMethodConfig, LastLoginMethodContext, LastLoginMethodPlugin, ResolveLastLoginMethod,
};
use alibi::plugins::magic_link::{MagicLinkConfig, MagicLinkDelivery, MagicLinkPlugin};
use alibi::plugins::oauth::{
    OAuthProvider, OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse,
};
use alibi::plugins::{AnonymousPlugin, PasskeyPlugin};
use alibi::{AuthError, AuthResult};

backend_tests!(
    last_login_tracks_every_sign_in_method,
    last_login_resolver_and_cookie_policy,
    last_login_tracks_social_callbacks
);

const COOKIE: &str = "better-auth.last_used_login_method";

struct Identity;

#[async_trait::async_trait]
impl AnonymousIdentity for Identity {
    async fn email(&self) -> AuthResult<Option<String>> {
        Ok(Some("anonymous-last-login@example.test".into()))
    }
}

fn tracked(response: &AuthResponse) -> Option<String> {
    response
        .headers
        .get_all("set-cookie")
        .find(|header| header.starts_with(&format!("{COOKIE}=")))
        .map(|header| header.split(';').next().unwrap().to_owned())
}

async fn last_login_tracks_every_sign_in_method<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let links = Arc::new(Mailbox::<MagicLinkDelivery>::default());
    let codes = Arc::new(Mailbox::<EmailOtpDelivery>::default());
    let auth = builder::<B>(&connection)
        .plugin(AnonymousPlugin::with_config(AnonymousConfig {
            identity: Some(Arc::new(Identity)),
            ..Default::default()
        }))
        .plugin(PasskeyPlugin::new())
        .plugin(MagicLinkPlugin::new(MagicLinkConfig {
            send_magic_link: Some(links.clone()),
            ..Default::default()
        }))
        .plugin(EmailOtpPlugin::new(EmailOtpConfig {
            send_verification_otp: Some(codes.clone()),
            ..Default::default()
        }))
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let mut trace = Trace::default();
    let owner = signup(&auth, "last-login-passkey@example.test").await;
    trace.value("email sign-up", json!(tracked(&owner)));
    let session = cookies(&owner);

    let key = Authenticator::new(5, "last-login-key");
    let options = call(
        &auth,
        request("/passkey/generate-register-options", None, &session),
        200,
    )
    .await;
    let client_data = client(&body(&options)["challenge"]);
    let shape = Shape {
        flags: USER_PRESENT | USER_VERIFIED | ATTESTED,
        ..Default::default()
    };
    let bytes = serde_json::to_vec(&client_data)?;
    _ = call(
        &auth,
        request(
            "/passkey/verify-registration",
            Some(json!({"response": key.registration(&client_data, &shape.build(&key, &bytes), false)})),
            &format!("{session}; {}", cookies(&options)),
        ),
        200,
    )
    .await;
    let options = call(
        &auth,
        request("/passkey/generate-authenticate-options", None, ""),
        200,
    )
    .await;
    let assertion_client =
        json!({"type": "webauthn.get", "challenge": body(&options)["challenge"], "origin": ORIGIN});
    let signed_in = call(
        &auth,
        request(
            "/passkey/verify-authentication",
            Some(
                json!({"response": key.assertion(&assertion_client, "localhost", USER_PRESENT, 2)}),
            ),
            &cookies(&options),
        ),
        200,
    )
    .await;
    trace.value("passkey", json!(tracked(&signed_in)));

    _ = call(
        &auth,
        request(
            "/sign-in/magic-link",
            Some(json!({"email": "last-login-magic@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let link = url::Url::parse(&links.take().url)?;
    let mut redeem = AuthRequest::new(HttpMethod::Get, link.path());
    redeem.query.extend(link.query_pairs().into_owned());
    let redeemed = call(&auth, redeem, 302).await;
    trace.value("magic link", json!(tracked(&redeemed)));

    _ = call(
        &auth,
        request(
            "/email-otp/send-verification-otp",
            Some(json!({"email": "last-login-otp@example.test", "type": "sign-in"})),
            "",
        ),
        200,
    )
    .await;
    let delivery = codes.take();
    let otp = call(
        &auth,
        request(
            "/sign-in/email-otp",
            Some(json!({"email": delivery.email, "otp": delivery.otp})),
            "",
        ),
        200,
    )
    .await;
    trace.value("email otp", json!(tracked(&otp)));

    let anonymous = call(
        &auth,
        request("/sign-in/anonymous", Some(json!({})), ""),
        200,
    )
    .await;
    trace.value("anonymous", json!(tracked(&anonymous)));
    let rejected = Box::pin(auth.handle_request(request(
        "/sign-up/email",
        Some(json!({
            "email": "rejected-last-login@example.test",
            "password": PASSWORD,
            "name": "Rejected",
            "lastLoginMethod": "forged",
        })),
        "",
    )))
    .await?;
    trace.response("forged method on sign-up", &rejected);
    let update = Box::pin(auth.handle_request(request(
        "/update-user",
        Some(json!({"lastLoginMethod": "forged"})),
        &session,
    )))
    .await?;
    trace.response("forged method on update", &update);
    trace.value(
        "stored methods",
        json!(
            db.text(
                "SELECT GROUP_CONCAT(email || '=' || COALESCE(last_login_method, 'none'), ',') FROM (SELECT * FROM users ORDER BY email)",
                &[],
            )
            .await?
        ),
    );
    trace.assert("last-login/every-sign-in-method");
    B::close(connection).await
}

struct Resolver;

impl ResolveLastLoginMethod for Resolver {
    fn resolve(&self, context: &LastLoginMethodContext) -> AuthResult<Option<String>> {
        let header = |name: &str| context.request.headers.get(name).map(String::as_str);
        match header("x-resolve") {
            Some("custom") => Ok(Some("custom method!(*)'".into())),
            Some("empty") => Ok(Some(String::new())),
            Some("internal") => Err(AuthError::internal("resolver unavailable")),
            Some("api") => Err(AuthError::forbidden("resolver denied")),
            _ => Ok(None),
        }
    }
}

async fn last_login_resolver_and_cookie_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let variants: Vec<(&str, LastLoginMethodConfig, bool)> = vec![
        (
            "resolver",
            LastLoginMethodConfig {
                resolver: Some(Arc::new(Resolver)),
                store_in_database: true,
                ..Default::default()
            },
            false,
        ),
        (
            "resolver cookie only",
            LastLoginMethodConfig {
                resolver: Some(Arc::new(Resolver)),
                ..Default::default()
            },
            false,
        ),
        (
            "lifetime too long",
            LastLoginMethodConfig {
                max_age: 40_000_000.0,
                ..Default::default()
            },
            false,
        ),
        (
            "strict and cross-subdomain",
            LastLoginMethodConfig {
                max_age: -1.0,
                ..Default::default()
            },
            true,
        ),
    ];
    for (index, (label, login, strict)) in variants.into_iter().enumerate() {
        let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
        if strict {
            config.session.cookie_same_site = alibi::config::SameSite::Strict;
            config.advanced.cross_sub_domain_cookies = Some(alibi::config::CrossSubDomainConfig {
                domain: "example.test".into(),
            });
        }
        let auth = AuthBuilder::new(config.clone())
            .store(B::store(Arc::new(config), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(alibi::plugins::EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .plugin(LastLoginMethodPlugin::with_config(login))
            .build()
            .await?;
        for (name, header) in [
            ("none", None),
            ("custom", Some("custom")),
            ("empty", Some("empty")),
            ("internal", Some("internal")),
            ("api", Some("api")),
        ] {
            let mut sign_up = request(
                "/sign-up/email",
                Some(json!({
                    "email": format!("policy-{index}-{name}@example.test"),
                    "password": PASSWORD,
                    "name": "Policy",
                })),
                "",
            );
            if let Some(header) = header {
                _ = sign_up.headers.insert("x-resolve".into(), header.into());
            }
            let response = Box::pin(auth.handle_request(sign_up)).await?;
            trace.response(&format!("{label}: {name}"), &response);
            trace.value(
                &format!("{label}: {name} cookie"),
                json!(tracked(&response)),
            );
        }
    }
    trace.value(
        "stored methods",
        json!(
            db.text(
                "SELECT GROUP_CONCAT(email || '=' || COALESCE(last_login_method, 'none'), ',') FROM (SELECT * FROM users ORDER BY email)",
                &[],
            )
            .await?
        ),
    );
    trace.assert("last-login/resolver-and-cookie-policy");
    B::close(connection).await
}

struct Profile;

#[async_trait::async_trait]
impl OAuthUserInfoHandler for Profile {
    async fn get_user_info(
        &self,
        _: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let user = OAuthUserInfo {
            additional_fields: Default::default(),
            id: "last-login-sub".into(),
            email: "last-login-social@example.test".into(),
            name: Some("Social".into()),
            image: None,
            email_verified: true,
        };
        Ok(OAuthUserInfoResponse {
            user_output: None,
            data: json!({"sub": user.id, "email": user.email}),
            user,
        })
    }
}

async fn last_login_tracks_social_callbacks<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let provider = Provider::start(
        "application/json",
        json!({"access_token": "provider-access", "token_type": "Bearer", "expires_in": 3600})
            .to_string(),
    )
    .await;
    let mut google = OAuthProvider::google("google-client", "google-secret");
    google.token_url = provider.url.join("token")?.into();
    google.get_user_info = Some(Arc::new(Profile));
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("google", google))
        .plugin(LastLoginMethodPlugin::with_config(LastLoginMethodConfig {
            store_in_database: true,
            ..Default::default()
        }))
        .build()
        .await?;
    let started = call(
        &auth,
        request(
            "/sign-in/social",
            Some(json!({"provider": "google", "callbackURL": "/done"})),
            "",
        ),
        200,
    )
    .await;
    let state = url::Url::parse(body(&started)["url"].as_str().unwrap())?
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let mut callback = request("/callback/google", None, &cookies(&started));
    callback.set_query_pairs([("code", "grant"), ("state", state.as_str())]);
    let finished = call(&auth, callback, 302).await;
    assert_eq!(
        tracked(&finished).as_deref(),
        Some("better-auth.last_used_login_method=google")
    );
    assert_eq!(
        db.text("SELECT last_login_method FROM users", &[])
            .await?
            .as_deref(),
        Some("google")
    );
    B::close(connection).await
}
