//! OAuth proxy forwarding and completion outcomes through one deployment
//! acting as both the production receiver and the preview bridge.
use super::social_flows::{Social, authorize};
use super::*;
use crate::snapshot::Trace;
use alibi::hooks::RequestHookContext;
use alibi::plugins::{OAuthProxyConfig, OAuthProxyPlugin};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::user_validation::{UserInfoValidator, UserValidationData, UserValidationRejection};
use alibi::{AuthResult, CreateSession};

backend_tests!(
    proxy_forwards_and_completes_provider_flows,
    proxy_error_destinations_and_pass_through,
    proxy_session_and_identity_failures
);

const PRODUCTION: &str = "http://127.0.0.1:43219";

struct Deny;

#[async_trait::async_trait]
impl UserInfoValidator for Deny {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        Ok(data
            .user
            .email
            .as_deref()
            .is_some_and(|email| email.starts_with("deny"))
            .then(|| UserValidationRejection {
                error: "PROXY_DENIED".into(),
                error_description: Some("Proxy identity denied".into()),
            }))
    }
}

#[derive(Clone, Copy)]
enum Refusal {
    Cancel,
    Forbidden,
    Coded,
    Internal,
}

struct Refuse(Refusal);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Refuse {
    async fn before_create_session(
        &self,
        _: &mut CreateSession,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        match self.0 {
            Refusal::Cancel => Ok(HookControl::Cancel),
            Refusal::Forbidden => Err(alibi::AuthError::forbidden("session refused")),
            Refusal::Coded => Err(alibi::AuthError::Api {
                status: 403,
                code: Some("SESSION_REFUSED".into()),
                message: "Session refused by policy".into(),
            }),
            Refusal::Internal => Err(alibi::AuthError::internal("session store failure")),
        }
    }
}

fn config(tweak: impl FnOnce(&mut AuthConfig)) -> AuthConfig {
    let mut config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(PRODUCTION);
    config.user_validation = Some(Arc::new(Deny));
    tweak(&mut config);
    config
}

fn proxy() -> OAuthProxyPlugin {
    OAuthProxyPlugin::with_config(OAuthProxyConfig {
        current_url: Some(ORIGIN.into()),
        production_url: Some(PRODUCTION.into()),
        ..Default::default()
    })
}

/// Location and status with the encrypted profile replaced by a marker.
fn outcome(response: &AuthResponse) -> Value {
    let location = response.headers.get("location").map(|location| {
        let mut url = url::Url::parse(location).unwrap();
        let pairs = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if key == "profile" {
                    "<profile>".into()
                } else {
                    value
                };
                (key.into_owned(), value.into_owned())
            })
            .collect::<Vec<_>>();
        if !pairs.is_empty() {
            _ = url.query_pairs_mut().clear().extend_pairs(pairs);
        }
        url.to_string()
    });
    json!({"status": response.status, "location": location})
}

async fn get<S: AuthSchema>(
    auth: &Alibi<S>,
    path: &str,
    query: &[(&str, &str)],
    cookie: &str,
) -> AuthResponse {
    let mut req = request(path, None, cookie);
    req.set_query_pairs(query.iter().copied());
    Box::pin(auth.handle_request(req)).await.unwrap()
}

/// Production receives the provider callback; its answer redirects to the bridge.
async fn forward<S: AuthSchema>(
    auth: &Alibi<S>,
    state: &str,
    code: &str,
    cookie: &str,
) -> AuthResponse {
    get(
        auth,
        "/callback/google",
        &[("code", code), ("state", state)],
        cookie,
    )
    .await
}

async fn bridge<S: AuthSchema>(
    auth: &Alibi<S>,
    forwarded: &AuthResponse,
    cookie: &str,
) -> AuthResponse {
    let url = url::Url::parse(forwarded.headers.get("location").unwrap()).unwrap();
    assert_eq!(url.path(), "/api/auth/callback/google/oauth-proxy");
    let query = url.query_pairs().into_owned().collect::<Vec<_>>();
    let pairs = query
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    get(auth, "/callback/google/oauth-proxy", &pairs, cookie).await
}

fn input() -> Value {
    json!({"provider":"google","callbackURL":format!("{ORIGIN}/dest"),"newUserCallbackURL":format!("{ORIGIN}/welcome"),"errorCallbackURL":format!("{ORIGIN}/failed")})
}

async fn proxy_forwards_and_completes_provider_flows<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let auth = social
        .auth_configured::<B>(
            &connection,
            config(|_| {}),
            |_| {},
            |builder| builder.plugin(proxy()),
            |store| store,
        )
        .await?;
    social.profile.set("proxy-sub", "proxy@example.com", true);

    let (state, cookie) = authorize(&auth, "/sign-in/social", input(), "").await;
    let forwarded = forward(&auth, &state, "grant", &cookie).await;
    trace.value("forwarded", outcome(&forwarded));
    let completed = bridge(&auth, &forwarded, &cookie).await;
    trace.value("registered", outcome(&completed));
    assert!(cookies(&completed).contains("session_token="));
    assert_eq!(db.count("users").await?, 1);

    let (state, cookie) = authorize(&auth, "/sign-in/social", input(), "").await;
    let forwarded = forward(&auth, &state, "grant", &cookie).await;
    let completed = bridge(&auth, &forwarded, &cookie).await;
    trace.value("returning", outcome(&completed));
    assert_eq!(db.count("users").await?, 1);

    let (state, cookie) = authorize(&auth, "/sign-in/social", input(), "").await;
    let mut posted = request(
        "/callback/google",
        Some(json!({"state": state, "code": "ignored", "extra": 5, "nothing": null})),
        &cookie,
    );
    posted.set_query_pairs([("code", "grant")]);
    let forwarded = Box::pin(auth.handle_request(posted)).await?;
    trace.value("body parameters", outcome(&forwarded));
    let completed = bridge(&auth, &forwarded, &cookie).await;
    trace.value("completed from body", outcome(&completed));

    let transport = request("/sign-in/social", Some(input()), "").with_url(url::Url::parse(
        &format!("{ORIGIN}/api/auth/sign-in/social"),
    )?);
    let inferred = social
        .auth_configured::<B>(
            &connection,
            config(|_| {}),
            |_| {},
            |builder| {
                builder.plugin(OAuthProxyPlugin::with_config(OAuthProxyConfig {
                    production_url: Some(PRODUCTION.into()),
                    ..Default::default()
                }))
            },
            |store| store,
        )
        .await?;
    let issued = Box::pin(inferred.handle_request(transport)).await?;
    let url = url::Url::parse(body(&issued)["url"].as_str().unwrap())?;
    trace.value(
        "inferred current origin",
        json!({
            "redirect_uri": url.query_pairs().find(|(key, _)| key == "redirect_uri").unwrap().1,
            "state_is_package": url.query_pairs().find(|(key, _)| key == "state").unwrap().1.len() > 100,
        }),
    );
    trace.assert("social/proxy-flows");
    B::close(connection).await
}

async fn proxy_error_destinations_and_pass_through<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let auth = social
        .auth_configured::<B>(
            &connection,
            config(|config| config.api_error_url = Some(format!("{ORIGIN}/configured-error"))),
            |_| {},
            |builder| builder.plugin(proxy()),
            |store| store,
        )
        .await?;
    social.profile.set("error-sub", "error@example.com", true);

    for garbage in [
        "not-hex",
        "00ff",
        "0000000000000000000000000000000000000000000000000000",
    ] {
        trace.response(
            &format!("undecryptable state {garbage}"),
            &forward(&auth, garbage, "grant", "").await,
        );
    }
    let mut anonymous = input();
    drop(
        anonymous
            .as_object_mut()
            .unwrap()
            .remove("errorCallbackURL"),
    );
    social.provider.respond(
        400,
        "application/json",
        json!({"error": "invalid_grant"}).to_string(),
    );
    let (state, cookie) = authorize(&auth, "/sign-in/social", anonymous.clone(), "").await;
    trace.value(
        "configured error page",
        outcome(&forward(&auth, &state, "wrong", &cookie).await),
    );
    trace.value(
        "provider error",
        outcome(
            &get(
                &auth,
                "/callback/google",
                &[("state", &state), ("error", "access_denied")],
                &cookie,
            )
            .await,
        ),
    );
    trace.value(
        "missing code",
        outcome(&get(&auth, "/callback/google", &[("state", &state)], &cookie).await),
    );
    let mut unknown = request("/callback/other", None, &cookie);
    unknown.set_query_pairs([("state", state.as_str()), ("code", "grant")]);
    trace.value(
        "other provider",
        outcome(&Box::pin(auth.handle_request(unknown)).await?),
    );

    let default_page = social
        .auth_configured::<B>(
            &connection,
            config(|_| {}),
            |_| {},
            |builder| builder.plugin(proxy()),
            |store| store,
        )
        .await?;
    let (state, cookie) = authorize(&default_page, "/sign-in/social", anonymous.clone(), "").await;
    trace.value(
        "default error page",
        outcome(&forward(&default_page, &state, "wrong", &cookie).await),
    );
    social.provider.respond(
        200,
        "application/json",
        json!({"access_token": "provider-access", "token_type": "Bearer"}).to_string(),
    );

    let rejecting = social
        .auth_configured::<B>(
            &connection,
            config(|_| {}),
            |provider| {
                provider.account_subject = Some(|_| Err("unusable subject".into()));
            },
            |builder| builder.plugin(proxy()),
            |store| store,
        )
        .await?;
    let (state, cookie) = authorize(&rejecting, "/sign-in/social", input(), "").await;
    trace.value(
        "unusable account key",
        outcome(&forward(&rejecting, &state, "grant", &cookie).await),
    );
    social.profile.set("blank-sub", "", true);
    let (state, cookie) = authorize(&auth, "/sign-in/social", input(), "").await;
    trace.value(
        "profile without email",
        outcome(&forward(&auth, &state, "grant", &cookie).await),
    );
    assert_eq!(db.count("users").await?, 0);
    trace.assert("social/proxy-errors");
    B::close(connection).await
}

async fn proxy_session_and_identity_failures<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let build = |provider: fn(&mut alibi::plugins::oauth::OAuthProvider),
                 refuse: Option<Refusal>| {
        let social = &social;
        let connection = &connection;
        async move {
            social
                .auth_configured::<B>(
                    connection,
                    config(|_| {}),
                    provider,
                    |builder| builder.plugin(proxy()),
                    |store| match refuse {
                        Some(refusal) => B::hook(store, Refuse(refusal)),
                        None => store,
                    },
                )
                .await
        }
    };
    let run = async |auth: &Alibi<B::Schema>| {
        let (state, cookie) = authorize(auth, "/sign-in/social", input(), "").await;
        let forwarded = forward(auth, &state, "grant", &cookie).await;
        bridge(auth, &forwarded, &cookie).await
    };

    let ordinary = build(|_| {}, None).await?;
    social.profile.set("deny-sub", "deny@example.com", true);
    trace.value("denied identity", outcome(&run(&ordinary).await));
    social.profile.set("closed-sub", "closed@example.com", true);
    let closed = build(|provider| provider.disable_sign_up = true, None).await?;
    trace.value("sign up disabled", outcome(&run(&closed).await));
    let implicit = build(|provider| provider.disable_implicit_sign_up = true, None).await?;
    trace.value("implicit sign up disabled", outcome(&run(&implicit).await));

    social
        .profile
        .set("session-sub", "session@example.com", true);
    for (label, refusal) in [
        ("session cancelled", Refusal::Cancel),
        ("session coded refusal", Refusal::Coded),
    ] {
        let auth = build(|_| {}, Some(refusal)).await?;
        trace.value(label, outcome(&run(&auth).await));
    }
    for (label, refusal) in [
        ("session forbidden", Refusal::Forbidden),
        ("session store failure", Refusal::Internal),
    ] {
        let auth = build(|_| {}, Some(refusal)).await?;
        trace.response(label, &run(&auth).await);
    }
    trace.assert("social/proxy-failures");
    B::close(connection).await
}
