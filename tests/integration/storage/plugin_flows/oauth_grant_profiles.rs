//! Profiles decoded from grant ID tokens: malformed tokens and non-string
//! emails fail the way the published factory fails, not like ordinary errors.
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::oauth::OAuthProvider;
use alibi::plugins::{AccountManagementPlugin, OAuthPlugin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

backend_tests!(
    grant_id_token_profiles_fail_like_the_published_factory,
    encrypted_token_storage_rejects_non_string_grant_tokens
);

fn unsigned(claims: &Value) -> String {
    format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
}

fn claims(sub: &str, email: Value) -> Value {
    json!({"sub": sub, "email": email, "name": "Paybin User", "email_verified": true})
}

async fn grant_id_token_profiles_fail_like_the_published_factory<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    let mut provider = OAuthProvider::paybin("native-client", Some("native-secret"));
    provider.token_url = remote.url.join("token")?.into();
    let auth = builder::<B>(&connection)
        .plugin(AccountManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("paybin", provider))
        .build()
        .await?;
    let mut trace = Trace::default();
    let grant = |id_token: Option<Value>| {
        let mut grant = json!({"access_token": "paybin-access", "token_type": "Bearer"});
        if let Some(token) = id_token {
            grant["id_token"] = token;
        }
        remote.respond_at("/token", 200, grant);
    };
    let sign_in = async |cookie: &str, link: bool| {
        let started = call(
            &auth,
            request(
                if link { "/link-social" } else { "/sign-in/social" },
                Some(json!({"provider":"paybin","callbackURL":"/home","errorCallbackURL":"/oops","disableRedirect":true})),
                cookie,
            ),
            200,
        )
        .await;
        let url = url::Url::parse(body(&started)["url"].as_str().unwrap()).unwrap();
        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let jar = [cookie.to_owned(), cookies(&started)]
            .into_iter()
            .filter(|cookie| !cookie.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
        let mut callback = request("/callback/paybin", None, &jar);
        callback.set_query_pairs([("code", "grant"), ("state", state.as_str())]);
        Box::pin(auth.handle_request(callback)).await.unwrap()
    };

    grant(Some(json!(unsigned(&claims(
        "pb-1",
        json!("pb1@example.test")
    )))));
    trace.response("registered", &sign_in("", false).await);
    for (label, id_token) in [
        ("undecodable token", Some(json!("garbage"))),
        ("non-string token", Some(json!(5))),
        ("missing token", None),
        ("falsy token", Some(json!(""))),
    ] {
        grant(id_token);
        trace.response(label, &sign_in("", false).await);
    }
    for (label, email) in [
        ("numeric email, existing account", json!(123)),
        ("boolean email, existing account", json!(true)),
        ("null email, existing account", Value::Null),
        ("false email, existing account", json!(false)),
    ] {
        grant(Some(json!(unsigned(&claims("pb-1", email)))));
        trace.response(label, &sign_in("", false).await);
    }
    grant(Some(json!(unsigned(&claims("pb-new", json!(123))))));
    trace.response("numeric email, new identity", &sign_in("", false).await);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM accounts WHERE provider_id = $1",
            &["paybin"]
        )
        .await?,
        1
    );

    let owner = cookies(&signup(&auth, "owner@example.test").await);
    grant(Some(json!(unsigned(&claims("pb-link", json!(123))))));
    trace.response("numeric email, link", &sign_in(&owner, true).await);
    grant(Some(json!(unsigned(&claims("pb-link", Value::Null)))));
    trace.response("null email, link", &sign_in(&owner, true).await);
    grant(Some(json!(unsigned(&claims(
        "pb-link",
        json!("owner@example.test")
    )))));
    trace.response("matching email, link", &sign_in(&owner, true).await);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM accounts WHERE provider_id = $1",
            &["paybin"]
        )
        .await?,
        2
    );
    trace.assert("social/grant-id-token-profiles");
    B::close(connection).await
}

async fn encrypted_token_storage_rejects_non_string_grant_tokens<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    let mut provider = OAuthProvider::paybin("native-client", Some("native-secret"));
    provider.token_url = remote.url.join("token")?.into();
    let mut config = AuthConfig::new(SECRET).base_url(ORIGIN);
    config.account.encrypt_oauth_tokens = true;
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("paybin", provider))
        .build()
        .await?;
    let id_token = unsigned(&claims("pb-enc", json!("enc@example.test")));
    let mut outcomes = Vec::new();
    for access in [json!(5), json!("paybin-access")] {
        remote.respond_at(
            "/token",
            200,
            json!({"access_token": access, "refresh_token": "paybin-refresh", "id_token": id_token}),
        );
        let started = call(
            &auth,
            request(
                "/sign-in/social",
                Some(json!({"provider":"paybin","callbackURL":"/home","errorCallbackURL":"/oops","disableRedirect":true})),
                "",
            ),
            200,
        )
        .await;
        let url = url::Url::parse(body(&started)["url"].as_str().unwrap())?;
        let state = url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let mut callback = request("/callback/paybin", None, &cookies(&started));
        callback.set_query_pairs([("code", "grant"), ("state", state.as_str())]);
        let response = Box::pin(auth.handle_request(callback)).await?;
        outcomes.push(response.headers.get("location").cloned());
    }
    assert_eq!(
        outcomes,
        [
            Some("http://localhost:43219/oops?error=Internal_server_error%3A_Provider_token_encryption_requires_a_string".into()),
            Some("/home".into())
        ]
    );
    let stored = db
        .text("SELECT access_token FROM accounts", &[])
        .await?
        .unwrap();
    assert_ne!(stored, "paybin-access");
    assert!(!stored.is_empty());
    B::close(connection).await
}
