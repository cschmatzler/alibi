//! Authorization URLs and token grants under each provider policy: what is
//! sent to the provider, and what is refused before anything is sent.
use super::social_flows::{Social, authorize, callback, linking};
use super::*;
use crate::snapshot::Trace;
use alibi::plugins::oauth::{OAuthProvider, OAuthTokenEndpointAuth};
use alibi::{AccountConfig, OAuthStateStrategy};

backend_tests!(
    authorization_urls_follow_the_provider_policy,
    authorization_configuration_failures_are_opaque,
    token_grants_follow_the_provider_policy,
    profile_requests_without_a_dedicated_handler,
    refresh_grants_follow_the_provider_policy,
    cookie_state_strategy_covers_linking_and_unknown_providers
);

fn policy(provider: &mut OAuthProvider) -> &mut alibi::plugins::oauth::OAuthAuthorizationPolicy {
    provider.authorization.as_mut().unwrap()
}

fn params(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).into(), (*value).into()))
        .collect()
}

async fn authorization_query<S: AuthSchema>(auth: &Alibi<S>, input: Value) -> Value {
    let response = call(auth, request("/sign-in/social", Some(input), ""), 200).await;
    let url = url::Url::parse(body(&response)["url"].as_str().unwrap()).unwrap();
    let query = url
        .query_pairs()
        .filter(|(key, _)| !matches!(&**key, "state" | "code_challenge"))
        .map(|(key, value)| json!([key, value]))
        .collect::<Vec<_>>();
    json!({"base": format!("{}://{}{}", url.scheme(), url.host_str().unwrap(), url.path()), "query": query, "fragment": url.fragment()})
}

async fn authorization_urls_follow_the_provider_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let cases: Vec<(&str, fn(&mut OAuthProvider), Value)> = vec![
        ("default", |_| {}, json!({})),
        (
            "response mode and prompt",
            |provider| {
                policy(provider).response_mode = Some("form_post".into());
                policy(provider).prompt = Some("consent".into());
            },
            json!({}),
        ),
        (
            "discord permissions without bot scope",
            |provider| policy(provider).discord_permissions = Some(8.0),
            json!({}),
        ),
        (
            "discord permissions integer",
            |provider| policy(provider).discord_permissions = Some(8.0),
            json!({"scopes":["bot"]}),
        ),
        (
            "discord permissions fraction",
            |provider| policy(provider).discord_permissions = Some(8.5),
            json!({"scopes":["bot"]}),
        ),
        (
            "discord permissions nan",
            |provider| policy(provider).discord_permissions = Some(f64::NAN),
            json!({"scopes":["bot"]}),
        ),
        (
            "discord permissions infinity",
            |provider| policy(provider).discord_permissions = Some(f64::INFINITY),
            json!({"scopes":["bot"]}),
        ),
        (
            "discord permissions negative infinity",
            |provider| policy(provider).discord_permissions = Some(f64::NEG_INFINITY),
            json!({"scopes":["bot"]}),
        ),
        (
            "login hint",
            |_| {},
            json!({"loginHint":"hint@example.test"}),
        ),
        (
            "login hint disabled",
            |provider| policy(provider).login_hint = false,
            json!({"loginHint":"hint@example.test"}),
        ),
        ("empty login hint", |_| {}, json!({"loginHint":""})),
        (
            "reserved provider parameters are ignored",
            |provider| {
                provider.authorization_params = vec![
                    ("state".into(), "forged".into()),
                    ("scope".into(), "forged".into()),
                    ("custom".into(), "kept".into()),
                ];
            },
            json!({}),
        ),
        (
            "additional parameters",
            |_| {},
            json!({"additionalParams":{"audience":"api","include_granted_scopes":"false"}}),
        ),
        (
            "client identifier parameter is not overridable",
            |provider| policy(provider).client_id_parameter = "appid".into(),
            json!({"additionalParams":{"appid":"forged","audience":"api"}}),
        ),
        (
            "existing endpoint parameters are replaced in place",
            |provider| {
                provider.auth_url =
                    "https://accounts.example/authorize?response_type=token&keep=1&response_type=again".into();
            },
            json!({}),
        ),
        (
            "callback path without a slash",
            |provider| policy(provider).callback_path = Some("custom/callback".into()),
            json!({}),
        ),
        (
            "callback path with a slash",
            |provider| policy(provider).callback_path = Some("/custom/callback".into()),
            json!({}),
        ),
        (
            "fixed parameters and fragment",
            |provider| {
                policy(provider).fixed_authorization_params = vec![("fixed".into(), "yes".into())];
                policy(provider).authorization_fragment = Some("provider_redirect".into());
            },
            json!({}),
        ),
    ];
    for (label, configure, input) in cases {
        let auth = social
            .auth::<B>(&connection, AccountConfig::default(), configure)
            .await?;
        let mut input = input;
        input["provider"] = json!("google");
        input["callbackURL"] = json!("/home");
        input["disableRedirect"] = json!(true);
        trace.value(label, authorization_query(&auth, input).await);
    }

    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |_| {})
        .await?;
    for key in [
        "state",
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    ] {
        let rejected = call(
            &auth,
            request(
                "/sign-in/social",
                Some(json!({"provider":"google","additionalParams":{key:"forged"}})),
                "",
            ),
            400,
        )
        .await;
        assert_eq!(body(&rejected)["code"], "VALIDATION_ERROR");
        assert!(
            body(&rejected)["message"]
                .as_str()
                .unwrap()
                .contains("cannot include reserved OAuth parameters")
        );
    }
    trace.assert("social/authorization-urls");
    B::close(connection).await
}

async fn authorization_configuration_failures_are_opaque<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    for (label, configure) in [
        (
            "missing secret",
            (|provider: &mut OAuthProvider| provider.client_secret.clear())
                as fn(&mut OAuthProvider),
        ),
        ("missing client", |provider| {
            provider.client_id.clear();
            policy(provider).require_client_id = true;
            policy(provider).require_client_secret = false;
        }),
    ] {
        let auth = social
            .auth::<B>(&connection, AccountConfig::default(), configure)
            .await?;
        let response = call(
            &auth,
            request("/sign-in/social", Some(json!({"provider":"google"})), ""),
            500,
        )
        .await;
        assert!(response.body.is_empty(), "{label}");
        let owner =
            cookies(&signup(&auth, &format!("{}@example.test", label.replace(' ', "-"))).await);
        let response = call(
            &auth,
            request("/link-social", Some(json!({"provider":"google"})), &owner),
            500,
        )
        .await;
        assert!(response.body.is_empty(), "{label}");
    }
    B::close(connection).await
}

async fn token_grants_follow_the_provider_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    let assertion = |provider: &mut OAuthProvider| {
        policy(provider).require_client_secret = false;
        policy(provider).authorization_code_params = params(&[
            ("client_assertion", "signed-assertion"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
        ]);
    };
    let cases: Vec<(&str, Box<dyn Fn(&mut OAuthProvider)>, Value)> = vec![
        ("default", Box::new(|_| {}), json!({})),
        (
            "assertion needs its type",
            Box::new(|provider| {
                policy(provider).authorization_code_params =
                    params(&[("client_assertion", "signed-assertion")]);
            }),
            json!({}),
        ),
        (
            "assertion cannot follow endpoint authentication",
            Box::new(move |provider| {
                assertion(provider);
                policy(provider).token_endpoint_auth =
                    Some(OAuthTokenEndpointAuth::ClientSecretPost);
            }),
            json!({}),
        ),
        (
            "assertion cannot accompany a secret",
            Box::new(move |provider| {
                assertion(provider);
            }),
            json!({}),
        ),
        (
            "assertion without secret",
            Box::new(move |provider| {
                assertion(provider);
                provider.client_secret.clear();
            }),
            json!({}),
        ),
        (
            "public client cannot hold a secret",
            Box::new(|provider| {
                policy(provider).token_endpoint_auth = Some(OAuthTokenEndpointAuth::None);
            }),
            json!({}),
        ),
        (
            "public client",
            Box::new(|provider| {
                provider.client_secret.clear();
                policy(provider).require_client_secret = false;
                policy(provider).token_endpoint_auth = Some(OAuthTokenEndpointAuth::None);
            }),
            json!({}),
        ),
        (
            "private key needs no secret",
            Box::new(|provider| {
                policy(provider).token_endpoint_auth = Some(OAuthTokenEndpointAuth::PrivateKeyJwt);
            }),
            json!({}),
        ),
        (
            "post needs a secret",
            Box::new(|provider| {
                provider.client_secret.clear();
                policy(provider).require_client_secret = false;
                policy(provider).token_endpoint_auth =
                    Some(OAuthTokenEndpointAuth::ClientSecretPost);
            }),
            json!({}),
        ),
        (
            "basic cannot repeat the secret",
            Box::new(|provider| {
                policy(provider).token_endpoint_auth =
                    Some(OAuthTokenEndpointAuth::ClientSecretBasic);
                policy(provider).authorization_code_params = params(&[("client_secret", "repeat")]);
            }),
            json!({}),
        ),
        (
            "basic",
            Box::new(|provider| {
                policy(provider).token_endpoint_auth =
                    Some(OAuthTokenEndpointAuth::ClientSecretBasic);
            }),
            json!({}),
        ),
        (
            "client key",
            Box::new(|provider| {
                policy(provider).authorization_code_client_key = Some("application-key".into());
                policy(provider).token_endpoint_auth = Some(OAuthTokenEndpointAuth::ClientKeyPost);
            }),
            json!({}),
        ),
        (
            "default expiry",
            Box::new(|provider| {
                policy(provider).default_access_token_expires_in = Some(3600.0);
            }),
            json!({}),
        ),
        (
            "unrepresentable default expiry",
            Box::new(|provider| {
                policy(provider).default_access_token_expires_in = Some(1e300);
            }),
            json!({}),
        ),
        (
            "array scope",
            Box::new(|_| {}),
            json!({"scope":[" first ", "second", 3, ""]}),
        ),
    ];
    for (index, (label, configure, extra)) in cases.into_iter().enumerate() {
        let social = Social::start().await;
        let mut grant = json!({"access_token":"grant-access","token_type":"Bearer"});
        for (key, value) in extra.as_object().unwrap() {
            grant[key] = value.clone();
        }
        social
            .provider
            .respond(200, "application/json", grant.to_string());
        social.profile.set(
            &format!("grant-sub-{index}"),
            &format!("grant-{index}@example.test"),
            true,
        );
        let auth = social
            .auth::<B>(&connection, AccountConfig::default(), |provider| {
                configure(provider);
            })
            .await?;
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home","errorCallbackURL":"/oops"}),
            "",
        )
        .await;
        let response = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
        trace.response(label, &response);
        let sent = social.provider.take();
        trace.value(
            &format!("{label}: token request"),
            json!(sent.first().map(|exchange| {
                let mut form = url::form_urlencoded::parse(&exchange.body)
                    .into_owned()
                    .filter(|(key, _)| key != "code_verifier")
                    .collect::<Vec<_>>();
                form.sort();
                json!({"form": form, "basic": exchange.headers.contains_key("authorization")})
            })),
        );
        let account = db
            .text(
                "SELECT scope FROM accounts WHERE account_id = $1",
                &[&format!("grant-sub-{index}")],
            )
            .await?;
        let expiring = db
            .count_where(
                "SELECT COUNT(*) FROM accounts WHERE account_id = $1 AND access_token_expires_at IS NOT NULL",
                &[&format!("grant-sub-{index}")],
            )
            .await?;
        trace.value(
            &format!("{label}: account"),
            json!({"scope": account, "expiring": expiring}),
        );
    }
    trace.assert("social/token-grants");
    B::close(connection).await
}

async fn profile_requests_without_a_dedicated_handler<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mut trace = Trace::default();
    for (label, status, profile) in [
        (
            "profile",
            200,
            json!({"sub":"plain-sub","email":"plain@example.test","email_verified":true,"name":"Plain"}),
        ),
        ("provider failure", 500, json!({"error":"unavailable"})),
        (
            "unmappable profile",
            200,
            json!({"email":"nosub@example.test"}),
        ),
    ] {
        let social = Social::start().await;
        social.provider.respond(
            200,
            "application/json",
            json!({"access_token":"plain-access","token_type":"Bearer"}).to_string(),
        );
        social.provider.respond_at("/userinfo", status, profile);
        let auth = social
            .auth::<B>(&connection, AccountConfig::default(), |provider| {
                provider.get_user_info = None;
                provider.verify_id_token = None;
                provider.user_info_url = Some(social.provider.url.join("userinfo").unwrap().into());
            })
            .await?;
        let (state, cookie) = authorize(
            &auth,
            "/sign-in/social",
            json!({"provider":"google","callbackURL":"/home","errorCallbackURL":"/oops"}),
            "",
        )
        .await;
        trace.response(
            label,
            &callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await,
        );
        trace.value(
            &format!("{label}: requests"),
            json!(
                social
                    .provider
                    .take()
                    .iter()
                    .map(|exchange| format!(
                        "{} {} {}",
                        exchange.method,
                        exchange.path,
                        exchange
                            .headers
                            .get("authorization")
                            .map_or("", |value| value.to_str().unwrap())
                    ))
                    .collect::<Vec<_>>()
            ),
        );
    }
    trace.assert("social/profile-without-handler");
    B::close(connection).await
}

async fn refresh_grants_follow_the_provider_policy<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"first-access","refresh_token":"first-refresh","token_type":"Bearer","expires_in":3600}).to_string(),
    );
    let auth = social
        .auth::<B>(&connection, AccountConfig::default(), |provider| {
            provider.client_secret.clear();
            policy(provider).require_client_secret = false;
            policy(provider).refresh_token_params = params(&[("audience", "refresh-audience")]);
        })
        .await?;
    let (state, cookie) = authorize(
        &auth,
        "/sign-in/social",
        json!({"provider":"google","callbackURL":"/home"}),
        "",
    )
    .await;
    let signed_in = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
    assert_eq!(signed_in.status, 302);
    let session = super::cookies(&signed_in);
    drop(social.provider.take());
    let account = db.text("SELECT id FROM accounts", &[]).await?.unwrap();

    social.provider.respond(
        400,
        "application/json",
        json!({"error":"invalid_grant"}).to_string(),
    );
    let failed = call(
        &auth,
        request(
            "/refresh-token",
            Some(json!({"accountId":account})),
            &session,
        ),
        400,
    )
    .await;
    assert_eq!(
        body(&failed)["code"],
        "FAILED_TO_REFRESH_ACCESS_TOKEN",
        "{}",
        body(&failed)
    );
    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"second-access","token_type":"Bearer"}).to_string(),
    );
    let refreshed = call(
        &auth,
        request(
            "/refresh-token",
            Some(json!({"accountId":account})),
            &session,
        ),
        200,
    )
    .await;
    assert_eq!(body(&refreshed)["accessToken"], "second-access");
    let sent = social.provider.take();
    assert_eq!(sent.len(), 2);
    for exchange in &sent {
        let form: std::collections::HashMap<_, _> = url::form_urlencoded::parse(&exchange.body)
            .into_owned()
            .collect();
        assert_eq!(form["grant_type"], "refresh_token");
        assert_eq!(form["refresh_token"], "first-refresh");
        assert_eq!(form["audience"], "refresh-audience");
        assert_eq!(form["client_id"], "google-client");
        assert!(!form.contains_key("client_secret"));
    }
    B::close(connection).await
}

async fn cookie_state_strategy_covers_linking_and_unknown_providers<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut account = linking(|_| {});
    account.store_state_strategy = OAuthStateStrategy::Cookie;
    let auth = social.auth::<B>(&connection, account, |_| {}).await?;
    let owner = cookies(&signup(&auth, "social@example.com").await);
    let (state, cookie) = authorize(
        &auth,
        "/link-social",
        json!({"provider":"google","callbackURL":"/settings"}),
        &owner,
    )
    .await;
    assert_eq!(db.count("verifications").await?, 0);
    let mut unknown = request("/callback/unknown", None, &cookie);
    unknown.set_query_pairs([("code", "grant"), ("state", state.as_str())]);
    let response = Box::pin(auth.handle_request(unknown)).await?;
    assert_eq!(response.status, 302);
    assert!(
        response
            .headers
            .get("location")
            .unwrap()
            .contains("error=oauth_provider_not_found"),
        "{:?}",
        response.headers
    );
    let linked = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
    assert_eq!(linked.status, 302);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM accounts WHERE provider_id = $1",
            &["google"]
        )
        .await?,
        1
    );
    B::close(connection).await
}
