//! Discovery, signed grants, client authentication, trusted account operations
//! and RP logout, through the public native boundaries and a recording peer.
use super::*;
use alibi::AuthAccount;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::{
    GenericOAuthConfig, OAuthAccountApi, OAuthAccountSelection, OAuthPrivateKeyJwtOptions,
    OAuthTokenEndpointAuth,
};
use std::collections::{HashMap, HashSet};

backend_tests!(
    oidc_discovery_signed_grants_assertions_refresh_and_logout,
    discovered_callback_issuer_rejects_mixup_before_grant_exchange
);
postgres_tests!(oidc_discovery_signed_grants_assertions_refresh_and_logout);

async fn oidc_discovery_signed_grants_assertions_refresh_and_logout<B: Backend>(
    db: Db,
) -> TestResult {
    let remote = Provider::start("application/json", "{}").await;
    let issuer = remote.url.as_str();
    let token_url = remote.url.join("token")?.to_string();
    let keys: Value = serde_json::from_str(include_str!("../../../fixtures/one-tap/jwks.json"))?;
    remote.respond_at("/discovery", 200, json!({"issuer":issuer,"authorization_endpoint":remote.url.join("authorize")?,"token_endpoint":token_url,"userinfo_endpoint":remote.url.join("profile")?,"jwks_uri":"keys","id_token_signing_alg_values_supported":["RS256"],"end_session_endpoint":remote.url.join("logout?keep=yes&client_id=old&client_id=duplicate&state=old&state=duplicate&id_token_hint=old&id_token_hint=duplicate&post_logout_redirect_uri=old&post_logout_redirect_uri=duplicate")?}));
    remote.respond_at("/keys", 200, keys.clone());
    let mut config = GenericOAuthConfig::new("native-client", "");
    config.discovery_url = Some(remote.url.join("discovery")?.into());
    config.discovery_headers = vec![("x-discovery-key".into(), "operator-owned".into())];
    config.require_id_token_verification = true;
    let policy = config.provider.authorization.as_mut().unwrap();
    policy.token_endpoint_auth = Some(OAuthTokenEndpointAuth::PrivateKeyJwt);
    policy.client_assertion = Some(
        OAuthPrivateKeyJwtOptions {
            private_key_pem: Some(include_str!("../../../fixtures/one-tap/private-key.pem").into()),
            algorithm: Some("RS256".into()),
            kid: Some("client-key".into()),
            ..Default::default()
        }
        .into_assertion()?,
    );
    let resolved = config
        .resolve()
        .await?
        .ok_or("OIDC discovery did not resolve")?;
    let discovery = remote.take();
    assert_eq!(discovery.len(), 1);
    assert_eq!(discovery[0].path, "/discovery");
    assert_eq!(discovery[0].headers["x-discovery-key"], "operator-owned");
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let account_events = Arc::new(Mutex::new(Vec::new()));
    let auth = builder::<B>(&connection)
        .endpoint_hook(AccessOperationHook(account_events.clone()))
        .plugin(OAuthPlugin::new().add_provider("oidc", resolved.provider))
        .build()
        .await?;
    let mut accepted = None;
    let mut delivered_id_token = String::new();
    let mut assertion_ids = HashSet::new();
    for control in [
        "signature",
        "issuer",
        "audience",
        "nonce",
        "expired",
        "future",
        "key-use",
        "key-ops",
        "duplicate-ops",
        "private-key",
        "key-alg",
        "duplicate-key",
        "missing-key",
        "valid",
    ] {
        let mut document = keys.clone();
        match control {
            "key-use" => document["keys"][0]["use"] = json!("enc"),
            "key-ops" => document["keys"][0]["key_ops"] = json!(["sign"]),
            "duplicate-ops" => document["keys"][0]["key_ops"] = json!(["verify", "verify"]),
            "private-key" => document["keys"][0]["d"] = json!("AQAB"),
            "key-alg" => document["keys"][0]["alg"] = json!("RS512"),
            "duplicate-key" => document["keys"]
                .as_array_mut()
                .unwrap()
                .push(keys["keys"][0].clone()),
            "missing-key" => document["keys"][0]["kid"] = json!("foreign-key"),
            _ => {}
        }
        remote.respond_at("/keys", 200, document);
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "oidc").await;
        assert!(
            authorization["scope"]
                .split(' ')
                .any(|scope| scope == "openid")
        );
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({"iss":issuer,"aud":"native-client","sub":"oidc-subject","email":"oidc@example.test","email_verified":true,"name":"OIDC User","iat":now,"exp":now+300,"nonce":authorization["nonce"]});
        match control {
            "issuer" => claims["iss"] = json!("https://wrong-issuer.example.test"),
            "audience" => claims["aud"] = json!("wrong-client"),
            "nonce" => claims["nonce"] = json!("wrong-nonce"),
            // ID tokens allow 30 seconds of clock skew on `exp`.
            "expired" => claims["exp"] = json!(now - 60),
            "future" => claims["nbf"] = json!(now + 3600),
            _ => {}
        }
        let id_token =
            super::oauth_signed::token(&claims, control == "signature", "one-tap-local-rs256")?;
        remote.respond_at("/token", 200, json!({"access_token":"initial-access","refresh_token":"initial-refresh","id_token":id_token,"token_type":"Bearer","expires_in":3600}));
        let response =
            super::oauth_profiles::complete(&auth, "oidc", &authorization, &cookie).await;
        let target = url::Url::parse(response.headers.get("location").unwrap())?;
        let exchanges = remote.take();
        let grant = exchanges
            .iter()
            .find(|exchange| exchange.path == "/token")
            .unwrap();
        verify_assertion(
            grant,
            &keys,
            &token_url,
            "authorization_code",
            &mut assertion_ids,
        )?;
        assert!(
            exchanges.iter().all(|exchange| exchange.path != "/profile"),
            "signed profile must not be replaced by unsigned userinfo"
        );
        if control == "valid" {
            assert_eq!(target.path(), "/done");
            authenticated(&auth, &cookies(&response), "oidc@example.test").await;
            delivered_id_token = id_token;
            accepted = Some(response);
        } else {
            assert_eq!(target.path(), "/failed", "{control}");
            assert!(target.query_pairs().any(|(key, _)| key == "error"));
            assert!(!cookies(&response).contains("session_token="));
            for table in ["user", "account", "session"] {
                assert_eq!(db.count(table).await?, 0, "{control}/{table}");
            }
        }
    }
    let accepted = accepted.unwrap();
    let session = call(
        &auth,
        request("/get-session", None, &cookies(&accepted)),
        200,
    )
    .await;
    let owner = body(&session)["user"]["id"].as_str().unwrap().to_owned();
    let account = db
        .text(
            "SELECT id FROM \"account\" WHERE \"providerId\" = 'oidc' AND \"accountId\" = 'oidc-subject'",
            &[],
        )
        .await?
        .unwrap();
    let select = || OAuthAccountSelection::Id(account.clone());
    let access = Box::pin(auth.dispatch_endpoint(
        OAuthPlugin::get_access_token_endpoint(
            OAuthAccountSelection::Id(account.clone()),
            Some(&owner),
        ),
        alibi::endpoint::EndpointOptions::default(),
    ))
    .await?;
    assert_eq!(
        access.decode()?.access_token.as_deref(),
        Some("initial-access")
    );
    let persisted = auth
        .context()
        .database
        .get_user_accounts_record(&owner)
        .await?;
    let expiry = persisted
        .iter()
        .find(|row| row.id().as_ref() == account)
        .unwrap()
        .access_token_expires_at()
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(
        access.decode()?.access_token_expires_at.as_deref(),
        Some(expiry.as_str())
    );

    assert_eq!(
        access
            .headers()
            .get_all("set-cookie")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "application_a=first; Path=/; HttpOnly",
            "application_b=second; Path=/; HttpOnly"
        ]
    );
    assert_eq!(*account_events.lock().unwrap(), ["before", "after"]);

    assert!(remote.take().is_empty());
    let outsider = signup(&auth, "outsider@example.test").await;
    let outsider_id = body(&outsider)["user"]["id"].as_str().unwrap().to_owned();
    let accounts = db.table("account").await?;
    assert!(
        OAuthAccountApi::get_access_token(&outsider_id, select(), auth.context())
            .await
            .is_err()
    );
    assert!(
        OAuthAccountApi::refresh_token(&outsider_id, select(), auth.context())
            .await
            .is_err()
    );
    assert!(
        OAuthAccountApi::account_info(&outsider_id, select(), auth.context())
            .await
            .is_err()
    );
    assert!(remote.take().is_empty());
    assert_eq!(db.table("account").await?, accounts);
    for options in [
        alibi::endpoint::EndpointOptions {
            headers: Some(std::collections::HashMap::new()),
            ..Default::default()
        },
        alibi::endpoint::EndpointOptions {
            request: Some(request("/incoming-request", None, "")),
            ..Default::default()
        },
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            access_endpoint(&json!({"accountId":account,"userId":owner}))?,
            options,
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), 401);
        assert!(denied.body_absent);
        assert_eq!(db.table("account").await?, accounts);
        assert!(remote.take().is_empty());
    }
    let wrong = Box::pin(
        auth.dispatch_endpoint(
            access_endpoint(&json!({"accountId":account,"userId":owner}))?,
            alibi::endpoint::EndpointOptions {
                headers: Some(
                    [("cookie".into(), cookies(&outsider))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(wrong.error.status_code(), 400);
    assert_eq!(db.table("account").await?, accounts);
    assert!(remote.take().is_empty());
    let selected = Box::pin(
        auth.dispatch_endpoint(
            access_endpoint(&json!({"accountId":account,"userId":outsider_id}))?,
            alibi::endpoint::EndpointOptions {
                headers: Some(
                    [("cookie".into(), cookies(&accepted))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await?;
    assert_eq!(selected.decode()?["accessToken"], "initial-access");
    let malformed = Box::pin(auth.dispatch_endpoint(
        access_endpoint(&json!({"accountId":5,"userId":owner}))?,
        alibi::endpoint::EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(malformed.error.status_code(), 400);
    assert_eq!(db.table("account").await?, accounts);
    assert!(remote.take().is_empty());
    // HTTP selectors must not turn a body/query userId into trusted authority.
    for (route, method) in [
        ("/account-info", HttpMethod::Get),
        ("/get-access-token", HttpMethod::Post),
        ("/refresh-token", HttpMethod::Post),
    ] {
        let mut denied = request(
            route,
            if method == HttpMethod::Post {
                Some(json!({"accountId":account,"userId":owner}))
            } else {
                None
            },
            &cookies(&outsider),
        );
        if method == HttpMethod::Get {
            denied.query.extend([
                ("accountId".into(), account.clone()),
                ("userId".into(), owner.clone()),
            ]);
        }
        let _ = call(&auth, denied, 400).await;
        assert!(remote.take().is_empty());
        assert_eq!(db.table("account").await?, accounts);
    }
    let mut public_profile = request("/account-info", None, &cookies(&accepted));
    drop(
        public_profile
            .query
            .insert("accountId".into(), account.clone()),
    );
    let public_profile = call(&auth, public_profile, 200).await;
    assert_eq!(body(&public_profile)["account"]["id"], account);
    assert_eq!(
        body(&public_profile)["account"]["accountId"],
        "oidc-subject"
    );
    assert_eq!(body(&public_profile)["user"]["email"], "oidc@example.test");
    assert_eq!(db.table("account").await?, accounts);
    drop(remote.take());

    Box::pin(refresh_owned_grant(
        &auth,
        &db,
        &remote,
        (&owner, &account, &delivered_id_token),
        &outsider,
        &account_events,
    ))
    .await?;
    let exchanges = remote.take();
    let grant = exchanges
        .iter()
        .find(|exchange| exchange.path == "/token")
        .unwrap();
    verify_assertion(
        grant,
        &keys,
        &token_url,
        "refresh_token",
        &mut assertion_ids,
    )?;
    let form: HashMap<String, String> = url::form_urlencoded::parse(&grant.body)
        .into_owned()
        .collect();
    assert_eq!(form["refresh_token"], "initial-refresh");
    let profile = OAuthAccountApi::account_info(&owner, select(), auth.context()).await?;
    assert_eq!(profile.account.account_id, "oidc-subject");
    assert_eq!(profile.user["email"], "oidc@example.test");
    let logout = call(
        &auth,
        request(
            "/sign-out",
            Some(
                json!({"callbackURL":"/signed-out","state":"caller-state","disableRedirect":true}),
            ),
            &cookies(&accepted),
        ),
        200,
    )
    .await;
    assert_eq!(body(&logout)["success"], true);
    assert_eq!(body(&logout)["redirect"], false);
    assert!(logout.headers.get("location").is_none());
    let destination = url::Url::parse(body(&logout)["url"].as_str().unwrap())?;
    assert_eq!(destination.path(), "/logout");
    for reserved in [
        "id_token_hint",
        "post_logout_redirect_uri",
        "client_id",
        "state",
    ] {
        assert_eq!(
            destination
                .query_pairs()
                .filter(|(key, _)| key == reserved)
                .count(),
            1,
            "duplicate logout parameter: {reserved}"
        );
    }
    let params: HashMap<String, String> = destination.query_pairs().into_owned().collect();
    assert_eq!(params["id_token_hint"], delivered_id_token);
    assert_eq!(
        params["post_logout_redirect_uri"],
        format!("{ORIGIN}/signed-out")
    );
    assert_eq!(params["client_id"], "native-client");
    assert_eq!(params["state"], "caller-state");
    assert_eq!(params["keep"], "yes");
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM \"session\" WHERE \"userId\"=$1",
            &[&owner]
        )
        .await?,
        0
    );
    authenticated(&auth, &cookies(&outsider), "outsider@example.test").await;
    let anonymous_logout = call(
        &auth,
        request(
            "/sign-out",
            Some(json!({"accountId":account,"userId":owner})),
            "",
        ),
        200,
    )
    .await;
    assert!(
        body(&anonymous_logout).get("url").is_none(),
        "untrusted account selector must not disclose an ID-token hint"
    );
    // The advertised algorithm set is captured at discovery resolution. A
    // matching RSA key alone cannot authorize an unadvertised signature type.
    for advertised in ["RS256", "RS512"] {
        remote.respond_at("/discovery", 200, json!({"issuer":issuer,"authorization_endpoint":remote.url.join("authorize")?,"token_endpoint":token_url,"jwks_uri":"keys","id_token_signing_alg_values_supported":[advertised]}));
        let mut config = GenericOAuthConfig::new("native-client", "native-secret");
        config.discovery_url = Some(remote.url.join("discovery")?.into());
        config.require_id_token_verification = true;
        let provider = config.resolve().await?.unwrap().provider;
        let scoped = builder::<B>(&connection)
            .plugin(OAuthPlugin::new().add_provider("algorithm", provider))
            .build()
            .await?;
        let (authorization, cookie) = super::oauth_profiles::begin(&scoped, "algorithm").await;
        let now = chrono::Utc::now().timestamp();
        let claims = json!({"iss":issuer,"aud":"native-client","sub":"algorithm-subject","email":"algorithm@example.test","name":"Algorithm User","iat":now,"exp":now+300,"nonce":authorization["nonce"]});
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS512);
        header.kid = Some("one-tap-local-rs256".into());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
                "../../../fixtures/one-tap/private-key.pem"
            ))?,
        )?;
        let mut document = keys.clone();
        document["keys"][0]["alg"] = json!("RS512");
        remote.respond_at("/keys", 200, document);
        remote.respond_at(
            "/token",
            200,
            json!({"access_token":"algorithm-access","id_token":token,"expires_in":3600}),
        );
        let before = db.tables(&["user", "account", "session"]).await?;
        let response =
            super::oauth_profiles::complete(&scoped, "algorithm", &authorization, &cookie).await;
        assert_eq!(
            url::Url::parse(response.headers.get("location").unwrap())?.path(),
            if advertised == "RS512" {
                "/done"
            } else {
                "/failed"
            }
        );
        if advertised == "RS512" {
            authenticated(&scoped, &cookies(&response), "algorithm@example.test").await;
            assert_eq!(
                db.count_where(
                    "SELECT COUNT(*) FROM \"account\" WHERE \"providerId\"=$1 AND \"accountId\"=$2",
                    &["algorithm", "algorithm-subject"]
                )
                .await?,
                1
            );
        } else {
            assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
            assert!(!cookies(&response).contains("session_token="));
        }
    }
    B::close(connection).await
}

fn verify_assertion(
    exchange: &Exchange,
    keys: &Value,
    endpoint: &str,
    grant: &str,
    seen: &mut HashSet<String>,
) -> TestResult {
    assert_eq!(exchange.method, "POST");
    assert!(exchange.headers.get("authorization").is_none());
    let form: HashMap<String, String> = url::form_urlencoded::parse(&exchange.body)
        .into_owned()
        .collect();
    assert_eq!(form["grant_type"], grant);
    assert_eq!(form["client_id"], "native-client");
    assert!(!form.contains_key("client_secret"));
    assert_eq!(
        form["client_assertion_type"],
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    let token = &form["client_assertion"];
    assert_eq!(
        jsonwebtoken::decode_header(token)?.kid.as_deref(),
        Some("client-key")
    );
    let jwk = serde_json::from_value(keys["keys"][0].clone())?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[endpoint]);
    validation.set_issuer(&["native-client"]);
    validation.sub = Some("native-client".into());
    let claims = jsonwebtoken::decode::<Value>(
        token,
        &jsonwebtoken::DecodingKey::from_jwk(&jwk)?,
        &validation,
    )?
    .claims;
    assert_eq!(
        claims["exp"].as_f64().unwrap() - claims["iat"].as_f64().unwrap(),
        120.0
    );
    assert!(
        seen.insert(claims["jti"].as_str().unwrap().to_owned()),
        "every delivered grant requires a fresh assertion"
    );
    Ok(())
}

async fn discovered_callback_issuer_rejects_mixup_before_grant_exchange<B: Backend>(
    db: Db,
) -> TestResult {
    let remote = Provider::start("application/json", "{}").await;
    let issuer = remote.url.as_str();
    let keys: Value = serde_json::from_str(include_str!("../../../fixtures/one-tap/jwks.json"))?;
    remote.respond_at(
        "/discovery",
        200,
        json!({
            "issuer":issuer,
            "authorization_endpoint":remote.url.join("authorize")?,
            "token_endpoint":remote.url.join("token")?,
            "userinfo_endpoint":remote.url.join("profile")?,
            "jwks_uri":remote.url.join("keys")?,
            "id_token_signing_alg_values_supported":["RS256"]
        }),
    );
    remote.respond_at("/keys", 200, keys);
    let mut provider = GenericOAuthConfig::new("mixup-client", "mixup-secret");
    provider.discovery_url = Some(remote.url.join("discovery")?.into());
    provider.require_id_token_verification = true;
    let resolved = provider.resolve().await?.ok_or("discovery failed")?;
    _ = remote.take();
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET).base_url(ORIGIN);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(super::auth_probe::fast_password())
        .plugin(SessionManagementPlugin::new())
        .plugin(OAuthPlugin::new().add_provider("oidc", resolved.provider))
        .build()
        .await?;
    let foreign = signup(&auth, "mixup-foreign@example.test").await;
    let before = db.tables(&["user", "account", "session"]).await?;
    let foreign_rows = [
        ("user", db.table("user").await?),
        ("account", db.table("account").await?),
        ("session", db.table("session").await?),
    ];
    for stage in ["wrong issuer", "matching issuer"] {
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "oidc").await;
        let now = chrono::Utc::now().timestamp();
        let claims = json!({"iss":issuer,"aud":"mixup-client","sub":"mixup-owner-sub","email":"mixup-owner@example.test","email_verified":true,"name":"Mixup Owner","iat":now,"exp":now+300,"nonce":authorization["nonce"]});
        let token = super::oauth_signed::token(&claims, false, "one-tap-local-rs256")?;
        remote.respond_at("/token", 200, json!({"access_token":"mixup-access","refresh_token":"mixup-refresh","id_token":token,"token_type":"Bearer","expires_in":3600}));
        let mut input = request("/callback/oidc", None, &cookie);
        input.set_query_pairs([
            ("state", authorization["state"].as_str()),
            ("code", "mixup-valid-grant"),
            (
                "iss",
                if stage == "wrong issuer" {
                    "https://attacker.example.invalid"
                } else {
                    issuer
                },
            ),
        ]);
        let completed = call(&auth, input, 302).await;
        let location = url::Url::parse(completed.headers.get("location").unwrap())?;
        if stage == "wrong issuer" {
            assert_eq!(location.path(), "/failed");
            assert_eq!(
                location
                    .query_pairs()
                    .find(|(key, _)| key == "error")
                    .unwrap()
                    .1,
                "issuer_mismatch"
            );
            assert!(!cookies(&completed).contains("session_token="));
            assert!(
                completed
                    .headers
                    .get_all("set-cookie")
                    .any(|cookie| cookie.contains("state=") && cookie.contains("Max-Age=0"))
            );
            assert_eq!(db.tables(&["user", "account", "session"]).await?, before);
            assert!(remote.take().is_empty());
        } else {
            assert_eq!(location.path(), "/done");
            authenticated(&auth, &cookies(&completed), "mixup-owner@example.test").await;
            let current = body(
                &call(
                    &auth,
                    request("/get-session", None, &cookies(&completed)),
                    200,
                )
                .await,
            );
            let rows: Vec<Value> = serde_json::from_str(&db.table("account").await?)?;
            let account = rows
                .iter()
                .find(|row| row["accountId"] == "mixup-owner-sub")
                .unwrap();
            assert_eq!(account["providerId"], "oidc");
            assert_eq!(account["userId"], current["user"]["id"]);
            let receipts = remote.take();
            assert_eq!(
                receipts
                    .iter()
                    .filter(|receipt| receipt.path == "/token")
                    .count(),
                1
            );
            assert!(receipts.iter().all(|receipt| receipt.path != "/profile"));
            for (table, original) in &foreign_rows {
                let old_rows: Vec<Value> = serde_json::from_str(original)?;
                let new_rows: Vec<Value> = serde_json::from_str(&db.table(table).await?)?;
                assert_eq!(new_rows.len(), 2);
                assert!(
                    old_rows.iter().all(|row| new_rows.contains(row)),
                    "foreign {table}"
                );
            }
        }
        assert_eq!(db.count("verification").await?, 0);
        let committed = db.tables(&["user", "account", "session"]).await?;
        let mut replay = request("/callback/oidc", None, &cookie);
        replay.set_query_pairs([
            ("state", authorization["state"].as_str()),
            ("code", "mixup-valid-grant"),
            ("iss", issuer),
        ]);
        let denied = call(&auth, replay, 302).await;
        let replay_location = url::Url::parse(denied.headers.get("location").unwrap())?;
        assert_eq!(
            replay_location
                .query_pairs()
                .find(|(key, _)| key == "error")
                .unwrap()
                .1,
            "state_mismatch"
        );
        assert_eq!(db.tables(&["user", "account", "session"]).await?, committed);
        assert!(remote.take().is_empty());
        authenticated(&auth, &cookies(&foreign), "mixup-foreign@example.test").await;
    }
    B::close(connection).await
}

fn access_endpoint(input: &Value) -> alibi::AuthResult<alibi::endpoint::ServerEndpoint<Value>> {
    alibi::endpoint::ServerEndpoint::new("oauth", "getAccessToken").with_body(input)
}
async fn refresh_owned_grant<S: AuthSchema>(
    auth: &Alibi<S>,
    db: &Db,
    remote: &Provider,
    owner_account_token: (&str, &str, &str),
    outsider: &AuthResponse,
    account_events: &Arc<Mutex<Vec<&'static str>>>,
) -> TestResult {
    let (owner, account, delivered_id_token) = owner_account_token;
    let before_refresh = db.tables(&["user", "account", "session"]).await?;
    for (options, status) in [
        (
            alibi::endpoint::EndpointOptions {
                headers: Some(HashMap::new()),
                ..Default::default()
            },
            401,
        ),
        (
            alibi::endpoint::EndpointOptions {
                request: Some(request("/incoming-request", None, "")),
                ..Default::default()
            },
            401,
        ),
        (
            alibi::endpoint::EndpointOptions {
                headers: Some([("cookie".into(), cookies(outsider))].into_iter().collect()),
                ..Default::default()
            },
            400,
        ),
    ] {
        let denied = Box::pin(
            auth.dispatch_endpoint(
                alibi::endpoint::ServerEndpoint::<Value>::new("oauth", "refreshToken")
                    .with_body(&json!({"accountId":account,"userId":owner}))?,
                options,
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        assert_eq!(denied.body_absent, status == 401);
        assert_eq!(
            db.tables(&["user", "account", "session"]).await?,
            before_refresh
        );
        assert!(remote.take().is_empty());
    }
    remote.respond_at("/token", 200, json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}));
    account_events.lock().unwrap().clear();
    let refresh = Box::pin(auth.dispatch_endpoint(
        OAuthPlugin::refresh_token_endpoint(
            OAuthAccountSelection::Id(account.to_owned()),
            Some(owner),
        ),
        alibi::endpoint::EndpointOptions::default(),
    ))
    .await?;
    let decoded = refresh.decode()?;
    assert_eq!(decoded.access_token, Some(json!("rotated-access")));
    assert_eq!(decoded.refresh_token, Some(json!("rotated-refresh")));
    assert_eq!(decoded.account_id.as_deref(), Some(account));
    assert_eq!(decoded.id_token, Some(json!(delivered_id_token)));
    let persisted = auth
        .context()
        .database
        .get_user_accounts_record(owner)
        .await?;
    let expiry = persisted
        .iter()
        .find(|row| row.id().as_ref() == account)
        .unwrap()
        .access_token_expires_at()
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(
        decoded.access_token_expires_at.as_deref(),
        Some(expiry.as_str())
    );
    assert_eq!(
        refresh
            .headers()
            .get_all("set-cookie")
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "application_a=first; Path=/; HttpOnly",
            "application_b=second; Path=/; HttpOnly"
        ]
    );
    assert_eq!(*account_events.lock().unwrap(), ["before", "after"]);
    assert_eq!(
        db.text(
            "SELECT \"accessToken\" FROM \"account\" WHERE id=$1",
            &[account]
        )
        .await?
        .as_deref(),
        Some("rotated-access")
    );
    assert_eq!(
        db.text(
            "SELECT \"refreshToken\" FROM \"account\" WHERE id=$1",
            &[account]
        )
        .await?
        .as_deref(),
        Some("rotated-refresh")
    );
    assert_eq!(
        db.tables(&["user", "session"]).await?,
        vec![before_refresh[0].clone(), before_refresh[2].clone()]
    );
    let before_accounts: Vec<Value> = serde_json::from_str(&before_refresh[1])?;
    let after_accounts: Vec<Value> = serde_json::from_str(&db.table("account").await?)?;
    assert_eq!(
        after_accounts
            .iter()
            .filter(|row| row["id"] != account)
            .collect::<Vec<_>>(),
        before_accounts
            .iter()
            .filter(|row| row["id"] != account)
            .collect::<Vec<_>>()
    );
    Ok(())
}

struct AccessOperationHook(Arc<Mutex<Vec<&'static str>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::endpoint::EndpointHook<S> for AccessOperationHook {
    fn matches_before(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<bool> {
        Ok(matches!(
            call.operation_id(),
            "getAccessToken" | "refreshToken"
        ))
    }
    async fn before(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<alibi::endpoint::BeforeEndpointAction>> {
        assert_eq!(
            call.path(),
            Some(if call.operation_id() == "refreshToken" {
                "/refresh-token"
            } else {
                "/get-access-token"
            })
        );
        self.0.lock().unwrap().push("before");
        Ok(None)
    }
    fn matches_after(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _: &alibi::AuthContext<S>,
        _: &alibi::endpoint::EndpointResponse,
    ) -> alibi::AuthResult<bool> {
        Ok(matches!(
            call.operation_id(),
            "getAccessToken" | "refreshToken"
        ))
    }
    async fn after(
        &self,
        call: &alibi::endpoint::EndpointCall,
        _: &alibi::AuthContext<S>,
        response: alibi::endpoint::EndpointResponse,
    ) -> alibi::AuthResult<alibi::endpoint::EndpointResponse> {
        self.0.lock().unwrap().push("after");
        if call.request().is_some() {
            return Ok(response);
        }
        Ok(response
            .with_header("set-cookie", "application_a=first; Path=/; HttpOnly")
            .with_header("set-cookie", "application_b=second; Path=/; HttpOnly"))
    }
}
