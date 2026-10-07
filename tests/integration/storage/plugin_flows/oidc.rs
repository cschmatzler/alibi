//! Discovery, signed grants, client authentication, trusted account operations
//! and RP logout, through the public native boundaries and a recording peer.
use super::*;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::{
    GenericOAuthConfig, OAuthAccountApi, OAuthAccountSelection, OAuthPrivateKeyJwtOptions,
    OAuthTokenEndpointAuth,
};
use std::collections::{HashMap, HashSet};

backend_tests!(oidc_discovery_signed_grants_assertions_refresh_and_logout);
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
    let auth = builder::<B>(&connection)
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
            "expired" => claims["exp"] = json!(now - 1),
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
            for table in ["users", "accounts", "sessions"] {
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
            "SELECT id FROM accounts WHERE provider_id = 'oidc' AND account_id = 'oidc-subject'",
            &[],
        )
        .await?
        .unwrap();
    let select = || OAuthAccountSelection::Id(account.clone());
    let access = OAuthAccountApi::get_access_token(&owner, select(), auth.context()).await?;
    assert_eq!(body(&access)["accessToken"], "initial-access");
    assert!(remote.take().is_empty());
    let outsider = signup(&auth, "outsider@example.test").await;
    let outsider_id = body(&outsider)["user"]["id"].as_str().unwrap().to_owned();
    let accounts = db.table("accounts").await?;
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
    assert_eq!(db.table("accounts").await?, accounts);
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
        assert_eq!(db.table("accounts").await?, accounts);
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
    assert_eq!(db.table("accounts").await?, accounts);
    drop(remote.take());

    remote.respond_at("/token", 200, json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}));
    let refresh = OAuthAccountApi::refresh_token(&owner, select(), auth.context()).await?;
    assert_eq!(body(&refresh)["accessToken"], "rotated-access");
    assert_eq!(
        db.text("SELECT access_token FROM accounts WHERE id=$1", &[&account])
            .await?
            .as_deref(),
        Some("rotated-access")
    );
    assert_eq!(
        db.text(
            "SELECT refresh_token FROM accounts WHERE id=$1",
            &[&account]
        )
        .await?
        .as_deref(),
        Some("rotated-refresh")
    );
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
    assert_eq!(body(&profile)["account"]["accountId"], "oidc-subject");
    assert_eq!(body(&profile)["user"]["email"], "oidc@example.test");
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
        db.count_where("SELECT COUNT(*) FROM sessions WHERE user_id=$1", &[&owner])
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
        let before = db.tables(&["users", "accounts", "sessions"]).await?;
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
                    "SELECT COUNT(*) FROM accounts WHERE provider_id=$1 AND account_id=$2",
                    &["algorithm", "algorithm-subject"]
                )
                .await?,
                1
            );
        } else {
            assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
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
