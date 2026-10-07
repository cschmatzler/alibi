use super::*;
use alibi::plugins::captcha::{
    CaptchaConfig, CaptchaPlugin, CaptchaProvider, RecaptchaConfig, SiteKeyCaptchaConfig,
    TurnstileConfig,
};
use alibi::plugins::haveibeenpwned::{
    HaveIBeenPwnedConfig, HaveIBeenPwnedPlugin, PwnedPasswordClient,
};
use alibi::plugins::oauth::OAuthProvider;
use alibi::plugins::one_tap::{OneTapConfig, OneTapPlugin};
use alibi::plugins::{OAuthPlugin, OAuthPopupPlugin};

backend_tests!(
    pwned_password_admission_uses_private_range_requests,
    captcha_provider_admission_precedes_persistence,
    one_tap_verifies_signed_identity_before_creating_accounts,
    popup_delivers_only_to_the_authenticated_opener
);
postgres_tests!(
    pwned_password_admission_uses_private_range_requests,
    captcha_provider_admission_precedes_persistence,
    one_tap_verifies_signed_identity_before_creating_accounts,
    popup_delivers_only_to_the_authenticated_opener
);

async fn pwned_password_admission_uses_private_range_requests<B: Backend>(db: Db) -> TestResult {
    // SHA-1("password") from the published k-anonymity protocol example, not
    // calculated by the implementation under test.
    let provider =
        Provider::start("text/plain", "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n").await;
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(HaveIBeenPwnedPlugin::with_config(HaveIBeenPwnedConfig {
            client: PwnedPasswordClient::new(
                reqwest::Client::builder()
                    .no_proxy()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()?,
                provider.url.clone(),
            ),
            ..Default::default()
        }))
        .build()
        .await?;
    let input = json!({"email":"pwned@example.test","password":"password","name":"Owner"});
    let denied = call(
        &auth,
        request("/sign-up/email", Some(input.clone()), ""),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "PASSWORD_COMPROMISED");
    for table in ["users", "accounts", "sessions"] {
        assert_eq!(db.count(table).await?, 0);
    }
    let exchange = provider.take().pop().unwrap();
    assert_eq!(exchange.path, "/5BAA6");
    assert_eq!(exchange.headers["add-padding"], "true");
    assert!(exchange.body.is_empty());

    // Provider failure must fail closed, without creating a partially signed-up user.
    provider.respond(503, "text/plain", "unavailable");
    let _ = call(
        &auth,
        request("/sign-up/email", Some(input.clone()), ""),
        500,
    )
    .await;
    assert_eq!(db.count("users").await?, 0);
    provider.respond(
        200,
        "text/plain",
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n",
    );
    let accepted = call(&auth, request("/sign-up/email", Some(input), ""), 200).await;
    authenticated(&auth, &cookies(&accepted), "pwned@example.test").await;
    assert_eq!(db.count("accounts").await?, 1);
    B::close(connection).await
}

async fn captcha_provider_admission_precedes_persistence<B: Backend>(db: Db) -> TestResult {
    let provider = Provider::start("application/json", json!({"success":false}).to_string()).await;
    for kind in ["turnstile", "recaptcha", "hcaptcha", "captchafox"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let captcha = match kind {
            "turnstile" => {
                let mut options = TurnstileConfig::new("provider-secret");
                options.http.site_verify_url = Some(provider.url.clone());
                options.expected_action = Some("signup".into());
                options.allowed_hostnames = vec!["auth.example.test".into()];
                CaptchaProvider::CloudflareTurnstile(options)
            }
            "recaptcha" => {
                let mut options = RecaptchaConfig::new("provider-secret");
                options.http.site_verify_url = Some(provider.url.clone());
                options.expected_action = Some("signup".into());
                options.allowed_hostnames = vec!["auth.example.test".into()];
                CaptchaProvider::GoogleRecaptcha(options)
            }
            _ => {
                let mut options = SiteKeyCaptchaConfig::new("provider-secret");
                options.http.site_verify_url = Some(provider.url.clone());
                options.site_key = Some("site-key".into());
                if kind == "hcaptcha" {
                    CaptchaProvider::HCaptcha(options)
                } else {
                    CaptchaProvider::CaptchaFox(options)
                }
            }
        };
        let auth = builder::<B>(&connection)
            .plugin(
                CaptchaPlugin::new(CaptchaConfig::new(captcha))
                    .with_http_client(reqwest::Client::builder().no_proxy().build()?),
            )
            .build()
            .await?;
        let mut input = request(
            "/sign-up/email",
            Some(json!({"email":"captcha@example.test","password":PASSWORD,"name":"Owner"})),
            "",
        );
        input.headers.extend([
            ("x-captcha-response".into(), "challenge-proof".into()),
            ("x-forwarded-for".into(), "198.51.100.7".into()),
        ]);
        provider.respond(
            200,
            "application/json",
            json!({"success":false}).to_string(),
        );
        let rejected = call(&auth, input.clone(), 403).await;
        assert_eq!(body(&rejected)["code"], "VERIFICATION_FAILED");
        for table in ["users", "accounts", "sessions"] {
            assert_eq!(db.count(table).await?, 0, "{kind}: {table}");
        }
        let exchange = provider.take().pop().unwrap();
        let fields: Value = if kind == "turnstile" {
            assert!(
                exchange.headers["content-type"]
                    .to_str()?
                    .starts_with("application/json")
            );
            serde_json::from_slice(&exchange.body)?
        } else {
            assert!(
                exchange.headers["content-type"]
                    .to_str()?
                    .starts_with("application/x-www-form-urlencoded")
            );
            serde_json::to_value(
                url::form_urlencoded::parse(&exchange.body)
                    .into_owned()
                    .collect::<std::collections::HashMap<_, _>>(),
            )?
        };
        assert_eq!(fields["secret"], "provider-secret");
        assert_eq!(fields["response"], "challenge-proof");
        assert_eq!(
            fields[if kind == "captchafox" {
                "remoteIp"
            } else {
                "remoteip"
            }],
            "198.51.100.7"
        );
        if matches!(kind, "hcaptcha" | "captchafox") {
            assert_eq!(fields["sitekey"], "site-key");
        }
        let valid =
            json!({"success":true,"score":0.9,"action":"signup","hostname":"auth.example.test"});
        if matches!(kind, "turnstile" | "recaptcha") {
            let mut rejected_fields = vec![
                ("action", json!("signin")),
                ("hostname", json!("foreign.example")),
            ];
            if kind == "recaptcha" {
                rejected_fields.push(("score", json!(0.49)));
            }
            for (field, wrong) in rejected_fields {
                let mut response = valid.clone();
                response[field] = wrong;
                provider.respond(200, "application/json", response.to_string());
                let rejected = call(&auth, input.clone(), 403).await;
                assert_eq!(
                    body(&rejected)["code"],
                    "VERIFICATION_FAILED",
                    "{kind}: {field}"
                );
                for table in ["users", "accounts", "sessions"] {
                    assert_eq!(
                        db.count(table).await?,
                        0,
                        "{kind}: {field} must reject before {table} writes"
                    );
                }
            }
        }
        provider.respond(200, "application/json", valid.to_string());
        let accepted = call(&auth, input, 200).await;
        authenticated(&auth, &cookies(&accepted), "captcha@example.test").await;
        assert_eq!(db.count("sessions").await?, 1);
        B::close(connection).await?;
    }
    Ok(())
}

async fn one_tap_verifies_signed_identity_before_creating_accounts<B: Backend>(
    db: Db,
) -> TestResult {
    let remote = Provider::start("application/json", "{}").await;
    let document: Value =
        serde_json::from_str(include_str!("../../../fixtures/one-tap/jwks.json"))?;
    remote.respond_at("/keys", 200, document.clone());
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OneTapPlugin::with_config(OneTapConfig {
            client_id: Some("native-google-client".into()),
            jwks_source: Some(Arc::new(alibi::plugins::oauth::HttpOAuthJwksSource::new(
                remote.url.join("keys")?.to_string(),
            ))),
            ..Default::default()
        }))
        .build()
        .await?;
    let valid_key = include_bytes!("../../../fixtures/one-tap/private-key.pem");
    let wrong_key = include_bytes!("../../../fixtures/one-tap/wrong-private-key.pem");
    for (key, audience, status) in [
        (wrong_key.as_slice(), "native-google-client", 400),
        (valid_key.as_slice(), "foreign-client", 400),
        (valid_key.as_slice(), "native-google-client", 200),
    ] {
        if status == 200 {
            remote.respond_at(
                "/keys",
                200,
                json!({"keys":[super::oauth_signed::wrong_public_key()?,document["keys"][0]]}),
            );
        }
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("one-tap-local-rs256".into());
        let token = jsonwebtoken::encode(
            &header,
            &json!({"iss":"https://accounts.google.com","aud":audience,"sub":"google-user-42","email":"google@example.test","email_verified":true,"name":"Google owner","iat":chrono::Utc::now().timestamp(),"exp":chrono::Utc::now().timestamp()+300}),
            &jsonwebtoken::EncodingKey::from_rsa_pem(key)?,
        )?;
        let response = call(
            &auth,
            request("/one-tap/callback", Some(json!({"idToken":token})), ""),
            status,
        )
        .await;
        if status == 400 {
            assert_eq!(body(&response)["message"], "invalid id token");
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        } else {
            authenticated(&auth, &cookies(&response), "google@example.test").await;
            assert_eq!(
                db.text("SELECT provider_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some("google")
            );
            assert_eq!(
                db.text("SELECT account_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some("google-user-42")
            );
        }
    }
    B::close(connection).await
}

async fn popup_delivers_only_to_the_authenticated_opener<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    remote.respond_at(
        "/token",
        200,
        json!({"access_token":"popup-access","token_type":"Bearer"}),
    );
    remote.respond_at("/profile", 200, json!({"id":471,"login":"popup-owner","name":"Popup Owner","email":null,"avatar_url":"https://images.test/popup"}));
    remote.respond_at(
        "/emails",
        200,
        json!([{"email":"popup@example.test","primary":true,"verified":true}]),
    );
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider(
            "github",
            OAuthProvider::github_with_endpoints(
                "native-client",
                "native-secret",
                remote.url.join("authorize")?.as_str(),
                remote.url.join("token")?.as_str(),
                remote.url.join("profile")?.as_str(),
                remote.url.join("emails")?.as_str(),
            ),
        ))
        .plugin(OAuthPopupPlugin::new())
        .build()
        .await?;
    let nonce = "</script><script>untrusted()</script>";
    let mut start = request("/oauth-popup/start", None, "");
    start.query.extend([
        ("provider".into(), "github".into()),
        ("popupOrigin".into(), "https://foreign.example".into()),
        ("popupNonce".into(), nonce.into()),
    ]);
    let rejected = call(&auth, start.clone(), 403).await;
    assert_eq!(body(&rejected)["code"], "INVALID_ORIGIN");
    assert_eq!(db.count("verifications").await?, 0);
    drop(start.query.insert("popupOrigin".into(), ORIGIN.into()));
    let issued = call(&auth, start.clone(), 302).await;
    let url = url::Url::parse(issued.headers.get("location").unwrap())?;
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(db.count("verifications").await?, 1);
    let mut callback = request("/callback/github", None, &cookies(&issued));
    callback.query.extend([
        ("state".into(), state),
        ("error".into(), "access_denied".into()),
    ]);
    let completed = call(&auth, callback, 200).await;
    let html = String::from_utf8(completed.body)?;
    let payload = html
        .split("id=\"better-auth-oauth-popup\">")
        .nth(1)
        .unwrap()
        .split("</script>")
        .next()
        .unwrap();
    let payload: Value = serde_json::from_str(payload)?;
    assert_eq!(payload["targetOrigin"], ORIGIN);
    assert_eq!(payload["nonce"], nonce);
    assert_eq!(payload["error"]["code"], "access_denied");
    assert!(
        !html.contains(nonce),
        "untrusted nonce must not terminate the data element"
    );
    assert!(completed.headers.get_all("set-cookie").any(|cookie| {
        cookie.starts_with("better-auth.oauth_popup=") && cookie.contains("Max-Age=0")
    }));
    assert_eq!(db.count("verifications").await?, 0);
    assert_eq!(db.count("users").await?, 0);
    let issued = call(&auth, start, 302).await;
    let url = url::Url::parse(issued.headers.get("location").unwrap())?;
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let mut callback = request("/callback/github", None, &cookies(&issued));
    callback.query.extend([
        ("state".into(), state),
        ("code".into(), "real-popup-grant".into()),
    ]);
    let completed = call(&auth, callback.clone(), 200).await;
    let html = String::from_utf8(completed.body.clone())?;
    let payload: Value = serde_json::from_str(
        html.split("id=\"better-auth-oauth-popup\">")
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap(),
    )?;
    assert_eq!(payload["targetOrigin"], ORIGIN);
    assert_eq!(payload["nonce"], nonce);
    assert!(payload.get("error").is_none());
    let token = payload["token"].as_str().unwrap();
    authenticated(
        &auth,
        &format!("better-auth.session_token={token}"),
        "popup@example.test",
    )
    .await;
    assert_eq!(
        db.text("SELECT account_id FROM accounts", &[])
            .await?
            .as_deref(),
        Some("471")
    );
    assert_eq!(db.count("verifications").await?, 0);
    assert!(completed.headers.get_all("set-cookie").any(|cookie| {
        cookie.starts_with("better-auth.oauth_popup=") && cookie.contains("Max-Age=0")
    }));
    let original = db.tables(&["users", "accounts", "sessions"]).await?;
    let replay = call(&auth, callback, 200).await;
    assert!(!cookies(&replay).contains("session_token="));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        original
    );
    let exchanges = remote.take();
    for path in ["/profile", "/emails"] {
        let exchange = exchanges
            .iter()
            .find(|exchange| exchange.path == path)
            .unwrap();
        assert_eq!(exchange.headers["authorization"], "Bearer popup-access");
    }
    B::close(connection).await
}
