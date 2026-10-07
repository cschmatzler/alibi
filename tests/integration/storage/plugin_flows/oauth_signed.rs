//! Provider-specific signed identity admission through the actual HTTP boundary.
use super::*;
use alibi::plugins::OAuthPlugin;
use alibi::plugins::oauth::{
    AppleOptions, CognitoOptions, FacebookOptions, HttpOAuthJwksSource, MicrosoftOptions,
    OAuthProvider,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use sha2::{Digest as _, Sha256};

backend_tests!(signed_provider_identity_requires_its_configured_authority);
postgres_tests!(signed_provider_identity_requires_its_configured_authority);

pub(super) fn token(claims: &Value, wrong_signature: bool, kid: &str) -> TestResult<String> {
    let pem = if wrong_signature {
        include_bytes!("../../../fixtures/one-tap/wrong-private-key.pem").as_slice()
    } else {
        include_bytes!("../../../fixtures/one-tap/private-key.pem").as_slice()
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    Ok(jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(pem)?,
    )?)
}

pub(super) fn wrong_public_key() -> TestResult<Value> {
    use base64::Engine as _;
    use rsa::{pkcs8::DecodePrivateKey as _, traits::PublicKeyParts as _};
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(
        "../../../fixtures/one-tap/wrong-private-key.pem"
    ))?;
    Ok(
        json!({"kty":"RSA", "kid":"one-tap-local-rs256", "alg":"RS256", "use":"sig", "n":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()), "e":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())}),
    )
}

fn protected_token(claims: &Value, header: Value) -> TestResult<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &EncodingKey::from_rsa_pem(include_bytes!("../../../fixtures/one-tap/private-key.pem"))?,
        Algorithm::RS256,
    )?;
    Ok(format!("{message}.{signature}"))
}

async fn signed_provider_identity_requires_its_configured_authority<B: Backend>(
    db: Db,
) -> TestResult {
    for name in [
        "google",
        "google-wildcard",
        "google-explicit",
        "apple",
        "cognito",
        "microsoft",
        "microsoft-primary",
        "microsoft-secondary",
        "microsoft-explicitfalse",
        "microsoft-unmatched",
        "microsoft-photo",
        "microsoft-photofailure",
        "facebook",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let remote = Provider::start(
            "application/json",
            include_str!("../../../fixtures/one-tap/jwks.json"),
        )
        .await;
        let keys = Arc::new(HttpOAuthJwksSource::new(
            remote.url.join("keys")?.to_string(),
        ));
        let (provider, issuer, subject, verified) = match name.split('-').next().unwrap() {
            "google" => {
                let mut provider = OAuthProvider::google("native-client", "native-secret");
                provider.id_token.as_mut().unwrap().jwks_source = keys;
                provider.additional_client_ids = vec!["secondary-client".into()];
                provider.hosted_domain = Some(
                    if name == "google-wildcard" {
                        "*"
                    } else {
                        "workspace.test"
                    }
                    .into(),
                );
                if name == "google-explicit" {
                    provider.id_token.as_mut().unwrap().audience =
                        Some(vec!["override-client".into()]);
                    provider.id_token.as_mut().unwrap().client_ids =
                        Some(vec!["ignored-client".into()]);
                }
                (
                    provider,
                    "https://accounts.google.com",
                    "signed-subject",
                    true,
                )
            }
            "apple" => {
                let mut options = AppleOptions::new("native-client", "native-secret");
                options.jwks_source = Some(keys);
                (
                    OAuthProvider::apple_with_options(options),
                    "https://appleid.apple.com",
                    "signed-subject",
                    true,
                )
            }
            "cognito" => {
                let mut options = CognitoOptions::new(
                    "native-client",
                    Some("native-secret".into()),
                    "pool.example.test",
                    "us-east-1",
                    "pool",
                );
                options.jwks_source = Some(keys);
                options.user_info_endpoint =
                    Some(remote.url.join("must-not-fetch-profile")?.into());
                (
                    OAuthProvider::cognito(options)?,
                    "https://cognito-idp.us-east-1.amazonaws.com/pool",
                    "signed-subject",
                    true,
                )
            }
            "microsoft" => {
                let mut options =
                    MicrosoftOptions::new("native-client", Some("native-secret".into()));
                options.jwks_source = Some(keys);
                options.tenant_id = Some("organizations".into());
                options.disable_profile_photo = !name.contains("photo");
                options.profile_photo_endpoint = Some(remote.url.join("photo")?.into());
                remote.respond_at(
                    "/photo",
                    if name == "microsoft-photofailure" {
                        503
                    } else {
                        200
                    },
                    json!("photo-bytes"),
                );
                (
                    OAuthProvider::microsoft(options)?,
                    "https://login.microsoftonline.com/tenant-a/v2.0",
                    "object-identity",
                    !matches!(name, "microsoft-explicitfalse" | "microsoft-unmatched"),
                )
            }
            "facebook" => {
                let mut options =
                    FacebookOptions::new("native-client", Some("native-secret".into()));
                options.jwks_source = Some(keys);
                (
                    OAuthProvider::facebook_with_options(options),
                    "https://www.facebook.com",
                    "signed-subject",
                    false,
                )
            }
            _ => return Err(format!("unknown signed provider fixture: {name}").into()),
        };
        let auth = builder::<B>(&connection)
            .plugin(OAuthPlugin::new().add_provider(name, provider))
            .build()
            .await?;
        let now = chrono::Utc::now().timestamp();
        let email = format!("{name}@signed.example.test");
        let mut claims = json!({"iss":issuer,"aud":"native-client","sub":"signed-subject","oid":"object-identity","tid":"tenant-a","email":email,"email_verified":true,"name":"Signed User","picture":"https://images.test/signed","iat":now,"exp":now+300,"nonce":"browser-nonce"});
        if name.starts_with("google") {
            claims["aud"] = json!(if name == "google-explicit" {
                "override-client"
            } else {
                "secondary-client"
            });
            claims["hd"] = json!("workspace.test");
        }
        if matches!(
            name,
            "microsoft-primary"
                | "microsoft-secondary"
                | "microsoft-unmatched"
                | "microsoft-explicitfalse"
        ) {
            drop(claims.as_object_mut().unwrap().remove("email_verified"));
            claims["verified_primary_email"] = json!(["foreign@example.test"]);
            claims["verified_secondary_email"] = json!(["foreign@example.test"]);
            if name == "microsoft-primary" {
                claims["verified_primary_email"] = json!([email]);
            }
            if name == "microsoft-secondary" {
                claims["verified_secondary_email"] = json!([email]);
            }
            if name == "microsoft-explicitfalse" {
                claims["verified_primary_email"] = json!([email]);
                claims["email_verified"] = json!(false);
            }
        }
        for control in [
            "signature",
            "audience",
            "issuer",
            "expiration",
            "nonce",
            "future-nbf",
            "old-iat",
            "future-iat",
            "missing-iat",
            "domain",
            "missing-domain",
            "audience-precedence",
        ] {
            if name.starts_with("microsoft-")
                || (matches!(control, "old-iat" | "future-iat" | "missing-iat")
                    && name == "facebook")
                || (matches!(control, "domain" | "missing-domain") && !name.starts_with("google"))
                || (control == "domain" && name == "google-wildcard")
                || (control == "audience-precedence" && name != "google-explicit")
            {
                continue;
            }
            let mut rejected = claims.clone();
            match control {
                "audience" => rejected["aud"] = json!("foreign-client"),
                "issuer" => rejected["iss"] = json!("https://foreign.example.test"),
                "expiration" => rejected["exp"] = json!(now - 3600),
                "nonce" => rejected["nonce"] = json!("foreign-nonce"),
                "future-nbf" => rejected["nbf"] = json!(now + 3600),
                "old-iat" => rejected["iat"] = json!(now - 7200),
                "future-iat" => rejected["iat"] = json!(now + 3600),
                "missing-iat" => {
                    drop(rejected.as_object_mut().unwrap().remove("iat"));
                }
                "domain" => rejected["hd"] = json!("foreign.test"),
                "missing-domain" => {
                    drop(rejected.as_object_mut().unwrap().remove("hd"));
                }
                "audience-precedence" => rejected["aud"] = json!("secondary-client"),
                _ => {}
            }
            let proof = token(&rejected, control == "signature", "one-tap-local-rs256")?;
            let denied = call(
                &auth,
                request(
                    "/sign-in/social",
                    Some(
                        json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}}),
                    ),
                    "",
                ),
                401,
            )
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_TOKEN", "{name}/{control}");
            assert!(cookies(&denied).is_empty(), "{name}/{control}");
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0, "{name}/{control}/{table}");
            }
        }
        // Exact-key factories must not silently fall back to another key. Google
        // deliberately has a separate first-key policy.
        if !name.starts_with("google") && !name.starts_with("microsoft-") {
            let proof = token(&claims, false, "absent-key")?;
            let denied = call(
                &auth,
                request(
                    "/sign-in/social",
                    Some(
                        json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}}),
                    ),
                    "",
                ),
                401,
            )
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_TOKEN", "{name}/kid");
            assert_eq!(db.count("users").await?, 0);
        }
        if name == "microsoft" {
            let mut consumer = claims.clone();
            consumer["tid"] = json!("9188040d-6c67-4c5b-b112-36a304b66dad");
            consumer["iss"] = json!(
                "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
            );
            let proof = token(&consumer, false, "one-tap-local-rs256")?;
            let denied = call(
                &auth,
                request(
                    "/sign-in/social",
                    Some(
                        json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}}),
                    ),
                    "",
                ),
                401,
            )
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_TOKEN");
            assert_eq!(db.count("accounts").await?, 0);
        }
        let document: Value =
            serde_json::from_str(include_str!("../../../fixtures/one-tap/jwks.json"))?;
        if matches!(name, "google" | "apple" | "facebook") {
            // Both keys are independently importable RSA keys; only the second
            // signed this token. Rejection therefore exercises selection policy.
            for keys in if name == "facebook" {
                vec![json!([wrong_public_key()?, document["keys"][0]]), {
                    let mut encryption = document["keys"][0].clone();
                    encryption["use"] = json!("enc");
                    json!([encryption])
                }]
            } else {
                vec![json!([wrong_public_key()?, document["keys"][0]])]
            } {
                remote.respond_at("/keys", 200, json!({"keys":keys}));
                let proof = token(&claims, false, "one-tap-local-rs256")?;
                let denied = call(&auth,request("/sign-in/social",Some(json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}})),""),401).await;
                assert_eq!(body(&denied)["code"], "INVALID_TOKEN");
                assert_eq!(db.count("users").await?, 0);
                assert_eq!(db.count("accounts").await?, 0);
                assert_eq!(db.count("sessions").await?, 0);
            }
        }
        remote.respond_at("/keys", 200, document.clone());
        // Correct signatures must not authorize an unsupported critical header.
        let proof = protected_token(
            &claims,
            json!({"alg":"RS256","kid":"one-tap-local-rs256","crit":["application"],"application":true}),
        )?;
        let denied = call(
            &auth,
            request(
                "/sign-in/social",
                Some(json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}})),
                "",
            ),
            401,
        )
        .await;
        assert_eq!(body(&denied)["code"], "INVALID_TOKEN");
        assert_eq!(db.count("sessions").await?, 0);
        if name == "facebook" {
            let mut encryption = wrong_public_key()?;
            encryption["use"] = json!("enc");
            remote.respond_at(
                "/keys",
                200,
                json!({"keys":[encryption,document["keys"][0]]}),
            );
        }
        let proof = protected_token(
            &claims,
            json!({"alg":"RS256","kid":"one-tap-local-rs256","crit":["b64"],"b64":true}),
        )?;
        let accepted = call(
            &auth,
            request(
                "/sign-in/social",
                Some(json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce","accessToken":if name.contains("photo") { Some("photo-access") } else { None }}})),
                "",
            ),
            200,
        )
        .await;
        authenticated(&auth, &cookies(&accepted), &email).await;
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM accounts WHERE provider_id = $1 AND account_id = $2",
                &[name, subject]
            )
            .await?,
            1,
            "{name}"
        );
        assert_eq!(
            db.text("SELECT name FROM users", &[]).await?.as_deref(),
            Some("Signed User"),
            "{name}"
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE email_verified = true",
                &[]
            )
            .await?,
            i64::from(verified),
            "{name}"
        );
        if name.contains("photo") {
            {
                let exchanges = remote.requests.lock().unwrap();
                let photo = exchanges
                    .iter()
                    .find(|exchange| exchange.path == "/photo")
                    .expect("configured Graph photo request");
                assert_eq!(photo.method, "GET");
                assert_eq!(photo.headers["authorization"], "Bearer photo-access");
            }
            assert_eq!(
                db.text("SELECT image FROM users", &[]).await?.as_deref(),
                Some(if name == "microsoft-photo" {
                    "data:image/jpeg;base64, InBob3RvLWJ5dGVzIg=="
                } else {
                    "https://images.test/signed"
                })
            );
        }
        if name == "apple" {
            let before = db.tables(&["users", "accounts", "sessions"]).await?;
            let proof = protected_token(&claims, json!({"alg":"RS256"}))?;
            let mut key = document["keys"][0].clone();
            key["kid"] = Value::Null;
            remote.respond_at("/keys", 200, json!({"keys":[key.clone()]}));
            let denied = call(
                &auth,
                request(
                    "/sign-in/social",
                    Some(
                        json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}}),
                    ),
                    "",
                ),
                401,
            )
            .await;
            assert_eq!(body(&denied)["code"], "INVALID_TOKEN");
            assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, before);
            drop(key.as_object_mut().unwrap().remove("kid"));
            remote.respond_at("/keys", 200, json!({"keys":[key]}));
            let accepted = call(
                &auth,
                request(
                    "/sign-in/social",
                    Some(
                        json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}}),
                    ),
                    "",
                ),
                200,
            )
            .await;
            authenticated(&auth, &cookies(&accepted), &email).await;
            assert_eq!(db.count("accounts").await?, 1);
            remote.respond_at("/keys", 200, document);
            let mut hashed = claims.clone();
            hashed["nonce"] = json!(
                Sha256::digest(b"browser-nonce")
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let proof = token(&hashed, false, "one-tap-local-rs256")?;
            let accepted = call(
                &auth,
                request(
                    "/sign-in/social",
                    Some(
                        json!({"provider":name,"idToken":{"token":proof,"nonce":"browser-nonce"}}),
                    ),
                    "",
                ),
                200,
            )
            .await;
            authenticated(&auth, &cookies(&accepted), &email).await;
            assert_eq!(db.count("accounts").await?, 1);
        }
        let requests = remote.take();
        assert!(!requests.is_empty());
        assert!(
            requests.iter().all(|request| (request.path == "/keys"
                || (name.contains("photo") && request.path == "/photo"))
                && request.method == "GET"),
            "{name}: identity came entirely from verified claims"
        );
        B::close(connection).await?;
    }
    Ok(())
}
