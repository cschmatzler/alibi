#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "asserted JWT contracts with real keys and SQLite"
)]

use super::*;
use crate::plugins::test_helpers;
use better_auth_core::CreateUser;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

fn payload(subject: &str) -> Map<String, Value> {
    json!({ "sub": subject, "application": "jwt-tests" })
        .as_object()
        .unwrap()
        .clone()
}
fn decoded(token: &str) -> (Value, Value) {
    let parts = token.split('.').collect::<Vec<_>>();
    (
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap(),
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap(),
    )
}

#[tokio::test]
async fn default_keys_are_encrypted_and_jwt_claims_signature_and_public_material_are_real() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    let token = plugin
        .sign_jwt(payload("subject-1"), &JwtSignOptions::default(), None, &ctx)
        .await
        .unwrap();
    let (header, claims) = decoded(&token);
    assert_eq!(header["alg"], "EdDSA");
    assert!(header.get("typ").is_none());
    assert!(claims.get("iat").is_none());
    assert_eq!(claims["iss"], ctx.config.base_url);
    assert_eq!(claims["aud"], ctx.config.base_url);
    assert!((claims["exp"].as_i64().unwrap() - Utc::now().timestamp() - 900).abs() <= 1);
    let keys = ctx.database.list_jwks().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(header["kid"], keys[0].id);
    assert!(serde_json::from_str::<String>(&keys[0].private_key).is_ok());
    assert!(!keys[0].private_key.contains("\"d\""));
    let private = decrypt(
        &serde_json::from_str::<String>(&keys[0].private_key).unwrap(),
        &ctx.config.secret,
    )
    .unwrap();
    assert!(serde_json::from_str::<Value>(&private).unwrap()["d"].is_string());
    let public = plugin
        .jwks(
            &test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None),
            &ctx,
        )
        .await
        .unwrap();
    let public: Value = serde_json::from_slice(&public.body).unwrap();
    assert_eq!(public["keys"][0]["kid"], header["kid"]);
    assert_eq!(public["keys"][0]["crv"], "Ed25519");
    assert!(public["keys"][0].get("d").is_none());
    assert!(public["keys"][0].get("privateKey").is_none());
    assert_eq!(
        plugin
            .verify_jwt(&token, None, None, &ctx)
            .await
            .unwrap()
            .unwrap(),
        claims.as_object().unwrap().clone()
    );
}

#[tokio::test]
async fn verification_rejects_tampering_wrong_claims_unknown_key_and_algorithm_confusion() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    let options = JwtSignOptions::default();
    for overrides in [
        json!({"iss":"wrong-issuer"}),
        json!({"aud":"wrong-audience"}),
        json!({"exp":0}),
        json!({"nbf":Utc::now().timestamp()+1000}),
        json!({"sub":""}),
    ] {
        let mut claims = payload("subject-1");
        claims.extend(overrides.as_object().unwrap().clone());
        let token = plugin.sign_jwt(claims, &options, None, &ctx).await.unwrap();
        assert!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }
    let token = plugin
        .sign_jwt(payload("subject-1"), &options, None, &ctx)
        .await
        .unwrap();
    let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    let mut header = decoded(&token).0;
    header["kid"] = json!("unknown-key");
    parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    assert!(
        plugin
            .verify_jwt(&parts.join("."), None, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
    header["kid"] = decoded(&token).0["kid"].clone();
    header["alg"] = json!("HS256");
    parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    assert!(
        plugin
            .verify_jwt(&parts.join("."), None, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
    parts[0] = token.split('.').next().unwrap().to_owned();
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload("wrong-user")).unwrap());
    assert!(
        plugin
            .verify_jwt(&parts.join("."), None, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
    for malformed in ["", "two.parts", "a.b.c", "a.b.c.d"] {
        assert!(
            plugin
                .verify_jwt(malformed, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        plugin
            .verify_jwt(&token, Some("wrong-issuer"), None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn signing_normalizes_jose_numeric_dates_and_rejects_invalid_claim_types() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    for (expiry, seconds) in [
        ("1m", 60.0),
        (" 1.5 minutes", 90.0),
        ("+1 hr", 3600.0),
        ("1 minute ago", -60.0),
        ("1 minute AGO", 60.0),
        ("1 year from now", 31557600.0),
        ("-0.5 secs", -1.0),
    ] {
        let before = Utc::now().timestamp() as f64;
        let mut claims = payload("subject");
        let _ = claims.insert("exp".to_owned(), json!(expiry));
        let token = plugin
            .sign_jwt(claims, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let after = Utc::now().timestamp() as f64;
        let expiry = decoded(&token).1["exp"].as_f64().unwrap();
        assert!(expiry >= before + seconds && expiry <= after + seconds);
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_some(),
            seconds > 0.0,
        );
    }
    for overrides in [
        json!({"exp":"invalid"}),
        json!({"exp":"+1m ago"}),
        json!({"exp":false}),
        json!({"iat":true}),
        json!({"nbf":true}),
        json!({"iss":123}),
        json!({"sub":123}),
        json!({"jti":true}),
        json!({"aud":[ctx.config.base_url,123]}),
    ] {
        let mut claims = payload("subject");
        claims.extend(overrides.as_object().unwrap().clone());
        assert!(
            plugin
                .sign_jwt(claims, &JwtSignOptions::default(), None, &ctx)
                .await
                .is_err()
        );
    }
    // Falsy optional claims are retained by the pinned signer rather than sent
    // to JOSE's setters; its verifier still checks NumericDate types.
    let token = plugin
        .sign_jwt(
            json!({"sub":"subject","iat":null,"jti":false})
                .as_object()
                .unwrap()
                .clone(),
            &JwtSignOptions::default(),
            None,
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(decoded(&token).1["jti"], false);
    assert!(
        plugin
            .verify_jwt(&token, None, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn signing_and_verification_enforce_jose_headers_and_externally_signed_claims() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    let key = plugin
        .resolve_signing_key(&JwtSignOptions::default(), None, &ctx)
        .await
        .unwrap()
        .unwrap();
    let claims = json!({"sub":"subject","exp":4102444800_i64,"iss":ctx.config.base_url,"aud":ctx.config.base_url});
    for (header, signs, verifies) in [
        (json!({}), true, true),
        (json!({"crit":["unknown"],"unknown":true}), false, false),
        (json!({"crit":[]}), false, false),
        (json!({"crit":["b64"]}), false, false),
        (json!({"crit":["b64"],"b64":false}), false, false),
        (json!({"crit":["b64"],"b64":true}), true, true),
        (json!({"crit":["b64","b64"],"b64":true}), false, true),
        (json!({"b64":false}), true, true),
    ] {
        let mut header = header.as_object().unwrap().clone();
        let options = JwtSignOptions {
            header: header.clone(),
            ..Default::default()
        };
        assert_eq!(
            plugin
                .sign_jwt(claims.as_object().unwrap().clone(), &options, None, &ctx)
                .await
                .is_ok(),
            signs
        );
        let _ = header.insert("alg".to_owned(), json!(key.algorithm.as_str()));
        let _ = header.insert("kid".to_owned(), json!(key.key_id));
        // Use the key directly to create a cryptographically valid JWT even
        // when the public signer correctly refuses its extension header.
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = crypto::sign(key.algorithm, &key.private_key, input.as_bytes()).unwrap();
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_some(),
            verifies
        );
    }
    // JOSE verifies the signature and the pinned helper then applies JS
    // truthiness to sub. Preserve this upstream behavior for externally signed
    // tokens, including truthy JSON values the built-in signer refuses.
    for (subject, verifies) in [
        (json!(123), true),
        (json!(true), true),
        (json!([]), true),
        (json!({}), true),
        (json!(false), false),
        (Value::Null, false),
        (json!(""), false),
    ] {
        let mut claims = claims.as_object().unwrap().clone();
        let _ = claims.insert("sub".to_owned(), subject);
        let header = json!({"alg":key.algorithm.as_str(),"kid":key.key_id});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = crypto::sign(key.algorithm, &key.private_key, input.as_bytes()).unwrap();
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_some(),
            verifies
        );
    }
    for invalid in [
        json!({"iat":"invalid"}),
        json!({"exp":"1m"}),
        json!({"nbf":true}),
    ] {
        let mut claims = claims.as_object().unwrap().clone();
        claims.extend(invalid.as_object().unwrap().clone());
        let header = json!({"alg":key.algorithm.as_str(),"kid":key.key_id});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = crypto::sign(key.algorithm, &key.private_key, input.as_bytes()).unwrap();
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn verification_imports_persisted_jwk_metadata_as_the_pinned_runtime_does() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    let (public, private) = crypto::generate(&JwtKeyPairConfig::default()).unwrap();
    let claims = json!({"sub":"subject","exp":4102444800_i64,"iss":ctx.config.base_url,"aud":ctx.config.base_url});
    for (index, (metadata, verifies)) in [
        (json!({}), true),
        (json!({"ext":false}), true),
        (json!({"key_ops":["verify"]}), true),
        // importJWK removes alg and use before WebCrypto imports the key.
        (json!({"alg":"HS256","use":"enc"}), true),
        (json!({"kty":"EC"}), false),
        (json!({"crv":"P-256"}), false),
        (json!({"ext":"false"}), false),
        (json!({"key_ops":[]}), false),
        (json!({"key_ops":["sign"]}), false),
        (json!({"key_ops":["verify","verify"]}), false),
        (json!({"d":private["d"]}), false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut material = public.as_object().unwrap().clone();
        material.extend(metadata.as_object().unwrap().clone());
        let key = ctx
            .database
            .create_jwk(CreateJwk {
                id: Some(format!("metadata-{index}")),
                public_key: serde_json::to_string(&material).unwrap(),
                private_key: serde_json::to_string(&private).unwrap(),
                created_at: Utc::now(),
                expires_at: None,
                alg: Some("EdDSA".to_owned()),
                crv: Some("Ed25519".to_owned()),
            })
            .await
            .unwrap();
        let header = json!({"alg":"EdDSA","kid":key.id});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = crypto::sign(JwtAlgorithm::EdDsa, &private, input.as_bytes()).unwrap();
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_some(),
            verifies
        );
    }
}

#[tokio::test]
async fn all_official_algorithms_generate_sign_and_verify_with_matching_jwks() {
    for algorithm in [
        JwtAlgorithm::EdDsa,
        JwtAlgorithm::Es256,
        JwtAlgorithm::Es512,
        JwtAlgorithm::Rs256,
        JwtAlgorithm::Ps256,
    ] {
        let ctx = test_helpers::create_test_context().await;
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            key_pair: JwtKeyPairConfig {
                algorithm,
                modulus_length: None,
            },
            ..Default::default()
        });
        let claims = json!({ "sub": "subject", "iat": 100, "exp": 4102444800_i64 })
            .as_object()
            .unwrap()
            .clone();
        let token = plugin
            .sign_jwt(claims.clone(), &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        let (header, _) = decoded(&token);
        assert_eq!(header["alg"], algorithm.as_str());
        let repeated = plugin
            .sign_jwt(claims, &JwtSignOptions::default(), None, &ctx)
            .await
            .unwrap();
        assert_eq!(decoded(&token), decoded(&repeated));
        if matches!(algorithm, JwtAlgorithm::EdDsa | JwtAlgorithm::Rs256) {
            assert_eq!(token, repeated);
        } else {
            // Pinned WebCrypto uses fresh ECDSA nonces and PSS salt even when
            // the exact protected header and claims are signed twice.
            assert_ne!(token, repeated);
        }
        assert!(
            plugin
                .verify_jwt(&token, None, None, &ctx)
                .await
                .unwrap()
                .is_some()
        );
        let key = ctx
            .database
            .get_jwk_by_id(header["kid"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.alg.as_deref(), Some(algorithm.as_str()));
        assert_eq!(key.crv.as_deref(), algorithm.curve());
    }
}

#[tokio::test]
async fn rotation_keeps_public_keys_for_grace_and_pinning_never_silently_changes_keys() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::with_config(JwtPluginConfig {
        grace_period: Duration::hours(2),
        ..Default::default()
    });
    let (public, private) = crypto::generate(&JwtKeyPairConfig::default()).unwrap();
    let old = ctx
        .database
        .create_jwk(CreateJwk {
            id: Some("expired-key".to_owned()),
            public_key: serde_json::to_string(&public).unwrap(),
            private_key: serde_json::to_string(
                &encrypt(
                    &serde_json::to_string(&private).unwrap(),
                    &ctx.config.secret,
                )
                .unwrap(),
            )
            .unwrap(),
            created_at: Utc::now() - Duration::days(1),
            expires_at: Some(Utc::now() - Duration::hours(1)),
            alg: Some("EdDSA".to_owned()),
            crv: Some("Ed25519".to_owned()),
        })
        .await
        .unwrap();
    let old_token = plugin
        .sign_resolved(
            plugin
                .default_claims(payload("old-subject"), None, &ctx)
                .unwrap(),
            &JwtSignOptions::default(),
            &ResolvedJwtSigningKey {
                algorithm: JwtAlgorithm::EdDsa,
                key_id: old.id.clone(),
                private_key: private,
            },
        )
        .unwrap();
    let current_token = plugin
        .sign_jwt(
            payload("new-subject"),
            &JwtSignOptions::default(),
            None,
            &ctx,
        )
        .await
        .unwrap();
    assert_ne!(decoded(&current_token).0["kid"], old.id);
    let jwks = plugin
        .jwks(
            &test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None),
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&jwks.body).unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(
        plugin
            .verify_jwt(&old_token, None, None, &ctx)
            .await
            .unwrap()
            .is_some()
    );
    let beyond_grace = JwtPlugin::with_config(JwtPluginConfig {
        grace_period: Duration::seconds(1),
        ..Default::default()
    });
    let jwks = beyond_grace
        .jwks(
            &test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None),
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&jwks.body).unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Server verification deliberately reads the keyring, even after the
    // public endpoint's grace window has ended, matching the pinned runtime.
    assert!(
        beyond_grace
            .verify_jwt(&old_token, None, None, &ctx)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        plugin
            .sign_jwt(
                payload("subject"),
                &JwtSignOptions {
                    signing_key_id: Some(old.id),
                    ..Default::default()
                },
                None,
                &ctx
            )
            .await
            .is_err()
    );
    assert!(
        plugin
            .sign_jwt(
                payload("subject"),
                &JwtSignOptions {
                    signing_key_id: Some("missing".to_owned()),
                    ..Default::default()
                },
                None,
                &ctx
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn explicit_algorithm_lazy_mints_only_configured_keys_and_default_uses_primary() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::with_config(JwtPluginConfig {
        additional_key_pairs: vec![JwtKeyPairConfig {
            algorithm: JwtAlgorithm::Es256,
            modulus_length: None,
        }],
        ..Default::default()
    });
    let extra = plugin
        .sign_jwt(
            payload("extra"),
            &JwtSignOptions {
                signing_algorithm: Some(JwtAlgorithm::Es256),
                header: json!({"typ":"logout+jwt"}).as_object().unwrap().clone(),
                ..Default::default()
            },
            None,
            &ctx,
        )
        .await
        .unwrap();
    assert_eq!(decoded(&extra).0["alg"], "ES256");
    assert_eq!(decoded(&extra).0["typ"], "logout+jwt");
    // A primary key is provisioned explicitly because upstream's unpinned
    // fallback uses a previously provisioned live extra key when none exists.
    plugin.create_jwk(None, None, &ctx).await.unwrap();
    let primary = plugin
        .sign_jwt(payload("primary"), &JwtSignOptions::default(), None, &ctx)
        .await
        .unwrap();
    assert_eq!(decoded(&primary).0["alg"], "EdDSA");
    assert!(
        plugin
            .sign_jwt(
                payload("unconfigured"),
                &JwtSignOptions {
                    signing_algorithm: Some(JwtAlgorithm::Rs256),
                    ..Default::default()
                },
                None,
                &ctx
            )
            .await
            .is_err()
    );
    let extra_id = decoded(&extra).0["kid"].as_str().unwrap().to_owned();
    assert!(
        plugin
            .sign_jwt(
                payload("mismatch"),
                &JwtSignOptions {
                    signing_key_id: Some(extra_id),
                    signing_algorithm: Some(JwtAlgorithm::EdDsa),
                    ..Default::default()
                },
                None,
                &ctx
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn session_payload_header_hook_and_server_only_endpoints_have_distinct_authority() {
    let ctx = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::new();
    let (user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new().with_email("jwt@fixture.test"),
        Duration::days(1),
    )
    .await;
    let mut request =
        test_helpers::create_auth_request_no_query(HttpMethod::Get, "/token", None, None);
    assert!(matches!(
        plugin.session_token(&request, &ctx).await,
        Err(AuthError::Upstream { status: 401, .. })
    ));
    request.headers.insert(
        "cookie".to_owned(),
        better_auth_core::utils::cookie_utils::create_session_cookie(&session.token, &ctx.config)
            .split(';')
            .next()
            .unwrap()
            .to_owned(),
    );
    let token = plugin.session_token(&request, &ctx).await.unwrap();
    let claims = plugin
        .verify_jwt(&token, None, None, &ctx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claims["sub"], user.id);
    assert_eq!(claims["email"], user.email.as_deref().unwrap());
    request.path = "/get-session".to_owned();
    let mut response = AuthResponse::json(200, &json!({"session":session,"user":user})).unwrap();
    response
        .headers
        .insert("access-control-expose-headers", "existing, set-auth-jwt");
    let response = plugin
        .after_request(&request, &ctx, response)
        .await
        .unwrap();
    assert_eq!(
        response
            .headers
            .get("access-control-expose-headers")
            .unwrap(),
        "existing, set-auth-jwt"
    );
    assert!(
        plugin
            .verify_jwt(
                response.headers.get("set-auth-jwt").unwrap(),
                None,
                None,
                &ctx
            )
            .await
            .unwrap()
            .is_some()
    );
    let disabled = JwtPlugin::with_config(JwtPluginConfig {
        disable_setting_jwt_header: true,
        ..Default::default()
    });
    let response = disabled
        .after_request(&request, &ctx, AuthResponse::new(200))
        .await
        .unwrap();
    assert!(response.headers.get("set-auth-jwt").is_none());
    for path in ["/sign-jwt", "/verify-jwt", "/jwt/sign", "/jwt/verify"] {
        assert!(
            plugin
                .on_request(
                    &test_helpers::create_auth_request_no_query(HttpMethod::Post, path, None, None),
                    &ctx
                )
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        <JwtPlugin as AuthPlugin<TestSchema>>::routes(&plugin).len(),
        2
    );
}

struct ApplicationClaims;

#[async_trait]
impl DefineJwtPayload for ApplicationClaims {
    async fn define_payload(&self, session: &JwtSession) -> AuthResult<Map<String, Value>> {
        Ok(
            json!({"purpose":"application","ownerId":session.user.id,"loginId":session.session.id})
                .as_object()
                .unwrap()
                .clone(),
        )
    }
}

struct ApplicationSubject(Option<String>);

#[async_trait]
impl DefineJwtSubject for ApplicationSubject {
    async fn subject(&self, _session: &JwtSession) -> AuthResult<Option<String>> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn application_session_callbacks_replace_default_claims_and_preserve_subject_fallback() {
    let ctx = test_helpers::create_test_context().await;
    let (user, session) = test_helpers::create_user_and_session(
        &ctx,
        CreateUser::new()
            .with_email("callback-owner@fixture.test")
            .with_name("Private name"),
        Duration::hours(1),
    )
    .await;
    let request = test_helpers::create_auth_request_no_query(
        HttpMethod::Get,
        "/token",
        Some(&session.token),
        None,
    );
    for subject in [Some("application-subject".to_owned()), None] {
        let plugin = JwtPlugin::with_config(JwtPluginConfig {
            define_payload: Some(Arc::new(ApplicationClaims)),
            define_subject: Some(Arc::new(ApplicationSubject(subject.clone()))),
            ..Default::default()
        });
        let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
        assert_eq!(response.status, 200);
        let response: Value = serde_json::from_slice(&response.body).unwrap();
        let claims = plugin
            .verify_jwt(response["token"].as_str().unwrap(), None, None, &ctx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claims["purpose"], "application");
        assert_eq!(claims["ownerId"], user.id);
        assert_eq!(claims["loginId"], session.id);
        assert_eq!(claims["sub"], subject.as_deref().unwrap_or(&user.id));
        assert!(!claims.contains_key("email"));
        assert!(!claims.contains_key("name"));
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            900
        );
    }
}

struct ApplicationKeyring {
    database: Arc<dyn better_auth_core::AuthStore<TestSchema>>,
}

#[async_trait]
impl JwtKeyring for ApplicationKeyring {
    async fn keys(&self, _request: Option<&AuthRequest>) -> AuthResult<Vec<Jwk>> {
        self.database.list_jwks().await
    }
    async fn create_key(
        &self,
        mut key: CreateJwk,
        request: Option<&AuthRequest>,
    ) -> AuthResult<Jwk> {
        if request.map(AuthRequest::path) != Some("/jwks") {
            return Err(AuthError::forbidden(
                "Application key provisioning requires its public key request",
            ));
        }
        key.id = Some("application-signing-key".to_owned());
        self.database.create_jwk(key).await
    }
}

#[tokio::test]
async fn application_keyring_persists_and_resolves_keys_outside_auth_storage() {
    let ctx = test_helpers::create_test_context().await;
    let application_keys = test_helpers::create_test_context().await;
    let plugin = JwtPlugin::with_config(JwtPluginConfig {
        keyring: Some(Arc::new(ApplicationKeyring {
            database: application_keys.database.clone(),
        })),
        ..Default::default()
    });
    let request = test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None);
    let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 200);
    let public: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(public["keys"][0]["kid"], "application-signing-key");
    let options = JwtSignOptions {
        signing_key_id: Some("application-signing-key".to_owned()),
        ..Default::default()
    };
    let token = plugin
        .sign_jwt(payload("external-key-owner"), &options, None, &ctx)
        .await
        .unwrap();
    let (header, claims) = decoded(&token);
    assert_eq!(header["kid"], "application-signing-key");
    assert_eq!(
        plugin
            .verify_jwt(&token, None, None, &ctx)
            .await
            .unwrap()
            .unwrap(),
        claims.as_object().unwrap().clone()
    );
    assert!(ctx.database.list_jwks().await.unwrap().is_empty());
    let persisted = application_keys.database.list_jwks().await.unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].id, "application-signing-key");
    assert!(!persisted[0].private_key.contains("\"d\""));
    let private = decrypt(
        &serde_json::from_str::<String>(&persisted[0].private_key).unwrap(),
        &ctx.config.secret,
    )
    .unwrap();
    assert!(serde_json::from_str::<Value>(&private).unwrap()["d"].is_string());
    assert!(
        JwtPlugin::new()
            .verify_jwt(&token, None, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
}

struct ApplicationSigner {
    context: AuthContext<TestSchema>,
    plugin: JwtPlugin,
}

#[async_trait]
impl SignRemoteJwt for ApplicationSigner {
    async fn sign(
        &self,
        payload: &Map<String, Value>,
        options: &JwtSignOptions,
    ) -> AuthResult<String> {
        self.plugin
            .sign_jwt(payload.clone(), options, None, &self.context)
            .await
    }
}

#[tokio::test]
async fn delegated_signing_uses_external_keys_and_preserves_explicit_payload_and_headers() {
    let ctx = test_helpers::create_test_context().await;
    let service = Arc::new(ApplicationSigner {
        context: test_helpers::create_test_context().await,
        plugin: JwtPlugin::new(),
    });
    let plugin = JwtPlugin::with_config(JwtPluginConfig {
        remote_url: Some("https://keys.fixture.test/jwks".to_owned()),
        remote_signer: Some(service.clone()),
        ..Default::default()
    });
    let options = JwtSignOptions {
        header: json!({"typ":"application+jwt"})
            .as_object()
            .unwrap()
            .clone(),
        ..Default::default()
    };
    let explicit = json!({"sub":"delegated-owner","permission":"read","iat":Utc::now().timestamp(),"exp":Utc::now().timestamp()+600}).as_object().unwrap().clone();
    let token = plugin
        .sign_jwt(explicit.clone(), &options, None, &ctx)
        .await
        .unwrap();
    let (header, claims) = decoded(&token);
    assert_eq!(header["typ"], "application+jwt");
    for (name, value) in explicit {
        assert_eq!(claims[&name], value);
    }
    assert_eq!(claims["iss"], ctx.config.base_url);
    assert_eq!(claims["aud"], ctx.config.base_url);
    assert_eq!(
        service
            .plugin
            .verify_jwt(&token, None, None, &service.context)
            .await
            .unwrap()
            .unwrap(),
        claims.as_object().unwrap().clone()
    );
    assert!(ctx.database.list_jwks().await.unwrap().is_empty());
    assert_eq!(service.context.database.list_jwks().await.unwrap().len(), 1);
    let request = test_helpers::create_auth_request_no_query(HttpMethod::Get, "/jwks", None, None);
    let response = plugin.on_request(&request, &ctx).await.unwrap().unwrap();
    assert_eq!(response.status, 404);
    assert!(response.body.is_empty());
    // The reference verifier reads its configured keyring; remoteUrl does not
    // substitute external keys for the local verification adapter.
    assert!(
        plugin
            .verify_jwt(&token, None, None, &ctx)
            .await
            .unwrap()
            .is_none()
    );
    let invalid = JwtPlugin::with_config(JwtPluginConfig {
        remote_signer: Some(service),
        ..Default::default()
    });
    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    assert!(invalid.on_init(&mut init).await.is_err());
}
