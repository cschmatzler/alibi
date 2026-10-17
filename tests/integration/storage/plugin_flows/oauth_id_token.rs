//! A real authorization grant is consumed once, with PKCE and redirect binding.
use super::oauth_extension_claims::extension_claims;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{
    OAuthProviderConfig, OAuthProviderPlugin, OAuthTokenIssueParams, jwt::JwtPlugin,
};
use base64::Engine as _;
use sha2::Digest as _;
backend_tests!(
    oauth_openid_code_issues_verified_client_and_access_bound_id_token,
    oauth_openid_without_jwt_plugin_uses_decrypted_client_secret_and_omits_public_id_tokens
);
postgres_tests!(
    oauth_openid_without_jwt_plugin_uses_decrypted_client_secret_and_omits_public_id_tokens
);
async fn oauth_openid_code_issues_verified_client_and_access_bound_id_token<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let live = Arc::new(extension_claims::LiveIdTokenClaims::default());
    *live.value.lock().unwrap() = Some("code".into());
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        extensions: extension_claims::extensions_with_live(None),
        custom_id_token_claims: Some(live.clone()),
        ..Default::default()
    });
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(provider.clone())
        .build()
        .await?;
    let owner = signup(&auth, "oidc-owner@example.test").await;
    let headers = [
        ("cookie".into(), cookies(&owner)),
        ("accept".into(), "application/json".into()),
    ]
    .into_iter()
    .collect();
    let created = Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Token client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile","token_endpoint_auth_method":"none","skip_consent":true,"enable_end_session":true,"metadata":{"tenant":"application"}}))?, EndpointOptions {headers:Some(headers), ..Default::default()})).await?.into_response()?;
    assert_eq!(created.status, 201);
    let id = body(&created)["client_id"].as_str().unwrap().to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
    let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email profile","state":"token-state","nonce":"oidc-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
    let grant = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
            EndpointOptions {
                headers: Some(
                    [
                        ("cookie".into(), cookies(&owner)),
                        ("accept".into(), "application/json".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
                request: Some(request("/oauth2/authorize", None, "")),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(grant.status, 200);
    let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
    assert_eq!(callback.path(), "/callback");
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
    let endpoint =
        ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?;
    let output = Box::pin(auth.dispatch_endpoint(
        endpoint,
        EndpointOptions {
            request: Some(request("/oauth2/token", Some(input.clone()), "")),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    assert_eq!(output.status, 200);
    let token = body(&output);
    assert_eq!(token["scope"], "openid email profile");
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["expires_in"], 3600);
    let plaintext = token["access_token"].as_str().unwrap();
    assert_eq!(plaintext.len(), 32);
    assert!(plaintext.bytes().all(|b| b.is_ascii_alphabetic()));
    assert!(token.get("refresh_token").is_none());

    let id_token = token["id_token"]
        .as_str()
        .expect("openid must issue a signed ID token");
    let observed = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers: Some([("cookie".into(), cookies(&owner))].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    let issuer = format!(
        "{}{}",
        auth.context().config.base_url,
        auth.context().config.base_path
    );
    let verifier =
        alibi::plugins::jwt::JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
            claims: alibi::plugins::jwt::JwtClaimsConfig {
                issuer: Some(issuer.clone()),
                audience: Some(alibi::plugins::jwt::JwtAudience::One(id.clone())),
                ..Default::default()
            },
            ..Default::default()
        });
    let payload = verifier
        .verify_jwt(id_token, Some(&issuer), None, auth.context())
        .await?
        .expect("ID token must verify against the actual persisted JWK");
    assert_eq!(payload["iss"], issuer);
    assert_eq!(payload["aud"], id);
    assert_eq!(payload["sub"], body(&observed)["user"]["id"]);
    assert_eq!(payload["nonce"], "oidc-nonce");
    assert_eq!(payload["acr"], "0");
    let actual_time = chrono::DateTime::parse_from_rfc3339(
        body(&observed)["session"]["createdAt"].as_str().unwrap(),
    )?
    .timestamp();
    assert_eq!(payload["auth_time"], actual_time);
    assert_eq!(
        payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
        36_000
    );
    let digest = sha2::Sha512::digest(plaintext);
    let expected_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..32]);
    assert_eq!(payload["at_hash"], expected_hash);
    assert_eq!(payload.get("name"), Some(&json!("ID operator code")));
    assert_eq!(payload["email"], "id-code@example.test");
    assert_eq!(payload["email_verified"], true);
    assert_eq!(payload["extension_owner"], "id-operator-code");
    assert_eq!(payload["per_request"], "id-operator-code");
    assert_eq!(payload["sid"], body(&observed)["session"]["id"]);
    assert_eq!(
        payload["cnf"],
        json!({"operator":"code"}),
        "cnf is not in the reference ID reserved set"
    );
    for field in ["picture", "nbf", "jti", "amr", "azp", "c_hash", "s_hash"] {
        assert!(!payload.contains_key(field));
    }
    let parts = id_token.split('.').collect::<Vec<_>>();
    let mut signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;
    signature[0] ^= 1;
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    );
    assert!(
        verifier
            .verify_jwt(&tampered, Some(&issuer), None, auth.context())
            .await?
            .is_none()
    );
    let foreign =
        alibi::plugins::jwt::JwtPlugin::with_config(alibi::plugins::jwt::JwtPluginConfig {
            claims: alibi::plugins::jwt::JwtClaimsConfig {
                audience: Some(alibi::plugins::jwt::JwtAudience::One(
                    "foreign-client".into(),
                )),
                ..Default::default()
            },
            ..Default::default()
        });
    assert!(
        foreign
            .verify_jwt(id_token, Some(&issuer), None, auth.context())
            .await?
            .is_none()
    );
    let user_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let client = provider.get_client(auth.context(), &id).await?.unwrap();
    let user = auth.store().get_user_by_id(&user_id).await?.unwrap();
    let session_id = body(&observed)["session"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut params = OAuthTokenIssueParams::new(
        client,
        vec!["openid".into(), "email".into(), "profile".into()],
    );
    params.user = Some(auth.context().trusted_user_view(&user));
    params.session_id = Some(session_id.clone());
    params.auth_time = chrono::DateTime::from_timestamp(actual_time, 0);
    params.nonce = Some("api-nonce".into());
    params.id_token_claims = Some(
        json!({"name":"Request name","email":"request@example.test","extension_owner":"request","per_request":"request","request_only":"retained"}),
    );
    let call = alibi::endpoint::EndpointCall::new(
        &alibi::endpoint::EndpointDefinition {
            name: "idClaims",
            operation_id: "idClaims",
            path: None,
            method: HttpMethod::Post,
        },
        None,
        None,
        EndpointOptions::default(),
    );
    *live.value.lock().unwrap() = Some("api".into());
    let issued = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:id-claims"),
            &params,
        )
        .await?;
    let claims = verifier
        .verify_jwt(
            issued["id_token"].as_str().unwrap(),
            Some(&issuer),
            None,
            auth.context(),
        )
        .await?
        .unwrap();
    assert_eq!(claims["name"], "ID operator api");
    assert_eq!(claims["email"], "id-api@example.test");
    assert_eq!(claims["extension_owner"], "id-operator-api");
    assert_eq!(claims["per_request"], "id-operator-api");
    assert_eq!(claims["request_only"], "retained");
    assert_eq!(claims["nonce"], "api-nonce");
    assert_eq!(claims["sub"], user_id);
    assert_eq!(claims["sid"], session_id);
    for error in ["api", "ordinary"] {
        *live.error.lock().unwrap() = error.into();
        let before = auth
            .store()
            .list_oauth_tokens_for_session(alibi::store::OAuthTokenKind::Access, &session_id)
            .await?
            .len();
        let rejected = provider
            .issue_tokens(
                auth.context(),
                &call,
                Some("urn:fixture:id-claims"),
                &params,
            )
            .await
            .unwrap_err();
        if error == "api" {
            assert!(
                matches!(rejected.error, alibi::AuthError::Api {status:400,code:Some(ref code),ref message} if code=="ID_CLAIM_REJECTED" && message=="ID callback rejected")
            );
        } else {
            assert!(
                matches!(rejected.error, alibi::AuthError::Internal(ref message) if message=="ID callback failed")
            );
        }
        assert_eq!(
            auth.store()
                .list_oauth_tokens_for_session(alibi::store::OAuthTokenKind::Access, &session_id)
                .await?
                .len(),
            before + 1,
            "the ID operator runs after actual opaque access issuance even when it rejects"
        );
    }
    let calls = live.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            json!({"userId":user_id,"userName":"Native owner","userEmail":"oidc-owner@example.test","scopes":["openid","email","profile"],"metadata":{"tenant":"application"}});
            4
        ]
    );
    params.scopes = vec!["email".into()];
    let without_id = provider
        .issue_tokens(
            auth.context(),
            &call,
            Some("urn:fixture:id-claims"),
            &params,
        )
        .await?;
    assert!(without_id.get("id_token").is_none());
    assert_eq!(*live.calls.lock().unwrap(), calls);
    Ok(())
}

#[derive(Debug)]
struct IdTokenCipher;
const ID_TOKEN_CIPHER_KEY: &str = "application-client-secret-encryption-key-32-characters";
#[async_trait::async_trait]
impl alibi::plugins::OAuthClientSecretCipher for IdTokenCipher {
    async fn encrypt(&self, secret: &str) -> alibi::AuthResult<String> {
        Ok(format!(
            "custom:{}",
            alibi::plugins::oauth::encryption::encrypt_token(secret, ID_TOKEN_CIPHER_KEY)?
        ))
    }
    async fn decrypt(&self, stored: &str) -> alibi::AuthResult<String> {
        alibi::plugins::oauth::encryption::decrypt_token(
            stored.strip_prefix("custom:").unwrap(),
            ID_TOKEN_CIPHER_KEY,
        )
    }
}
async fn oauth_openid_without_jwt_plugin_uses_decrypted_client_secret_and_omits_public_id_tokens<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for (custom, public) in [(false, false), (true, false), (false, true)] {
        let prefix = if custom { "client_prefix_" } else { "" };
        let auth = super::auth_probe::fast_builder::<B>(&connection)
            .plugin(OAuthProviderPlugin::with_config(
                alibi::plugins::OAuthProviderConfig {
                    disable_jwt_plugin: true,
                    client_secret_prefix: custom.then(|| prefix.into()),
                    client_secret_cipher: custom.then(|| {
                        Arc::new(IdTokenCipher) as Arc<dyn alibi::plugins::OAuthClientSecretCipher>
                    }),
                    ..Default::default()
                },
            ))
            .build()
            .await?;
        let owner = signup(
            &auth,
            &format!("encrypted-id-{custom}-{public}@example.test"),
        )
        .await;
        let cookie = cookies(&owner);
        let options = || EndpointOptions {
            headers: Some(
                [
                    ("cookie".into(), cookie.clone()),
                    ("accept".into(), "application/json".into()),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        };
        let created=auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth-provider","adminCreateOAuthClient").with_body(&json!({"client_name":"Encrypted ID client","redirect_uris":["https://app.fixture.test/callback"],"scope":"openid email profile","token_endpoint_auth_method":if public{"none"}else{"client_secret_post"},"skip_consent":true}))?,options()).await?.into_response()?;
        assert_eq!(created.status, 201);
        let client = body(&created);
        let id = client["client_id"].as_str().unwrap();
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier));
        let query = json!({"client_id":id,"response_type":"code","redirect_uri":"https://app.fixture.test/callback","scope":"openid email profile","state":"encrypted-state","nonce":"encrypted-nonce","code_challenge":challenge,"code_challenge_method":"S256"});
        let grant = auth
            .dispatch_endpoint(
                OAuthProviderPlugin::oauth2_authorize_endpoint(&query)?,
                EndpointOptions {
                    request: Some(request("/oauth2/authorize", None, "")),
                    ..options()
                },
            )
            .await?
            .into_response()?;
        assert_eq!(grant.status, 200);
        let callback = url::Url::parse(body(&grant)["url"].as_str().unwrap())?;
        let code = callback
            .query_pairs()
            .find(|(name, _)| name == "code")
            .unwrap()
            .1
            .into_owned();
        let mut input = json!({"grant_type":"authorization_code","client_id":id,"code":code,"code_verifier":verifier,"redirect_uri":"https://app.fixture.test/callback"});
        if !public {
            input["client_secret"] = client["client_secret"].clone();
        }
        let output = auth
            .dispatch_endpoint(
                ServerEndpoint::<Value>::new("oauth-provider", "oauth2Token").with_body(&input)?,
                EndpointOptions {
                    request: Some(request("/oauth2/token", Some(input.clone()), "")),
                    ..Default::default()
                },
            )
            .await?
            .into_response()?;
        assert_eq!(
            output.status,
            200,
            "custom={custom} public={public}: {}",
            body(&output)
        );
        let token = body(&output);
        let access = token["access_token"].as_str().unwrap();
        assert_eq!(access.len(), 32);
        assert!(access.bytes().all(|byte| byte.is_ascii_alphabetic()));
        assert_eq!(token["token_type"], "Bearer");
        assert_eq!(token["scope"], "openid email profile");
        assert_eq!(
            output.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        if public {
            assert!(token.get("id_token").is_none());
            continue;
        }
        let secret = client["client_secret"]
            .as_str()
            .unwrap()
            .strip_prefix(prefix)
            .unwrap();
        let signed = token["id_token"].as_str().unwrap();
        let header = jsonwebtoken::decode_header(signed)?;
        assert_eq!(header.alg, jsonwebtoken::Algorithm::HS256);
        assert!(header.kid.is_none());
        assert!(header.typ.is_none());
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&[id]);
        validation.set_issuer(&[format!("{ORIGIN}/api/auth")]);
        let key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
        let payload = jsonwebtoken::decode::<Value>(signed, &key, &validation)?.claims;
        assert_eq!(payload["sub"], body(&owner)["user"]["id"]);
        assert_eq!(payload["nonce"], "encrypted-nonce");
        assert_eq!(payload["acr"], "0");
        assert_eq!(
            payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
            36000
        );
        let digest = sha2::Sha256::digest(access);
        assert_eq!(
            payload["at_hash"],
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
        );
        assert!(
            jsonwebtoken::decode::<Value>(
                signed,
                &jsonwebtoken::DecodingKey::from_secret(b"unrelated-client-secret"),
                &validation
            )
            .is_err()
        );
    }
    assert!(serde_json::from_str::<Vec<Value>>(&db.table("jwks").await?)?.is_empty());
    B::close(connection).await
}
