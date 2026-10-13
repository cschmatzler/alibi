//! Direct OAuth initiation owns signed state and usable PKCE proofs.
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthPlugin, oauth::GenericOAuthConfig};
use base64::Engine;
use sha2::{Digest, Sha256};

backend_tests!(server_sign_in_social_issues_owned_state_and_pkce_without_fabricating_a_request);

async fn server_sign_in_social_issues_owned_state_and_pkce_without_fabricating_a_request<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    remote.respond_at(
        "/token",
        200,
        json!({"access_token":"social-access","refresh_token":"social-refresh","expires_in":3600}),
    );
    remote.respond_at("/profile",200,json!({"id":"logical-social-subject","email":"logical-social@example.test","name":"Logical Social","email_verified":true}));
    let mut provider = GenericOAuthConfig::new("native-client", "native-secret");
    provider.provider.scopes = vec!["profile".into()];
    provider.provider.authorization = Some(Default::default());
    provider.authorization_url = Some(remote.url.join("authorize")?.into());
    provider.token_url = Some(remote.url.join("token")?.into());
    provider.user_info_url = Some(remote.url.join("profile")?.into());
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            OAuthPlugin::new().add_provider("generic", provider.resolve().await?.unwrap().provider),
        )
        .build()
        .await?;
    let endpoint =
        |body: &Value| ServerEndpoint::<Value>::new("oauth", "signInSocial").with_body(body);
    let before = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    for (body, status) in [
        (json!({}), 400),
        (json!({"provider":7}), 400),
        (json!({"provider":"generic","scopes":7}), 400),
        (json!({"provider":"generic","disableRedirect":null}), 400),
        (
            json!({"provider":"generic","additionalParams":{"state":"injected"}}),
            400,
        ),
        (json!({"provider":"missing-provider"}), 404),
        (
            json!({"provider":"generic","idToken":{"token":"unsupported"}}),
            404,
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(endpoint(&body)?, EndpointOptions::default()))
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        if body.get("provider").is_none() || body["provider"] == 7 {
            let response = denied.error.to_auth_response();
            let error: Value = serde_json::from_slice(&response.body)?;
            assert_eq!(error["message"], "[body.provider] Invalid input");
        }
        assert_eq!(
            db.tables(&["user", "account", "session", "verification"])
                .await?,
            before
        );
        assert!(remote.take().is_empty());
    }
    let mut redeem = None;
    for (index, disable) in [true, false].into_iter().enumerate() {
        let callback = if index == 0 {
            "/logical-done"
        } else {
            "https://external.example.test/done"
        };
        let body = json!({"provider":"generic","callbackURL":callback,"newUserCallbackURL":callback,"errorCallbackURL":callback,"disableRedirect":disable,"scopes":["profile","calendar"],"loginHint":"Owner+hint@example.test","requestSignUp":true,"additionalParams":{"prompt":"consent :+&"},"additionalData":{"application":"owned","nested":{"round":index}},"authorizationParams":{"state":"ignored-unknown-field"}});
        let typed: alibi::plugins::oauth::OAuthSocialSignInRequest =
            serde_json::from_value(body.clone())?;
        let started_at = chrono::Utc::now().timestamp_millis();
        let result = Box::pin(
            auth.dispatch_endpoint(
                OAuthPlugin::sign_in_social_endpoint(&typed)?,
                EndpointOptions {
                    headers: Some(
                        [("origin".into(), "https://untrusted.example.test".into())]
                            .into_iter()
                            .collect(),
                    ),
                    ..Default::default()
                },
            ),
        )
        .await?;
        let finished_at = chrono::Utc::now().timestamp_millis();
        let value = serde_json::to_value(result.decode()?)?;
        let url = url::Url::parse(value["url"].as_str().unwrap())?;
        let params = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(value["redirect"], !disable);
        assert_eq!(
            result.headers().get("location").map(String::as_str),
            (!disable).then(|| url.as_str())
        );
        assert_eq!(params["client_id"], "native-client");
        assert_eq!(params["scope"], "profile calendar profile");
        assert_eq!(params["login_hint"], "Owner+hint@example.test");
        assert_eq!(params["prompt"], "consent :+&");
        assert_eq!(params["code_challenge_method"], "S256");
        let rows: Vec<Value> = serde_json::from_str(&db.table("verification").await?)?;
        let proof = rows
            .iter()
            .find(|row| row["identifier"] == format!("auth-state:{}", params["state"]))
            .unwrap();
        let payload: Value = serde_json::from_str(proof["value"].as_str().unwrap())?;
        let verifier = payload["codeVerifier"].as_str().unwrap();
        assert_eq!(verifier.len(), 128);
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes())),
            params["code_challenge"]
        );
        assert_eq!(
            payload,
            json!({
                "callbackURL": callback, "errorURL": callback, "newUserURL": callback,
                "codeVerifier": verifier, "oauthState": params["state"],
                "requestSignUp": true, "application": "owned", "nested": {"round": index},
                "expiresAt": payload["expiresAt"],
            })
        );
        let expires_at = payload["expiresAt"].as_i64().unwrap();
        assert!((started_at + 600_000..=finished_at + 600_000).contains(&expires_at));
        let stored_expiry =
            chrono::DateTime::parse_from_rfc3339(proof["expiresAt"].as_str().unwrap())?
                .timestamp_millis();
        assert!((started_at + 600_000..=finished_at + 600_000).contains(&stored_expiry));
        let fields = result
            .headers()
            .get_all("set-cookie")
            .cloned()
            .collect::<Vec<_>>();
        let state_cookie = fields
            .iter()
            .find(|cookie| cookie.starts_with("better-auth.state="))
            .unwrap();
        let encoded = state_cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        let signed = encoded;
        assert_eq!(
            alibi::utils::cookie_utils::verify_cookie_value(signed, SECRET).as_deref(),
            Some(params["state"].as_str())
        );
        assert_eq!(
            db.tables(&["user", "account", "session"]).await?,
            before[..3]
        );
        assert!(remote.take().is_empty());
        if index == 0 {
            redeem = Some((fields, params["state"].clone(), verifier.to_owned()));
        }
    }
    let (fields, state, verifier) = redeem.unwrap();
    let cookie = fields
        .iter()
        .map(|cookie| cookie.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    let mut incoming = request("/callback/generic", None, &cookie);
    incoming.set_query_pairs([("code", "logical-code"), ("state", state.as_str())]);
    let response = call(&auth, incoming, 302).await;
    assert_eq!(
        response.headers.get("location").map(String::as_str),
        Some("/logical-done")
    );
    authenticated(&auth, &cookies(&response), "logical-social@example.test").await;
    let sent = remote.take();
    let grant = sent
        .iter()
        .find(|exchange| exchange.path == "/token")
        .unwrap();
    let form = url::form_urlencoded::parse(&grant.body)
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(form["code_verifier"], verifier);
    assert_eq!(form["code"], "logical-code");

    B::close(connection).await
}
