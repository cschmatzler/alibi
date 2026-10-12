//! Logical account linking binds a real OAuth proof to the verified session owner.
use super::server_revocation_support::{Observer, options};
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::{OAuthPlugin, oauth::GenericOAuthConfig};
use base64::Engine;
use sha2::{Digest, Sha256};

backend_tests!(server_link_social_account_preserves_owner_and_redeems_bound_pkce);

async fn server_link_social_account_preserves_owner_and_redeems_bound_pkce<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    remote.respond_at("/token",200,json!({"access_token":"generic-access","refresh_token":"generic-refresh","expires_in":3600}));
    let mut provider = GenericOAuthConfig::new("native-client", "native-secret");
    provider.provider.scopes = vec!["profile".into()];
    provider.authorization_url = Some(remote.url.join("authorize")?.into());
    provider.token_url = Some(remote.url.join("token")?.into());
    provider.user_info_url = Some(remote.url.join("profile")?.into());
    let observer = Observer::new("linkSocialAccount", "/link-social");
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            OAuthPlugin::new().add_provider("generic", provider.resolve().await?.unwrap().provider),
        )
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let owner = signup(&auth, "logical-link-owner@example.test").await;
    let foreign = signup(&auth, "logical-link-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for (body, options, status) in [
        (
            json!({"provider":"generic"}),
            EndpointOptions::default(),
            400,
        ),
        (
            json!({"provider":"generic"}),
            EndpointOptions {
                headers: Some(Default::default()),
                ..Default::default()
            },
            401,
        ),
        (json!({}), options(&owner), 400),
        (json!({"provider":7}), options(&owner), 400),
        (
            json!({"provider":"generic","scopes":7}),
            options(&owner),
            400,
        ),
        (
            json!({"provider":"generic","disableRedirect":null}),
            options(&owner),
            400,
        ),
        (
            json!({"provider":"generic","additionalParams":{"state":"injected"}}),
            options(&owner),
            400,
        ),
        (json!({"provider":"missing-provider"}), options(&owner), 404),
        (
            json!({"provider":"generic","idToken":{"token":"unsupported"}}),
            options(&owner),
            404,
        ),
    ] {
        let denied = Box::pin(auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth", "linkSocialAccount").with_body(&body)?,
            options,
        ))
        .await
        .unwrap_err();
        assert_eq!(denied.error.status_code(), status);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
        assert!(remote.take().is_empty());
    }
    let mut redeem = None;
    for (round, disable) in [true, false].into_iter().enumerate() {
        let callback = if round == 0 {
            "/linked-logical"
        } else {
            "https://external.example.test/linked"
        };
        let body = json!({"provider":"generic","callbackURL":callback,"errorCallbackURL":callback,"disableRedirect":disable,"requestSignUp":true,
            "scopes":["profile","calendar"],"loginHint":"Owner+link@example.test","additionalParams":{"prompt":"consent :+&"},"additionalData":{"application":"linked","nested":{"round":round}},
            "userId":foreign_id,"link":{"userId":foreign_id,"email":"logical-link-foreign@example.test"},"authorizationParams":{"state":"ignored-field"}});
        let mut input = options(&owner);
        _ = input
            .headers
            .as_mut()
            .unwrap()
            .insert("origin".into(), "https://untrusted.example.test".into());
        let started_at = chrono::Utc::now().timestamp_millis();
        let typed: alibi::plugins::oauth::OAuthLinkSocialRequest =
            serde_json::from_value(body.clone())?;
        let response = Box::pin(auth.dispatch_endpoint(
            OAuthPlugin::link_social_account_endpoint(&typed)?.with_body(&body)?,
            input,
        ))
        .await?;
        let finished_at = chrono::Utc::now().timestamp_millis();
        let value = serde_json::to_value(response.decode()?)?;
        let url = url::Url::parse(value["url"].as_str().unwrap())?;
        let params = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(value["redirect"], !disable);
        assert_eq!(
            response.headers().get("location").map(String::as_str),
            (!disable).then(|| url.as_str())
        );
        assert_eq!(params["scope"], "profile calendar profile");
        assert_eq!(params["login_hint"], "Owner+link@example.test");
        assert_eq!(params["prompt"], "consent :+&");
        let proofs: Vec<Value> = serde_json::from_str(&db.table("verifications").await?)?;
        let proof = proofs
            .iter()
            .find(|p| p["identifier"] == format!("auth-state:{}", params["state"]))
            .unwrap();
        let payload: Value = serde_json::from_str(proof["value"].as_str().unwrap())?;
        let verifier = payload["codeVerifier"].as_str().unwrap();
        assert_eq!(verifier.len(), 128);
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        );
        assert_eq!(params["state"].len(), 32);
        assert!(
            params["state"]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        );
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes())),
            params["code_challenge"]
        );
        assert_eq!(
            payload,
            json!({"callbackURL":callback,"errorURL":callback,"requestSignUp":true,"application":"linked","nested":{"round":round},
            "link":{"userId":owner_id,"email":"logical-link-owner@example.test"},"codeVerifier":verifier,"oauthState":params["state"],"expiresAt":payload["expiresAt"]})
        );
        let window = started_at + 600_000..=finished_at + 600_000;
        assert!(window.contains(&payload["expiresAt"].as_i64().unwrap()));
        assert!(
            window.contains(
                &chrono::DateTime::parse_from_rfc3339(proof["expires_at"].as_str().unwrap())?
                    .timestamp_millis()
            )
        );
        for field in ["created_at", "updated_at"] {
            let timestamp = chrono::DateTime::parse_from_rfc3339(proof[field].as_str().unwrap())?
                .timestamp_millis();
            assert!((started_at..=finished_at).contains(&timestamp));
        }
        let state_cookie = response
            .headers()
            .get_all("set-cookie")
            .find(|c| c.starts_with("better-auth.state="))
            .unwrap();
        let encoded = state_cookie
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        assert_eq!(
            alibi::utils::cookie_utils::verify_cookie_value(encoded, SECRET).as_deref(),
            Some(params["state"].as_str())
        );
        assert_eq!(
            db.tables(&["users", "accounts", "sessions"]).await?,
            before[..3]
        );
        assert!(remote.take().is_empty());
        if round == 0 {
            redeem = Some((
                params["state"].clone(),
                verifier.to_owned(),
                state_cookie.split(';').next().unwrap().to_owned(),
            ));
        }
    }
    let (state, verifier, cookie) = redeem.unwrap();
    remote.respond_at("/profile",200,json!({"id":"logical-linked-subject","email":"logical-link-owner@example.test","name":"Remote linked profile","email_verified":true}));
    let mut incoming = request("/callback/generic", None, &cookie);
    incoming.set_query_pairs([("code", "logical-link-code"), ("state", state.as_str())]);
    let linked = call(&auth, incoming.clone(), 302).await;
    assert_eq!(
        linked.headers.get("location").map(String::as_str),
        Some("/linked-logical")
    );
    assert_eq!(
        db.tables(&["users", "sessions"]).await?,
        vec![before[0].clone(), before[2].clone()]
    );
    let accounts: Vec<Value> = serde_json::from_str(&db.table("accounts").await?)?;
    let old: Vec<Value> = serde_json::from_str(&before[1])?;
    assert_eq!(accounts.len(), old.len() + 1);
    for prior in old {
        assert!(accounts.contains(&prior));
    }
    let added = accounts
        .iter()
        .find(|a| a["provider_id"] == "generic")
        .unwrap();
    assert_eq!(added["user_id"], owner_id);
    assert_eq!(added["account_id"], "logical-linked-subject");
    assert_eq!(added["access_token"], "generic-access");
    assert_eq!(added["refresh_token"], "generic-refresh");
    let sent = remote.take();
    let grant = sent.iter().find(|s| s.path == "/token").unwrap();
    let form = url::form_urlencoded::parse(&grant.body)
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(form["code"], "logical-link-code");
    assert_eq!(form["code_verifier"], verifier);
    let stable = db.tables(&["users", "accounts", "sessions"]).await?;
    drop(call(&auth, incoming, 302).await);
    assert_eq!(db.tables(&["users", "accounts", "sessions"]).await?, stable);
    assert!(remote.take().is_empty());
    assert_eq!(
        observer
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.as_deref() == Some(owner_id.as_str()))
            .count(),
        4
    );
    B::close(connection).await
}
