//! Provider factory policy: client-ID lists, environments, credential modes and
//! profile rules that need no HTTP dispatch.
use super::oauth_profile_edges::{fetch, unsigned};
use super::oauth_profiles::FailedMapper;
use super::*;
use alibi::plugins::oauth::*;
use std::collections::HashMap;

fn form(exchange: &Exchange) -> HashMap<String, String> {
    let query = exchange.path.split_once('?').map_or("", |(_, query)| query);
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .chain(url::form_urlencoded::parse(&exchange.body).into_owned())
        .collect()
}

#[tokio::test]
async fn client_id_lists_reconfigure_every_transport_that_embeds_them() {
    let ids = || vec!["first".to_owned(), "second".to_owned()];
    let google = OAuthProvider::google("original", "secret").with_client_ids(ids());
    assert_eq!(google.client_id, "first");
    assert_eq!(google.additional_client_ids, ["second"]);
    assert_eq!(
        google.id_token.as_ref().unwrap().client_ids.as_deref(),
        Some(ids().as_slice())
    );
    assert!(
        OAuthProvider::google("a", "b")
            .with_client_ids(vec![])
            .client_id
            .is_empty()
    );

    let remote = Provider::start(
        "application/json",
        json!({"access_token":"wechat-access","refresh_token":"wechat-refresh","openid":"open-1","scope":"snsapi_login","expires_in":7200}).to_string(),
    )
    .await;
    let mut options = WeChatOptions::new("original", "wechat-secret");
    options.token_endpoint = Some(remote.url.join("token").unwrap().into());
    options.refresh_endpoint = Some(remote.url.join("refresh").unwrap().into());
    options.language = WeChatLanguage::English;
    let wechat = OAuthProvider::wechat_with_options(options).with_client_ids(ids());
    assert_eq!(
        wechat
            .authorization
            .as_ref()
            .unwrap()
            .literal_client_id
            .as_deref(),
        Some("first,second")
    );
    assert!(
        wechat
            .authorization_params
            .contains(&("lang".into(), "en".into()))
    );
    let tokens = wechat
        .authorization
        .as_ref()
        .unwrap()
        .authorization_code
        .as_ref()
        .unwrap()
        .0
        .validate_authorization_code(OAuthAuthorizationCodeContext {
            code: "wechat-code".into(),
            redirect_uri: "https://app.example/callback".into(),
            code_verifier: None,
            device_id: None,
        })
        .await
        .unwrap();
    assert_eq!(tokens.access_token.as_deref(), Some("wechat-access"));
    _ = wechat
        .refresh_access_token
        .as_ref()
        .unwrap()
        .refresh_access_token("old-refresh")
        .await
        .unwrap();
    let sent = remote.take();
    assert_eq!(sent.len(), 2);
    for exchange in &sent {
        assert_eq!(form(exchange)["appid"], "first,second", "{}", exchange.path);
    }

    let remote = Provider::start("application/json", json!({"user":{"user_id":"vk-1","email":"vk@example.test","first_name":"V","last_name":"K"}}).to_string()).await;
    let mut options = VkOptions::new("original", Some("vk-secret".into()));
    options.user_info_endpoint = Some(remote.url.join("profile").unwrap().into());
    let vk = OAuthProvider::vk_with_options(options).with_client_ids(ids());
    assert_eq!(
        vk.authorization
            .as_ref()
            .unwrap()
            .literal_client_id
            .as_deref(),
        None
    );
    _ = fetch(&vk, None).await.unwrap();
    assert_eq!(form(&remote.take()[0])["client_id"], "first,second");
    assert!(
        vk.get_user_info
            .as_ref()
            .unwrap()
            .configured_client_ids(&[])
            .is_some()
    );
    assert!(!vk.get_user_info.as_ref().unwrap().errors_are_exceptions());

    let github = OAuthProvider::github("client", "secret");
    let handler = github.get_user_info.as_ref().unwrap();
    assert!(handler.configured_client_ids(&ids()).is_none());
    assert!(handler.errors_are_exceptions());
}

#[test]
fn environments_languages_and_access_modes_select_endpoints_and_parameters() {
    let mut options = PayPalOptions::new("client", "secret");
    assert!(
        OAuthProvider::paypal_with_options(options.clone())
            .auth_url
            .contains("sandbox")
    );
    options.environment = PayPalEnvironment::Live;
    options.user_info_endpoint = None;
    let production = OAuthProvider::paypal_with_options(options);
    assert!(
        production.auth_url.starts_with("https://www.paypal.com"),
        "{}",
        production.auth_url
    );
    assert!(
        production
            .user_info_url
            .as_deref()
            .unwrap()
            .starts_with("https://api-m.paypal.com")
    );

    let mut options = SalesforceOptions::new("client", Some("secret".into()));
    options.environment = SalesforceEnvironment::Sandbox;
    assert!(
        OAuthProvider::salesforce_with_options(options)
            .auth_url
            .contains("test.salesforce.com")
    );

    for (access, expected) in [
        (DropboxAccessType::Offline, "offline"),
        (DropboxAccessType::Online, "online"),
        (DropboxAccessType::Legacy, "legacy"),
    ] {
        let mut options = DropboxOptions::new("client", Some("secret".into()));
        options.access_type = Some(access);
        assert!(
            OAuthProvider::dropbox_with_options(options)
                .authorization_params
                .contains(&("token_access_type".into(), expected.into()))
        );
    }
    let wechat = OAuthProvider::wechat("client", "secret");
    assert!(
        wechat
            .authorization_params
            .contains(&("lang".into(), "cn".into()))
    );

    let google = OAuthProvider::google("client", "secret")
        .with_hosted_domain("first.test")
        .with_hosted_domain("second.test");
    assert_eq!(google.hosted_domain.as_deref(), Some("second.test"));
    assert_eq!(
        google
            .authorization_params
            .iter()
            .filter(|(key, _)| key == "hd")
            .collect::<Vec<_>>(),
        [&("hd".to_owned(), "second.test".to_owned())]
    );
    assert!(
        OAuthProvider::gitlab("client", "secret")
            .auth_url
            .starts_with("https://gitlab.com/oauth")
    );

    let mut options = MicrosoftOptions::new("client", Some("secret".into()));
    options.profile_photo_size = MicrosoftProfilePhotoSize::Size64;
    options.profile_photo_endpoint = None;
    assert!(OAuthProvider::microsoft(options).is_ok());
}

#[test]
fn public_clients_without_a_secret_use_no_token_endpoint_credentials() {
    let none = |provider: OAuthProvider| {
        let policy = provider.authorization.as_ref().unwrap();
        [
            policy.token_endpoint_auth,
            policy.refresh_token_endpoint_auth,
        ]
        .contains(&Some(OAuthTokenEndpointAuth::None))
    };
    for (name, provider) in [
        ("cloudflare", OAuthProvider::cloudflare("client", None)),
        ("dropbox", OAuthProvider::dropbox("client", None)),
        ("huggingface", OAuthProvider::huggingface("client", None)),
        ("kakao", OAuthProvider::kakao("client", None)),
        ("kick", OAuthProvider::kick("client", None)),
        ("line", OAuthProvider::line("client", None)),
        ("linear", OAuthProvider::linear("client", None)),
        ("linkedin", OAuthProvider::linkedin("client", None)),
        ("naver", OAuthProvider::naver("client", None)),
        ("notion", OAuthProvider::notion("client", None)),
        ("paybin", OAuthProvider::paybin("client", None)),
        ("polar", OAuthProvider::polar("client", None)),
    ] {
        assert!(none(provider), "{name}");
    }
    let cognito = OAuthProvider::cognito(CognitoOptions::new(
        "client",
        None,
        "pool.example.test",
        "us-east-1",
        "pool",
    ))
    .unwrap();
    assert!(none(cognito));
}

#[test]
fn discord_default_avatars_follow_the_snowflake_or_discriminator() {
    let discord = OAuthProvider::discord("client", "secret");
    let map = discord.map_user_info.unwrap();
    let profile = |extra: Value| {
        let mut profile = json!({"id":"175928847299117063","email":"d@example.test","username":"user","avatar":null,"discriminator":"0"});
        for (key, value) in extra.as_object().unwrap() {
            profile[key] = value.clone();
        }
        map(profile)
    };
    assert_eq!(
        profile(json!({})).unwrap().image.as_deref(),
        Some("https://cdn.discordapp.com/embed/avatars/2.png")
    );
    assert_eq!(
        profile(json!({"discriminator":"1234"}))
            .unwrap()
            .image
            .as_deref(),
        Some("https://cdn.discordapp.com/embed/avatars/4.png")
    );
    assert_eq!(
        profile(json!({"avatar":"hash"})).unwrap().image.as_deref(),
        Some("https://cdn.discordapp.com/avatars/175928847299117063/hash.png")
    );
    assert_eq!(
        profile(json!({"avatar":"a_hash"}))
            .unwrap()
            .image
            .as_deref(),
        Some("https://cdn.discordapp.com/avatars/175928847299117063/a_hash.gif")
    );
    for (extra, expected) in [
        (json!({"discriminator":null}), "missing discriminator"),
        (
            json!({"id":"not-digits"}),
            "invalid Discord decimal snowflake",
        ),
        (json!({"id":""}), "invalid Discord decimal snowflake"),
        (
            json!({"discriminator":"x1"}),
            "invalid Discord discriminator",
        ),
        (json!({"avatar":5}), "missing avatar"),
    ] {
        assert_eq!(profile(extra).unwrap_err(), expected);
    }
}

#[test]
fn gitlab_admits_only_active_unlocked_accounts() {
    let gitlab = OAuthProvider::gitlab("client", "secret");
    let map = gitlab.map_user_info.unwrap();
    let profile = |extra: Value| {
        let mut profile = json!({"id":7,"state":"active","email":"g@example.test","name":"Git Lab","username":"gl"});
        for (key, value) in extra.as_object().unwrap() {
            profile[key] = value.clone();
        }
        map(profile)
    };
    assert_eq!(profile(json!({})).unwrap().id, "7");
    for locked in [json!(false), json!(0), json!(""), Value::Null] {
        assert!(profile(json!({"locked": locked})).is_ok(), "{locked}");
    }
    for locked in [json!(true), json!(1), json!("yes"), json!([]), json!({})] {
        assert_eq!(
            profile(json!({"locked": locked})).unwrap_err(),
            "GitLab account is inactive or locked",
            "{locked}"
        );
    }
    assert!(profile(json!({"state":"blocked"})).is_err());
    assert_eq!(
        profile(json!({"id":null})).unwrap_err(),
        "Missing GitLab account ID"
    );
}

#[tokio::test]
async fn github_profile_failures_report_the_response_body() {
    let remote = Provider::start("text/plain", "rate limited").await;
    remote.respond(403, "text/plain", "rate limited");
    let github = OAuthProvider::github_with_endpoints(
        "client",
        "secret",
        "https://github.example/authorize",
        "https://github.example/token",
        remote.url.join("user").unwrap().as_str(),
        remote.url.join("emails").unwrap().as_str(),
    );
    assert_eq!(
        fetch(&github, None).await.unwrap_err(),
        "GitHub user info request failed: rate limited"
    );
}

#[tokio::test]
async fn published_profile_handlers_reject_malformed_grants_and_failed_mappers() {
    let case = |name: &str| {
        super::oauth_profiles::profiles()
            .into_iter()
            .find(|case| case.name == name && case.variant == "default")
            .unwrap()
    };
    let remote = Provider::start("application/json", "{}").await;
    let twitch = case("twitch");
    let provider = (twitch.factory)(remote.url.as_str());
    for (token, expected) in [
        ("two.parts", "Invalid grant ID token"),
        ("e30..sig", "Invalid grant ID-token payload"),
        (&unsigned(&json!([1])), "Invalid grant ID-token claims"),
    ] {
        assert_eq!(
            fetch(&provider, Some(token.into())).await.unwrap_err(),
            expected
        );
    }
    assert_eq!(
        fetch(&provider, None).await.unwrap_err(),
        "Missing Twitch ID token"
    );

    let spotify = case("spotify");
    let mut profile = spotify.profile.clone();
    profile["images"] = json!({"0": {"url": "https://images.test/object-image"}});
    remote.respond(200, "application/json", profile.to_string());
    let response = fetch(&(spotify.factory)(remote.url.as_str()), None)
        .await
        .unwrap();
    assert_eq!(
        response.user.image.as_deref(),
        Some("https://images.test/object-image")
    );

    for name in ["salesforce", "vercel", "zoom"] {
        let case = case(name);
        remote.respond(200, "application/json", case.profile.to_string());
        let provider =
            (case.factory)(remote.url.as_str()).with_profile_mapper(Arc::new(FailedMapper));
        let error = fetch(&provider, None).await.unwrap_err();
        assert!(
            error.contains("Application profile rejected"),
            "{name}: {error}"
        );
        assert_eq!(
            error == "Application profile rejected",
            name == "salesforce",
            "{name}"
        );
    }

    let paypal = case("paypal");
    let mut profile = paypal.profile.clone();
    profile["sub"] = json!(5.0);
    remote.respond(200, "application/json", profile.to_string());
    let provider = (paypal.factory)(remote.url.as_str());
    let token = |sub: Value| unsigned(&json!({"sub": sub}));
    assert!(fetch(&provider, Some(token(json!(5)))).await.is_ok());
    assert_eq!(
        fetch(&provider, Some(token(json!(6)))).await.unwrap_err(),
        "PayPal ID-token subject mismatch"
    );
    assert_eq!(
        fetch(&provider, Some(token(json!("5")))).await.unwrap_err(),
        "PayPal ID-token subject mismatch"
    );
}

#[tokio::test]
async fn discovery_documents_with_unusable_links_are_ignored_or_skipped() {
    let remote = Provider::start("application/json", "{}").await;
    let configure = |discovery: Value| {
        remote.respond_at("/discovery", 200, discovery);
        let mut config = GenericOAuthConfig::new("client", "secret");
        config.discovery_url = Some(remote.url.join("discovery").unwrap().into());
        config.authorization_url = Some("https://idp.example/authorize".into());
        config.token_url = Some("https://idp.example/token".into());
        config
    };
    let ignored = configure(
        json!({"issuer":"not a url","end_session_endpoint":"https://idp.example/logout"}),
    )
    .resolve()
    .await
    .unwrap()
    .unwrap();
    assert!(ignored.metadata.end_session_endpoint.is_none());
    assert!(
        ignored
            .provider
            .authorization
            .as_ref()
            .unwrap()
            .end_session
            .is_none()
    );
    assert!(
        !ignored
            .provider
            .get_user_info
            .as_ref()
            .unwrap()
            .errors_are_exceptions()
    );

    let skipped = configure(json!({"issuer":"https://idp.example","jwks_uri":"http://[bad"}))
        .resolve()
        .await
        .unwrap();
    assert!(skipped.is_none());
}

struct ImageMapper;

#[async_trait::async_trait]
impl OAuthProfileMapper for ImageMapper {
    async fn map_profile(&self, _: Value) -> Result<alibi::field_policy::FieldOutput, String> {
        Ok([
            ("name".into(), json!("Application name")),
            ("image".into(), json!(42)),
        ]
        .into_iter()
        .collect())
    }
}

#[tokio::test]
async fn application_mappers_may_publish_scalar_images() {
    let polar = super::oauth_profiles::profiles()
        .into_iter()
        .find(|case| case.name == "polar" && case.variant == "default")
        .unwrap();
    let remote = Provider::start("application/json", polar.profile.to_string()).await;
    let provider = (polar.factory)(remote.url.as_str()).with_profile_mapper(Arc::new(ImageMapper));
    let user = fetch(&provider, None).await.unwrap().user;
    assert_eq!(user.image.as_deref(), Some("42"));
    assert_eq!(user.name.as_deref(), Some("Application name"));
}

#[tokio::test]
async fn wechat_profiles_bind_unionid_then_profile_openid_then_token_openid() {
    let remote = Provider::start("application/json", "{}").await;
    let mut options = WeChatOptions::new("client", "secret");
    options.user_info_endpoint = Some(remote.url.join("profile").unwrap().into());
    let provider = OAuthProvider::wechat_with_options(options);
    let request = |raw: Value| OAuthUserInfoRequest {
        access_token: Some("access".into()),
        raw: Some(raw),
        ..Default::default()
    };
    let handler = provider.get_user_info.as_ref().unwrap();
    for (profile, expected) in [
        (
            json!({"unionid":"union","openid":"profile-open","nickname":"N"}),
            Ok("union"),
        ),
        (
            json!({"openid":"profile-open","nickname":"N"}),
            Ok("profile-open"),
        ),
        (
            json!({"unionid":"","openid":"profile-open"}),
            Ok("profile-open"),
        ),
        (json!({"nickname":"N"}), Ok("token-open")),
        (
            json!({"errcode":40001,"errmsg":"invalid"}),
            Err("Missing WeChat profile"),
        ),
        (Value::Null, Err("Missing WeChat profile")),
    ] {
        remote.respond(200, "application/json", profile.to_string());
        let outcome = handler
            .get_user_info(request(
                json!({"openid":"token-open","access_token":"access"}),
            ))
            .await
            .map(|response| response.user.id);
        let expected: Result<String, String> = expected.map(Into::into).map_err(Into::into);
        assert_eq!(outcome, expected, "{profile}");
    }
    assert_eq!(
        handler
            .get_user_info(request(json!({"access_token":"access"})))
            .await
            .unwrap_err(),
        "Missing WeChat token openid"
    );
}
