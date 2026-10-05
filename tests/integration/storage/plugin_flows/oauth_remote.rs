//! Provider protocols whose authority is carried by remote verification or
//! nonstandard grants, rather than a generic bearer GET profile.
use super::*;
use better_auth::plugins::OAuthPlugin;
use better_auth::plugins::oauth::{
    CognitoOptions, FacebookOptions, LineOptions, OAuthAccountApi, OAuthAccountSelection,
    OAuthProvider, OAuthUserInfo, WeChatOptions,
};
use std::collections::HashMap;

backend_tests!(
    line_delegated_verification_binds_client_and_nonce,
    wechat_get_grants_bind_openid_and_rotate_refresh,
    facebook_graph_inspection_binds_app_and_profile,
    access_grant_profile_fallback_preserves_raw_subject
);
postgres_tests!(
    line_delegated_verification_binds_client_and_nonce,
    wechat_get_grants_bind_openid_and_rotate_refresh,
    facebook_graph_inspection_binds_app_and_profile,
    access_grant_profile_fallback_preserves_raw_subject
);

async fn line_delegated_verification_binds_client_and_nonce<B: Backend>(db: Db) -> TestResult {
    let remote = Provider::start("application/json", "{}").await;
    let mut options = LineOptions::new("native-client", Some("native-secret".into()));
    options.verification_endpoint = Some(remote.url.join("verify")?.into());
    options.user_info_endpoint = Some(remote.url.join("must-not-fetch-profile")?.into());
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("line", OAuthProvider::line_with_options(options)))
        .build()
        .await?;
    let proof = super::oauth_signed::token(
        &json!({"sub":"line-41","email":"line@example.test","name":"LINE User","picture":"https://images.test/line","aud":"native-client","nonce":"browser-nonce"}),
        false,
        "one-tap-local-rs256",
    )?;
    for (status, response, expected) in [
        (503, json!({}), 401),
        (
            200,
            json!({"aud":"foreign-client","nonce":"browser-nonce"}),
            401,
        ),
        (
            200,
            json!({"aud":"native-client","nonce":"foreign-nonce"}),
            401,
        ),
        (
            200,
            json!({"aud":"native-client","nonce":"browser-nonce"}),
            200,
        ),
    ] {
        remote.respond_at("/verify", status, response);
        let result = call(
            &auth,
            request(
                "/sign-in/social",
                Some(json!({"provider":"line","idToken":{"token":proof,"nonce":"browser-nonce"}})),
                "",
            ),
            expected,
        )
        .await;
        let exchanges = remote.take();
        assert_eq!(exchanges.len(), 1);
        assert_eq!(exchanges[0].path, "/verify");
        assert_eq!(exchanges[0].method, "POST");
        let form: HashMap<String, String> = url::form_urlencoded::parse(&exchanges[0].body)
            .into_owned()
            .collect();
        assert_eq!(form["id_token"], proof);
        assert_eq!(form["client_id"], "native-client");
        assert_eq!(form["nonce"], "browser-nonce");
        if expected == 401 {
            assert_eq!(body(&result)["code"], "INVALID_TOKEN");
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        } else {
            authenticated(&auth, &cookies(&result), "line@example.test").await;
            assert_eq!(
                db.text("SELECT account_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some("line-41")
            );
            assert_eq!(
                db.text("SELECT name FROM users", &[]).await?.as_deref(),
                Some("LINE User")
            );
        }
    }
    B::close(connection).await
}

async fn wechat_get_grants_bind_openid_and_rotate_refresh<B: Backend>(db: Db) -> TestResult {
    let remote = Provider::start("application/json", "{}").await;
    let mut options = WeChatOptions::new("native-client", "native-secret");
    options.token_endpoint = Some(remote.url.join("token")?.into());
    options.refresh_endpoint = Some(remote.url.join("refresh")?.into());
    options.user_info_endpoint = Some(remote.url.join("profile")?.into());
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let mapped = Arc::new(Mutex::new(Vec::new()));
    let provider = OAuthProvider::wechat_with_options(options).with_profile_mapper(Arc::new(
        super::oauth_profiles::PartialProfileMapper(mapped.clone()),
    ));
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("wechat", provider.clone()))
        .build()
        .await?;
    remote.respond_at("/profile", 200, json!({"openid":"open-41","unionid":"union-41","nickname":"WeChat User","headimgurl":"https://images.test/wechat"}));
    let mut accepted = None;
    for (reply, valid) in [
        (json!({"errcode":40029,"errmsg":"invalid code"}), false),
        (
            json!({"access_token":"remote-access","refresh_token":"remote-refresh","scope":"snsapi_login,profile","expires_in":7200}),
            false,
        ),
        (
            json!({"access_token":"remote-access","refresh_token":"remote-refresh","openid":"open-41","scope":"snsapi_login,profile","expires_in":7200}),
            true,
        ),
    ] {
        remote.respond_at("/token", 200, reply);
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "wechat").await;
        assert_eq!(authorization["appid"], "native-client");
        let response =
            super::oauth_profiles::complete(&auth, "wechat", &authorization, &cookie).await;
        let target = url::Url::parse(response.headers.get("location").unwrap())?;
        let exchanges = remote.take();
        let grant = exchanges
            .iter()
            .find(|request| request.path.starts_with("/token?"))
            .unwrap();
        assert_eq!(grant.method, "GET");
        assert!(grant.body.is_empty());
        let grant_url = remote.url.join(&grant.path)?;
        let query: HashMap<String, String> = grant_url.query_pairs().into_owned().collect();
        assert_eq!(query["appid"], "native-client");
        assert_eq!(query["secret"], "native-secret");
        assert_eq!(query["code"], "one-use-grant");
        assert_eq!(query["grant_type"], "authorization_code");
        if valid {
            assert_eq!(target.path(), "/done");
            let profile = exchanges
                .iter()
                .find(|request| request.path.starts_with("/profile?"))
                .unwrap();
            assert_eq!(profile.method, "GET");
            assert!(profile.headers.get("authorization").is_none());
            let profile_url = remote.url.join(&profile.path)?;
            let query: HashMap<String, String> = profile_url.query_pairs().into_owned().collect();
            assert_eq!(query["access_token"], "remote-access");
            assert_eq!(query["openid"], "open-41");
            assert_eq!(query["lang"], "zh_CN");
            authenticated(
                &auth,
                &cookies(&response),
                "union-41@wechat.placeholder.invalid",
            )
            .await;
            assert_eq!(
                db.text("SELECT account_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some("union-41")
            );
            assert_eq!(
                db.text("SELECT name FROM users", &[]).await?.as_deref(),
                Some("Application display")
            );
            accepted = Some(response);
        } else {
            assert_eq!(target.path(), "/failed");
            assert!(!cookies(&response).contains("session_token="));
            assert!(
                exchanges
                    .iter()
                    .all(|request| !request.path.starts_with("/profile"))
            );
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        }
    }
    assert_eq!(
        *mapped.lock().unwrap(),
        vec![
            json!({"openid":"open-41","unionid":"union-41","nickname":"WeChat User","headimgurl":"https://images.test/wechat"})
        ]
    );
    assert_eq!(
        db.text("SELECT image FROM users", &[]).await?.as_deref(),
        Some("https://images.test/wechat")
    );
    let original = db.tables(&["users", "accounts", "sessions"]).await?;
    remote.respond_at("/profile", 200, json!({"errcode":40003,"openid":"open-41","unionid":"union-41","nickname":"WeChat User","headimgurl":"https://images.test/wechat"}));
    let (authorization, cookie) = super::oauth_profiles::begin(&auth, "wechat").await;
    let denied = super::oauth_profiles::complete(&auth, "wechat", &authorization, &cookie).await;
    assert_eq!(
        url::Url::parse(denied.headers.get("location").unwrap())?.path(),
        "/failed"
    );
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        original
    );
    remote.respond_at("/profile", 200, json!({"openid":"open-41","unionid":"union-41","nickname":"WeChat User","headimgurl":"https://images.test/wechat"}));
    let failed = provider.with_profile_mapper(Arc::new(super::oauth_profiles::FailedMapper));
    let failed_auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("wechat", failed))
        .build()
        .await?;
    let (authorization, cookie) = super::oauth_profiles::begin(&failed_auth, "wechat").await;
    let mut callback = request("/callback/wechat", None, &cookie);
    callback.query.extend([
        ("state".into(), authorization["state"].clone()),
        ("code".into(), "one-use-grant".into()),
    ]);
    let denied = call(&failed_auth, callback, 500).await;
    assert!(!cookies(&denied).contains("session_token="));
    assert_eq!(
        db.tables(&["users", "accounts", "sessions"]).await?,
        original
    );
    drop(remote.take());
    let accepted = accepted.unwrap();
    let session = call(
        &auth,
        request("/get-session", None, &cookies(&accepted)),
        200,
    )
    .await;
    let owner = body(&session)["user"]["id"].as_str().unwrap().to_owned();
    let account = db.text("SELECT id FROM accounts", &[]).await?.unwrap();
    remote.respond_at("/refresh", 200, json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","openid":"open-41","scope":"snsapi_login,profile","expires_in":7200}));
    let response = OAuthAccountApi::refresh_token(
        &owner,
        OAuthAccountSelection::Id(account.clone()),
        auth.context(),
    )
    .await?;
    assert_eq!(body(&response)["accessToken"], "rotated-access");
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
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].method, "GET");
    let refresh_url = remote.url.join(&exchanges[0].path)?;
    assert_eq!(refresh_url.path(), "/refresh");
    let query: HashMap<String, String> = refresh_url.query_pairs().into_owned().collect();
    assert_eq!(query["appid"], "native-client");
    assert_eq!(query["refresh_token"], "remote-refresh");
    assert_eq!(query["grant_type"], "refresh_token");
    B::close(connection).await
}

async fn facebook_graph_inspection_binds_app_and_profile<B: Backend>(db: Db) -> TestResult {
    let remote = Provider::start("application/json", "{}").await;
    let mut options = FacebookOptions::new("native-client", Some("native-secret".into()));
    options.token_inspection_endpoint = Some(remote.url.join("inspect")?.into());
    options.user_info_endpoint = Some(remote.url.join("profile")?.into());
    let mut provider = OAuthProvider::facebook_with_options(options);
    provider.token_url = remote.url.join("token")?.into();
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OAuthPlugin::new().add_provider("facebook", provider))
        .build()
        .await?;
    remote.respond_at(
        "/token",
        200,
        json!({"access_token":"graph-access","token_type":"Bearer","expires_in":3600}),
    );
    remote.respond_at("/profile", 200, json!({"id":"graph-41","email":"facebook-graph@example.test","name":"Graph User","picture":{"data":{"url":"https://images.test/facebook"}},"email_verified":true}));
    for (application, subject, inspected, valid) in [
        ("foreign-app", "graph-41", true, false),
        ("native-client", "different-subject", true, false),
        ("native-client", "graph-41", false, false),
        ("native-client", "graph-41", true, true),
    ] {
        remote.respond_at(
            "/inspect",
            200,
            json!({"data":{"is_valid":inspected,"app_id":application,"user_id":subject}}),
        );
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "facebook").await;
        let response =
            super::oauth_profiles::complete(&auth, "facebook", &authorization, &cookie).await;
        let target = url::Url::parse(response.headers.get("location").unwrap())?;
        let exchanges = remote.take();
        let inspection = exchanges
            .iter()
            .find(|request| request.path.starts_with("/inspect?"))
            .unwrap();
        assert_eq!(inspection.method, "GET");
        let inspection_url = remote.url.join(&inspection.path)?;
        let params: HashMap<String, String> = inspection_url.query_pairs().into_owned().collect();
        assert_eq!(params["input_token"], "graph-access");
        assert_eq!(params["access_token"], "native-client|native-secret");
        if valid {
            assert_eq!(target.path(), "/done");
            authenticated(&auth, &cookies(&response), "facebook-graph@example.test").await;
            assert_eq!(
                db.text("SELECT account_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some("graph-41")
            );
            assert_eq!(
                db.text("SELECT image FROM users", &[]).await?.as_deref(),
                Some("https://images.test/facebook")
            );
        } else {
            assert_eq!(target.path(), "/failed");
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        }
    }
    B::close(connection).await
}

fn fallback_mapper(profile: Value) -> Result<OAuthUserInfo, String> {
    if profile["source"] == "claims" {
        return Err("Application needs remote profile".into());
    }
    Ok(OAuthUserInfo {
        id: "mapped-presentation-id".into(),
        email: "fallback@example.test".into(),
        name: Some("Mapped remote".into()),
        image: None,
        email_verified: false,
        additional_fields: Default::default(),
    })
}

async fn access_grant_profile_fallback_preserves_raw_subject<B: Backend>(db: Db) -> TestResult {
    for mode in [
        "line",
        "cognito",
        "cognito-mapper",
        "cognito-invalid-subject",
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let remote = Provider::start("application/json", "{}").await;
        let mut provider = if mode == "line" {
            let mut options = LineOptions::new("native-client", Some("native-secret".into()));
            options.user_info_endpoint = Some(remote.url.join("profile")?.into());
            OAuthProvider::line_with_options(options)
        } else {
            let mut options = CognitoOptions::new(
                "native-client",
                Some("native-secret".into()),
                "pool.example.test",
                "us-east-1",
                "pool",
            );
            options.user_info_endpoint = Some(remote.url.join("profile")?.into());
            if mode.starts_with("cognito-") {
                options.map_profile_to_user = Some(fallback_mapper);
            }
            OAuthProvider::cognito(options)?
        };
        provider.token_url = remote.url.join("token")?.into();
        let mut grant = json!({"access_token":"fallback-access","refresh_token":"fallback-refresh","expires_in":3600});
        if mode.starts_with("cognito-") {
            let claims = json!({"sub":if mode == "cognito-invalid-subject" { None } else { Some("claims-subject") },"email":"fallback@example.test","name":"Claims User","source":if mode == "cognito-mapper" { "claims" } else { "userinfo" }});
            grant["id_token"] = json!(super::oauth_signed::token(
                &claims,
                false,
                "one-tap-local-rs256"
            )?);
        }
        remote.respond_at("/token", 200, grant);
        remote.respond_at("/profile", 200, json!({"sub":"remote-subject","userId":"remote-subject","email":"fallback@example.test","name":"Remote User","displayName":"Remote User","source":"userinfo"}));
        let auth = builder::<B>(&connection)
            .plugin(OAuthPlugin::new().add_provider("fallback", provider))
            .build()
            .await?;
        let (authorization, cookie) = super::oauth_profiles::begin(&auth, "fallback").await;
        let result =
            super::oauth_profiles::complete(&auth, "fallback", &authorization, &cookie).await;
        let exchanges = remote.take();
        let profile = exchanges
            .iter()
            .find(|exchange| exchange.path == "/profile");
        if mode == "cognito-invalid-subject" {
            assert_eq!(
                url::Url::parse(result.headers.get("location").unwrap())?.path(),
                "/failed"
            );
            assert!(profile.is_none());
            for table in ["users", "accounts", "sessions"] {
                assert_eq!(db.count(table).await?, 0);
            }
        } else {
            assert_eq!(
                url::Url::parse(result.headers.get("location").unwrap())?.path(),
                "/done",
                "{mode}"
            );
            authenticated(&auth, &cookies(&result), "fallback@example.test").await;
            let profile = profile.expect("actual fallback transport");
            assert_eq!(profile.method, "GET");
            assert_eq!(profile.headers["authorization"], "Bearer fallback-access");
            assert_eq!(
                db.text("SELECT account_id FROM accounts", &[])
                    .await?
                    .as_deref(),
                Some("remote-subject")
            );
            assert_eq!(
                db.text("SELECT name FROM users", &[]).await?.as_deref(),
                Some(if mode == "cognito-mapper" {
                    "Mapped remote"
                } else {
                    "Remote User"
                })
            );
        }
        B::close(connection).await?;
    }
    Ok(())
}
