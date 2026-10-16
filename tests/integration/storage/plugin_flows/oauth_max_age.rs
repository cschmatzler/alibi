//! Existing sessions must satisfy authorization freshness before code issuance.
use super::*;
use alibi::endpoint::EndpointOptions;
use alibi::plugins::OAuthProviderPlugin;
use alibi::plugins::jwt::{JwtPlugin, JwtPluginConfig};

backend_tests!(oauth_max_age_blocks_stale_authority_and_validates_input);
async fn oauth_max_age_blocks_stale_authority_and_validates_input<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::with_config(JwtPluginConfig {
            disable_setting_jwt_header: true,
            ..Default::default()
        }))
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = Box::pin(signup(&auth, "max-age-owner@example.test")).await;
    let cookie = cookies(&owner);
    let client = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::admin_create_oauth_client_endpoint(&json!({
            "client_name":"Freshness client","redirect_uris":["https://app.fixture.test/callback"],
            "scope":"email","skip_consent":true,"require_pkce":false,
        }))?,
        EndpointOptions {
            headers: Some([("cookie".into(), cookie.clone())].into_iter().collect()),
            ..Default::default()
        },
    ))
    .await?
    .into_response()?;
    db.set_timestamp(
        "session",
        "createdAt",
        ("token", body(&owner)["token"].as_str().unwrap()),
        chrono::Utc::now() - chrono::Duration::hours(2),
    )
    .await?;
    let base = json!({"client_id":body(&client)["client_id"],"response_type":"code",
        "redirect_uri":"https://app.fixture.test/callback","scope":"email","state":"freshness-state"});
    for (http, age, prompt, expected_age) in [
        (true, json!("0"), None, "0"),
        (false, json!(0), None, "0"),
        (false, json!("0"), None, "0"),
        (false, json!(0), Some("none"), "0"),
        (true, json!("60"), None, "60"),
        (false, json!(60), None, "60"),
        (false, json!(60), Some("none"), "60"),
    ] {
        let before = db
            .tables(&["user", "account", "session", "verification", "oauthClient"])
            .await?;
        let mut query = base.clone();
        query["max_age"] = age;
        if let Some(prompt) = prompt {
            query["prompt"] = json!(prompt);
        }
        let response = Box::pin(authorize(&auth, &query, &cookie, http)).await?;
        assert_eq!(response.status, 200);
        let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        if prompt == Some("none") {
            assert_eq!(target.host_str(), Some("app.fixture.test"));
            assert_eq!(
                target
                    .query_pairs()
                    .find(|(key, _)| key == "error")
                    .unwrap()
                    .1,
                "login_required"
            );
        } else {
            assert_eq!(target.path(), "/login");
            assert_eq!(
                target
                    .query_pairs()
                    .find(|(key, _)| key == "max_age")
                    .unwrap()
                    .1,
                expected_age
            );
        }
        assert!(!target.query_pairs().any(|(key, _)| key == "code"));
        assert!(response.headers.get_all("set-cookie").next().is_none());
        assert_eq!(
            db.tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?,
            before
        );
    }
    for (http, age) in [
        (true, json!("86400")),
        (false, json!(86400)),
        (false, json!(" 0x15180 ")),
    ] {
        let mut query = base.clone();
        query["max_age"] = age;
        let response = Box::pin(authorize(&auth, &query, &cookie, http)).await?;
        assert_eq!(response.status, 200);
        let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        assert_eq!(target.host_str(), Some("app.fixture.test"));
        assert!(target.query_pairs().any(|(key, _)| key == "code"));
    }
    let invalid = [
        json!(-1),
        json!(0.5),
        json!(""),
        json!("  "),
        json!("-1"),
        json!("1.5"),
        json!("Infinity"),
        json!(false),
        Value::Null,
        json!(["0", "1"]),
        json!({}),
    ];
    for (http, age) in invalid
        .into_iter()
        .map(|age| (false, age))
        .chain([(true, json!(["0", "86400"]))])
    {
        let before = db
            .tables(&["user", "account", "session", "verification", "oauthClient"])
            .await?;
        let mut query = base.clone();
        query["max_age"] = age;
        let response = Box::pin(authorize(&auth, &query, &cookie, http)).await?;
        assert_eq!(response.status, 200);
        assert_eq!(
            db.tables(&["user", "account", "session", "verification", "oauthClient"])
                .await?,
            before,
            "invalid authorization parameters must not create authority; http={http}"
        );
        let target = url::Url::parse(ORIGIN)?.join(body(&response)["url"].as_str().unwrap())?;
        assert_eq!(
            target
                .query_pairs()
                .find(|(key, _)| key == "error")
                .unwrap()
                .1,
            "invalid_request"
        );
        assert!(!target.query_pairs().any(|(key, _)| key == "code"));
        assert!(response.headers.get_all("set-cookie").next().is_none());
    }
    Ok(())
}
async fn authorize<S: AuthSchema>(
    auth: &Alibi<S>,
    query: &Value,
    cookie: &str,
    http: bool,
) -> alibi::AuthResult<AuthResponse> {
    let mut request = request("/oauth2/authorize", None, cookie);
    _ = request
        .headers
        .insert("accept".into(), "application/json".into());
    if http {
        request.set_query_pairs(query.as_object().unwrap().iter().flat_map(|(key, value)| {
            let values = match value {
                Value::Array(values) => values.iter().collect::<Vec<_>>(),
                _ => vec![value],
            };
            values
                .into_iter()
                .map(move |value| (key.clone(), value.as_str().unwrap().to_owned()))
        }));
        Box::pin(auth.handle_request(request)).await
    } else {
        Box::pin(auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_authorize_endpoint(query)?,
            EndpointOptions {
                headers: Some(request.headers.clone()),
                request: Some(request),
                ..Default::default()
            },
        ))
        .await
        .map_err(|error| error.error)?
        .into_response()
    }
}
