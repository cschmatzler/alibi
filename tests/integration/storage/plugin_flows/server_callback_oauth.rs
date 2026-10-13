//! Genuine logical callback input controls schema admission and one-time proof redemption.
use super::server_revocation_support::options;
use super::*;
use alibi::endpoint::{EndpointError, EndpointOptions, ServerEndpoint};
use alibi::plugins::OAuthPlugin;
backend_tests!(server_callback_oauth_redeems_logical_get_and_preserves_post_proofs);

async fn callback<S: AuthSchema>(
    auth: &Alibi<S>,
    query: Option<&Value>,
    body: Option<&Value>,
    method: Option<HttpMethod>,
    cookie: &str,
) -> EndpointError {
    let typed = query.and_then(|query| {
        serde_json::from_value::<alibi::plugins::oauth::OAuthCallbackInput>(query.clone()).ok()
    });
    let mut endpoint = OAuthPlugin::callback_oauth_endpoint("generic", typed.as_ref()).unwrap();
    if let Some(query) = query {
        endpoint = endpoint.with_query(query).unwrap();
    }
    if let Some(body) = body {
        endpoint = endpoint.with_body(body).unwrap();
    }
    Box::pin(
        auth.dispatch_endpoint(
            endpoint,
            EndpointOptions {
                method,
                headers: (!cookie.is_empty())
                    .then(|| [("cookie".into(), cookie.into())].into_iter().collect()),
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap_err()
}
fn location(error: &EndpointError) -> &str {
    error.headers.as_ref().unwrap().get("location").unwrap()
}
async fn start<S: AuthSchema>(
    auth: &Alibi<S>,
    link: bool,
    owner: &AuthResponse,
) -> (String, String) {
    let body = json!({"provider":"generic","callbackURL":"/logical-callback-done","errorCallbackURL":"/logical-callback-error?keep=yes#panel","disableRedirect":true});
    let operation = if link {
        "linkSocialAccount"
    } else {
        "signInSocial"
    };
    let result = Box::pin(
        auth.dispatch_endpoint(
            ServerEndpoint::<Value>::new("oauth", operation)
                .with_body(&body)
                .unwrap(),
            if link {
                options(owner)
            } else {
                EndpointOptions::default()
            },
        ),
    )
    .await
    .unwrap();
    let value = result.decode().unwrap();
    let url = url::Url::parse(value["url"].as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let cookie = result
        .headers()
        .get_all("set-cookie")
        .map(|c| c.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    (state, cookie)
}
async fn server_callback_oauth_redeems_logical_get_and_preserves_post_proofs<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let remote = Provider::start("application/json", "{}").await;
    remote.respond_at("/token",200,json!({"access_token":"generic-access","refresh_token":"generic-refresh","scope":"profile","expires_in":3600}));
    remote.respond_at("/profile",200,json!({"id":"logical-callback-subject","email":"logical-callback-owner@example.test","name":"Provider Owner","email_verified":true}));
    let provider = super::server_oauth_support::generic_provider(&remote)?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(
            OAuthPlugin::new().add_provider("generic", provider.resolve().await?.unwrap().provider),
        )
        .build()
        .await?;
    let owner = signup(&auth, "logical-callback-owner@example.test").await;
    let foreign = signup(&auth, "logical-callback-foreign@example.test").await;
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let foreign_id = body(&foreign)["user"]["id"].as_str().unwrap().to_owned();
    let before = db
        .tables(&["user", "account", "session", "verification"])
        .await?;
    for (query, body) in [
        (json!(null), None),
        (json!(7), None),
        (json!({"state":7}), None),
        (json!({"code":["duplicate"]}), None),
        (json!({}), Some(json!(null))),
        (json!({}), Some(json!({"error":false}))),
    ] {
        let error = callback(&auth, Some(&query), body.as_ref(), None, "").await;
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(
            db.tables(&["user", "account", "session", "verification"])
                .await?,
            before
        );
        assert!(remote.take().is_empty());
    }
    for (query, method, expected) in [
        (None, None, "invalid_callback_request"),
        (Some(json!({})), None, "state_not_found"),
        (Some(json!({"state":""})), None, "state_not_found"),
        (
            Some(json!({"state":"missing-state"})),
            None,
            "state_mismatch",
        ),
        (
            Some(json!({"state":"missing-state"})),
            Some(HttpMethod::Put),
            "invalid_callback_request",
        ),
    ] {
        let error = callback(&auth, query.as_ref(), None, method, "").await;
        assert_eq!(error.error.status_code(), 302);
        assert!(error.body_absent);
        let url = url::Url::parse(location(&error))?;
        assert_eq!(
            url.query_pairs().find(|(key, _)| key == "error").unwrap().1,
            expected
        );
    }
    let post=callback(&auth,Some(&json!({"code":"query-code","device_id":"device :+&","extra":"ignored"})),Some(&json!({"code":"body-code","state":"body-state","error_description":"body description","extra":"ignored"})),Some(HttpMethod::Post),"").await;
    assert_eq!(post.error.status_code(), 302);
    assert!(post.body_absent);
    let url = url::Url::parse(location(&post))?;
    assert_eq!(url.path(), "/api/auth/callback/generic");
    assert_eq!(
        url.query_pairs()
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>(),
        [
            ("code".into(), "query-code".into()),
            ("device_id".into(), "device :+&".into()),
            ("error_description".into(), "body description".into()),
            ("state".into(), "body-state".into())
        ]
        .into_iter()
        .collect()
    );
    for query in [
        json!({"code":"valid-code","error":"access_denied","error_description":""}),
        json!({"code":""}),
    ] {
        let (state, cookie) = start(&auth, true, &owner).await;
        let mut query = query;
        query["state"] = json!(state);
        let error = callback(&auth, Some(&query), None, None, &cookie).await;
        assert_eq!(error.error.status_code(), 302);
        let url = url::Url::parse(location(&error))?;
        assert_eq!(
            url.query_pairs().find(|(key, _)| key == "error").unwrap().1,
            if query.get("error").is_some() {
                "access_denied"
            } else {
                "no_code"
            }
        );
        assert!(url.query_pairs().all(|(key, _)| key != "error_description"));
        let proofs: Vec<Value> = serde_json::from_str(&db.table("verification").await?)?;
        assert!(
            proofs
                .iter()
                .all(|proof| proof["identifier"] != format!("auth-state:{state}"))
        );
        assert!(remote.take().is_empty());
    }
    let (state, cookie) = start(&auth, true, &owner).await;
    let mismatch = callback(
        &auth,
        Some(&json!({"state":state,"code":"ignored-code"})),
        None,
        None,
        "better-auth.state=invalid",
    )
    .await;
    assert_eq!(
        url::Url::parse(location(&mismatch))?
            .query_pairs()
            .find(|(key, _)| key == "error")
            .unwrap()
            .1,
        "state_mismatch"
    );
    let proofs: Vec<Value> = serde_json::from_str(&db.table("verification").await?)?;
    assert!(
        proofs
            .iter()
            .any(|proof| proof["identifier"] == format!("auth-state:{state}"))
    );
    let linked=callback(&auth,Some(&json!({"state":state,"code":"logical-link-code","error":"","extra":{"userId":foreign_id}})),Some(&json!({"state":"ignored-body-state","code":"ignored-body-code"})),None,&cookie).await;
    assert_eq!(linked.error.status_code(), 302);
    assert_eq!(location(&linked), "/logical-callback-done");
    assert_eq!(
        db.tables(&["user", "session"]).await?,
        vec![before[0].clone(), before[2].clone()]
    );
    let accounts: Vec<Value> = serde_json::from_str(&db.table("account").await?)?;
    let previous: Vec<Value> = serde_json::from_str(&before[1])?;
    assert_eq!(accounts.len(), previous.len() + 1);
    for row in previous {
        assert!(accounts.contains(&row));
    }
    assert_eq!(
        accounts
            .iter()
            .find(|a| a["providerId"] == "generic")
            .unwrap()["userId"],
        owner_id
    );
    let replay = callback(
        &auth,
        Some(&json!({"state":state,"code":"replayed"})),
        None,
        None,
        &cookie,
    )
    .await;
    assert_eq!(
        url::Url::parse(location(&replay))?
            .query_pairs()
            .find(|(key, _)| key == "error")
            .unwrap()
            .1,
        "state_mismatch"
    );
    let (login_state, login_cookie) = start(&auth, false, &owner).await;
    let logged_in = callback(
        &auth,
        Some(&json!({"state":login_state,"code":"logical-sign-in-code"})),
        None,
        None,
        &login_cookie,
    )
    .await;
    assert_eq!(logged_in.error.status_code(), 302);
    assert_eq!(location(&logged_in), "/logical-callback-done");
    let cookies = logged_in
        .headers
        .as_ref()
        .unwrap()
        .get_all("set-cookie")
        .map(|c| c.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ");
    authenticated(&auth, &cookies, "logical-callback-owner@example.test").await;
    let sessions: Vec<Value> = serde_json::from_str(&db.table("session").await?)?;
    let old_sessions: Vec<Value> = serde_json::from_str(&before[2])?;
    assert_eq!(sessions.len(), old_sessions.len() + 1);
    for session in old_sessions {
        assert!(sessions.contains(&session));
    }
    let users: Vec<Value> = serde_json::from_str(&db.table("user").await?)?;
    let old_users: Vec<Value> = serde_json::from_str(&before[0])?;
    assert_eq!(
        users.iter().find(|u| u["id"] == foreign_id),
        old_users.iter().find(|u| u["id"] == foreign_id)
    );
    let sent = remote.take();
    let forms = sent
        .iter()
        .filter(|s| s.path == "/token")
        .map(|s| {
            url::form_urlencoded::parse(&s.body)
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(forms.len(), 2);
    assert_eq!(forms[0]["code"], "logical-link-code");
    assert_eq!(forms[1]["code"], "logical-sign-in-code");
    B::close(connection).await
}
