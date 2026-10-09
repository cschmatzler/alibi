//! Linked-account token and profile endpoints: input validation, authentication
//! and refresh outcomes.
use super::social_flows::{Social, authorize, callback};
use super::*;
use crate::snapshot::Trace;
use alibi::AccountConfig;
use alibi::plugins::oauth::{OAuthAccountApi, OAuthAccountSelection};

backend_tests!(account_endpoints_validate_selection_authentication_and_refresh);

async fn account_endpoints_validate_selection_authentication_and_refresh<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let account = AccountConfig {
        store_account_cookie: true,
        ..Default::default()
    };
    let auth = social.auth::<B>(&connection, account, |_| {}).await?;
    let (state, cookie) = authorize(
        &auth,
        "/sign-in/social",
        json!({"provider":"google","callbackURL":"/home"}),
        "",
    )
    .await;
    let signed_in = callback(&auth, &[("code", "grant"), ("state", &state)], &cookie).await;
    assert_eq!(signed_in.status, 302);
    let session = cookies(&signed_in);
    let id = db.text("SELECT id FROM accounts", &[]).await?.unwrap();

    let post = |path: &'static str, input: Value, cookie: String| {
        let auth = &auth;
        async move {
            Box::pin(auth.handle_request(request(path, Some(input), &cookie)))
                .await
                .unwrap()
        }
    };
    for path in ["/get-access-token", "/refresh-token"] {
        for (label, input) in [
            ("empty object", json!({})),
            ("array", json!([])),
            ("unknown key", json!({"accountId": id, "extra": 1})),
            (
                "unknown keys",
                json!({"accountId": id, "extra": 1, "more": 2}),
            ),
            (
                "both selectors",
                json!({"accountId": id, "useAccountCookie": true}),
            ),
            ("foreign user", json!({"accountId": id, "userId": 5})),
            ("account cookie selector", json!({"useAccountCookie": true})),
            ("unknown account", json!({"accountId": "missing"})),
        ] {
            trace.response(
                &format!("{path} {label}"),
                &post(path, input, session.clone()).await,
            );
        }
        trace.response(
            &format!("{path} unauthenticated"),
            &post(path, json!({"accountId": id}), String::new()).await,
        );
    }
    for (label, query, cookie) in [
        (
            "account-info selected",
            vec![("accountId", id.as_str())],
            session.as_str(),
        ),
        (
            "account-info unknown key",
            vec![("accountId", id.as_str()), ("extra", "1")],
            session.as_str(),
        ),
        ("account-info no selector", vec![], session.as_str()),
        (
            "account-info unauthenticated",
            vec![("accountId", id.as_str())],
            "",
        ),
    ] {
        let mut req = request("/account-info", None, cookie);
        req.set_query_pairs(query);
        trace.response(label, &Box::pin(auth.handle_request(req)).await?);
    }

    social.provider.respond(
        200,
        "application/json",
        json!({"access_token":"rotated-access","token_type":"Bearer","expires_in":3600})
            .to_string(),
    );
    let refreshed = post("/refresh-token", json!({"accountId": id}), session.clone()).await;
    trace.response("refresh without a new refresh token", &refreshed);
    assert_eq!(body(&refreshed)["refreshToken"], "provider-refresh");
    assert_eq!(
        db.text("SELECT refresh_token FROM accounts", &[])
            .await?
            .as_deref(),
        Some("provider-refresh")
    );

    for selection in [
        OAuthAccountSelection::Id(id.clone()),
        OAuthAccountSelection::Cookie,
    ] {
        let error = OAuthAccountApi::get_access_token("", selection, auth.context())
            .await
            .unwrap_err();
        trace.value("server call without user", json!(error.to_string()));
    }
    trace.assert("social/account-api");
    B::close(connection).await
}
