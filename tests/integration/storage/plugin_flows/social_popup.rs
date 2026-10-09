//! Popup start validation, forwarded sign-in options and delivery of provider errors.
use super::social_flows::{Social, callback};
use super::*;
use crate::snapshot::Trace;
use alibi::AccountConfig;
use alibi::plugins::OAuthPopupPlugin;

backend_tests!(popup_start_validates_targets_and_forwards_sign_in_options);

fn payload(response: &AuthResponse) -> Value {
    let html = String::from_utf8_lossy(&response.body);
    serde_json::from_str(
        html.split("id=\"better-auth-oauth-popup\">")
            .nth(1)
            .unwrap()
            .split("</script>")
            .next()
            .unwrap(),
    )
    .unwrap()
}

async fn start<S: AuthSchema>(auth: &Alibi<S>, query: &[(&str, &str)]) -> AuthResponse {
    let mut req = request("/oauth-popup/start", None, "");
    req.set_query_pairs(
        [("popupOrigin", ORIGIN), ("popupNonce", "nonce-1")]
            .into_iter()
            .chain(query.iter().copied()),
    );
    Box::pin(auth.handle_request(req)).await.unwrap()
}

async fn popup_start_validates_targets_and_forwards_sign_in_options<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let mut trace = Trace::default();
    let auth = social
        .auth_with::<B>(
            &connection,
            AccountConfig::default(),
            |provider| provider.disable_implicit_sign_up = true,
            |builder| builder.plugin(OAuthPopupPlugin::new()),
        )
        .await?;

    for (label, extra) in [
        (
            "untrusted callback",
            vec![
                ("provider", "google"),
                ("callbackURL", "https://evil.example/cb"),
            ],
        ),
        (
            "untrusted error callback",
            vec![
                ("provider", "google"),
                ("errorCallbackURL", "https://evil.example/e"),
            ],
        ),
        (
            "untrusted new user callback",
            vec![
                ("provider", "google"),
                ("newUserCallbackURL", "https://evil.example/n"),
            ],
        ),
        ("unknown provider", vec![("provider", "nowhere")]),
    ] {
        let response = start(&auth, &extra).await;
        assert_eq!(response.status, 200, "{label}");
        trace.value(label, payload(&response));
    }
    assert_eq!(db.count("verifications").await?, 0);

    let started = start(
        &auth,
        &[
            ("provider", "google"),
            ("callbackURL", "/after"),
            ("errorCallbackURL", "/popup-error"),
            ("newUserCallbackURL", "/popup-new"),
            ("requestSignUp", "true"),
            ("scopes", "calendar,drive"),
            (
                "additionalData",
                r#"{"keep":"yes","callbackURL":"https://evil.example","oauthState":"forged","serverContext":{"x":1},"link":{"userId":"forged"},"requestSignUp":false}"#,
            ),
        ],
    )
    .await;
    assert_eq!(started.status, 302);
    let location = url::Url::parse(started.headers.get("location").unwrap())?;
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert!(
        query["scope"].contains("calendar drive"),
        "{}",
        query["scope"]
    );
    let stored = db
        .text("SELECT value FROM verifications", &[])
        .await?
        .unwrap();
    let stored: Value = serde_json::from_str(&stored)?;
    assert!(stored.get("serverContext").is_none() && stored.get("link").is_none());
    trace.value(
        "stored state",
        json!({
            "callbackURL": stored["callbackURL"],
            "errorURL": stored["errorURL"],
            "newUserURL": stored["newUserURL"],
            "requestSignUp": stored["requestSignUp"],
            "keep": stored["keep"],
        }),
    );
    let cookie = cookies(&started);
    social.profile.set("popup-sub", "popup@example.com", true);
    let completed = callback(
        &auth,
        &[("code", "grant"), ("state", &query["state"])],
        &cookie,
    )
    .await;
    assert_eq!(completed.status, 200);
    let delivered = payload(&completed);
    assert!(
        delivered["token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    trace.value(
        "delivered",
        json!({"nonce": delivered["nonce"], "redirectTo": delivered["redirectTo"]}),
    );
    assert_eq!(db.count("users").await?, 1);

    let started = start(&auth, &[("provider", "google")]).await;
    let location = url::Url::parse(started.headers.get("location").unwrap())?;
    let state = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let denied = callback(
        &auth,
        &[
            ("state", &state),
            ("error", "access_denied"),
            ("error_description", "User cancelled"),
        ],
        &cookies(&started),
    )
    .await;
    trace.value("provider error", payload(&denied));
    trace.assert("social/popup-start");
    B::close(connection).await
}
