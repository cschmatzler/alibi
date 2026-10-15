//! Popup start validation, forwarded sign-in options and delivery of provider errors.
use super::social_flows::{Social, callback};
use super::*;
use crate::snapshot::Trace;
use alibi::AccountConfig;
use alibi::plugins::OAuthPopupPlugin;

backend_tests!(
    popup_start_validates_targets_and_forwards_sign_in_options,
    popup_server_callback_delivers_completion_and_retires_marker
);
postgres_tests!(popup_server_callback_delivers_completion_and_retires_marker);

async fn popup_server_callback_delivers_completion_and_retires_marker<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let social = Social::start().await;
    let auth = social
        .auth_with::<B>(
            &connection,
            AccountConfig::default(),
            |_| {},
            |builder| builder.plugin(OAuthPopupPlugin::new()),
        )
        .await?;
    social
        .profile
        .set("sdk-popup-sub", "sdk-popup@example.com", true);
    for denied in [false, true] {
        let started = start(
            &auth,
            &[("provider", "google"), ("callbackURL", "/sdk-popup-done")],
        )
        .await;
        assert_eq!(started.status, 302);
        let location = url::Url::parse(started.headers.get("location").unwrap())?;
        let state = location
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        let query = if denied {
            json!({"state":state,"error":"access_denied","error_description":"User cancelled"})
        } else {
            json!({"state":state,"code":"grant"})
        };
        let endpoint = alibi::plugins::OAuthPlugin::callback_oauth_endpoint("google", None)?
            .with_query(&query)?;
        let result = auth
            .dispatch_endpoint(
                endpoint,
                alibi::endpoint::EndpointOptions {
                    headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                    ..Default::default()
                },
            )
            .await?;
        let completed = result.into_response()?;
        assert_eq!(completed.status, 200);
        let delivered = payload(&completed);
        assert_eq!(delivered["nonce"], "nonce-1");
        assert_eq!(delivered["targetOrigin"], ORIGIN);
        assert!(completed.headers.get("content-security-policy").is_some());
        assert!(
            completed
                .headers
                .get_all("set-cookie")
                .any(|value| value.contains("oauth_popup=") && value.contains("Max-Age=0"))
        );
        if denied {
            assert_eq!(
                delivered["error"],
                json!({"code":"access_denied","description":"User cancelled"})
            );
            assert!(delivered.get("token").is_none());
        } else {
            assert_eq!(delivered["redirectTo"], "/sdk-popup-done");
            let token = delivered["token"].as_str().unwrap();
            assert!(
                cookies(&completed).contains(token)
                    || cookies(&completed).contains(
                        &url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>()
                    )
            );
            let session = call(
                &auth,
                request("/get-session", None, &cookies(&completed)),
                200,
            )
            .await;
            assert_eq!(body(&session)["user"]["email"], "sdk-popup@example.com");
        }
        assert!(
            auth.store()
                .get_verification_by_identifier(&format!("auth-state:{state}"))
                .await?
                .is_none()
        );
    }
    assert_eq!(db.count("user").await?, 1);
    assert_eq!(db.count("session").await?, 1);
    B::close(connection).await
}

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
    let query: std::collections::HashMap<_, _> =
        [("popupOrigin", ORIGIN), ("popupNonce", "nonce-1")]
            .into_iter()
            .chain(query.iter().copied())
            .collect();
    match Box::pin(
        auth.dispatch_endpoint(
            OAuthPopupPlugin::oauth_popup_start_endpoint(
                &serde_json::from_value::<alibi::plugins::oauth_popup::OAuthPopupStartInput>(
                    serde_json::to_value(&query).unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            alibi::endpoint::EndpointOptions::default(),
        ),
    )
    .await
    {
        Ok(output) => output.into_response().unwrap(),
        Err(error) => {
            let mut response = if error.body_absent {
                AuthResponse::new(error.error.status_code())
            } else {
                error.error.to_auth_response()
            };
            if let Some(body) = error.body {
                response.body = serde_json::to_vec(&*body).unwrap();
            }
            if let Some(headers) = error.headers {
                for (name, value) in headers.iter() {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        response.headers.append(name, value);
                    } else {
                        drop(response.headers.insert(name, value));
                    }
                }
            }
            response
        }
    }
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

    for query in [
        json!({"provider":42,"popupOrigin":ORIGIN}),
        json!({"provider":"google"}),
    ] {
        let error = Box::pin(
            auth.dispatch_endpoint(
                alibi::endpoint::ServerEndpoint::<Value>::new("oauth-popup", "oauthPopupStart")
                    .with_query(&query)?,
                alibi::endpoint::EndpointOptions::default(),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(error.error.status_code(), 400);
        assert_eq!(
            error.error.error_payload().1.as_deref(),
            Some("VALIDATION_ERROR")
        );
        assert_eq!(db.count("verification").await?, 0);
    }
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
    assert_eq!(db.count("verification").await?, 0);

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
        .text("SELECT \"value\" FROM \"verification\"", &[])
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
    assert_eq!(db.count("user").await?, 1);

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
