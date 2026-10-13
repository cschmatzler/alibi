//! Browser logout requires the actual OP-issued signed session confirmation.
use super::*;
use alibi::AuthSession as _;
use alibi::plugins::{OAuthProviderPlugin, jwt::JwtPlugin};
backend_tests!(oauth_logout_confirmation_binds_real_browser_session_and_rejects_forgery);
async fn oauth_logout_confirmation_binds_real_browser_session_and_rejects_forgery<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = super::auth_probe::fast_builder::<B>(&connection)
        .plugin(JwtPlugin::new())
        .plugin(OAuthProviderPlugin::new())
        .build()
        .await?;
    let owner = signup(&auth, "logout-confirm-owner@example.test").await;
    let other = signup(&auth, "logout-confirm-other@example.test").await;
    let mut begin = request("/oauth2/end-session", None, &cookies(&owner));
    _ = begin.headers.insert("accept".into(), "text/html".into());
    let started = chrono::Utc::now().timestamp_millis();
    let response = call(&auth, begin, 200).await;
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("text/html; charset=utf-8")
    );
    let html = String::from_utf8(response.body.clone())?;
    assert!(html.contains("data-oidc-logout-confirmation"));
    assert!(html.contains("name=\"action\" value=\"confirm\""));
    assert!(html.contains(&format!(
        "action=\"{ORIGIN}/api/auth/oauth2/end-session/confirm\""
    )));
    let raw = response
        .headers
        .get_all("set-cookie")
        .find(|raw| raw.contains(".oauth_logout_confirmation="))
        .unwrap();
    let (proof_name, proof_value) = raw.split(';').next().unwrap().split_once('=').unwrap();
    assert!(raw.contains("Path=/api/auth/oauth2/end-session/confirm"));
    assert!(raw.contains("Max-Age=300"));
    assert!(raw.contains("HttpOnly"));
    assert!(raw.to_ascii_lowercase().contains("samesite=lax"));
    let encoded = format!("v={proof_value}");
    let decoded = url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .unwrap()
        .1
        .into_owned();
    let (payload, signature) = decoded.rsplit_once('.').unwrap();
    use base64::Engine as _;
    use hkdf::hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes())?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&base64::engine::general_purpose::STANDARD.decode(signature)?)?;
    let state: Value = serde_json::from_str(payload)?;
    let sessions = auth
        .store()
        .get_user_sessions(body(&owner)["user"]["id"].as_str().unwrap())
        .await?;
    assert_eq!(state["sessionId"], json!(sessions[0].id()));
    assert!(state["expiresAt"].as_i64().unwrap() >= started + 300_000);
    assert!(
        state["expiresAt"].as_i64().unwrap() <= chrono::Utc::now().timestamp_millis() + 300_000
    );
    let proof_cookie = format!("{proof_name}={proof_value}");
    for selected in [cookies(&owner), cookies(&other)] {
        let cookie = if selected == cookies(&owner) {
            format!("{selected}; {}=forged", proof_name)
        } else {
            format!("{selected}; {proof_cookie}")
        };
        let mut confirm = request("/oauth2/end-session/confirm", Some(json!({})), &cookie);
        confirm.body = Some(b"action=confirm".to_vec());
        _ = confirm.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        _ = confirm
            .headers
            .insert("accept".into(), "application/json".into());
        let denied = call(&auth, confirm, 400).await;
        assert_eq!(
            body(&denied),
            json!({"error":"invalid_request","error_description":"The logout confirmation is invalid or expired"})
        );
    }
    assert_eq!(
        auth.store()
            .get_user_sessions(body(&owner)["user"]["id"].as_str().unwrap())
            .await?
            .len(),
        1
    );
    let mut confirm = request(
        "/oauth2/end-session/confirm",
        Some(json!({})),
        &format!("{}; {proof_cookie}", cookies(&owner)),
    );
    confirm.body = Some(b"action=confirm".to_vec());
    _ = confirm.headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    _ = confirm.headers.insert("accept".into(), "text/html".into());
    let ended = call(&auth, confirm, 200).await;
    assert!(String::from_utf8(ended.body)?.contains("data-oidc-logout-state=\"logged-out\""));
    assert_eq!(
        auth.store()
            .get_user_sessions(body(&owner)["user"]["id"].as_str().unwrap())
            .await?
            .len(),
        0
    );
    assert_eq!(
        auth.store()
            .get_user_sessions(body(&other)["user"]["id"].as_str().unwrap())
            .await?
            .len(),
        1
    );
    let denied = Box::pin(auth.dispatch_endpoint(
        OAuthProviderPlugin::oauth2_end_session_confirmation_endpoint()?,
        alibi::endpoint::EndpointOptions::default(),
    ))
    .await
    .unwrap_err();
    assert_eq!(denied.error.status_code(), 400);
    assert_eq!(
        denied.body.unwrap().to_json_value()?,
        json!({"error":"invalid_request","error_description":"The logout confirmation is invalid or expired"})
    );
    let mut begin = request("/oauth2/end-session", None, &cookies(&other));
    _ = begin.headers.insert("accept".into(), "text/html".into());
    let fresh = call(&auth, begin, 200).await;
    let proof = fresh
        .headers
        .get_all("set-cookie")
        .find(|raw| raw.contains(".oauth_logout_confirmation="))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let logical = Box::pin(
        auth.dispatch_endpoint(
            OAuthProviderPlugin::oauth2_end_session_confirmation_endpoint()?,
            alibi::endpoint::EndpointOptions {
                headers: Some(
                    [("cookie".into(), format!("{}; {proof}", cookies(&other)))]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        ),
    )
    .await?
    .into_response()?;
    assert_eq!(logical.status, 200);
    assert_eq!(body(&logical), Value::Null);
    assert_eq!(
        auth.store()
            .get_user_sessions(body(&other)["user"]["id"].as_str().unwrap())
            .await?
            .len(),
        0
    );
    Ok(())
}
