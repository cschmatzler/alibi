//! A configured `__Secure-` cookie name prefix is applied once, by the cookie policy.
use better_auth::plugins::EmailPasswordPlugin;
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthRequest, HttpMethod};
use serde_json::json;

async fn issued_cookie_names(base_url: &str, cookie_name: &str) -> Vec<String> {
    let mut config =
        AuthConfig::new("cookie-name-at-least-32-characters-secret").base_url(base_url);
    config.session.cookie_name = cookie_name.into();
    let auth = AuthBuilder::without_database(config)
        .plugin(EmailPasswordPlugin::new())
        .build()
        .await
        .unwrap();
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(request.headers.insert("origin".into(), base_url.into()));
    request.body = Some(
        serde_json::to_vec(
            &json!({"email":"cookie@example.test","name":"Cookie","password":"Password123!"}),
        )
        .unwrap(),
    );
    let response = Box::pin(auth.handle_request(request)).await.unwrap();
    assert_eq!(response.status, 200);
    response
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split('=').next().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn configured_secure_prefix_is_not_applied_twice() {
    for name in [
        "__Secure-better-auth.session_token",
        "better-auth.session_token",
    ] {
        assert_eq!(
            issued_cookie_names("https://auth.example.test", name).await,
            [
                "__Secure-better-auth.session_token",
                "__Secure-better-auth.session_data"
            ],
            "{name}"
        );
    }
    assert_eq!(
        issued_cookie_names(
            "https://auth.example.test",
            "__Secure-reverie.session_token"
        )
        .await,
        [
            "__Secure-reverie.session_token",
            "__Secure-reverie.session_data"
        ]
    );
    // Without the secure policy the prefix is dropped, as browsers reject it.
    assert_eq!(
        issued_cookie_names("http://localhost:3000", "__Secure-reverie.session_token").await,
        ["reverie.session_token", "reverie.session_data"]
    );
}
