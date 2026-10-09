//! Native HTTP journeys: real Axum, SQLite, hashing and client cookie handling.
#![allow(
    clippy::pedantic,
    reason = "test code favors explicit, linear scenarios over pedantic style"
)]
#![expect(
    unused_crate_dependencies,
    reason = "integration targets share the package dependency list"
)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "journeys fail at missing protocol fields with descriptive assertions"
)]

mod support;

use reqwest::StatusCode;
use serde_json::{Value, json};
use support::{Backend, Browser, Server, TestResult};

async fn cookies_authenticate_isolated_clients_and_signout_revokes_the_credential(
    backend: Backend,
) -> TestResult {
    let server = Server::start(backend).await?;
    let alice = Browser::new(&server)?;
    let bob = Browser::new(&server)?;
    let anonymous = Browser::new(&server)?;
    let alice_user = alice.signup("alice@example.test").await?;
    let bob_user = bob.signup("bob@example.test").await?;
    assert_ne!(alice_user["user"]["id"], bob_user["user"]["id"]);
    assert_eq!(alice.profile().await?["userId"], alice_user["user"]["id"]);
    assert_eq!(bob.profile().await?["userId"], bob_user["user"]["id"]);
    assert_eq!(
        anonymous.get("/private").send().await?.status(),
        StatusCode::UNAUTHORIZED
    );

    // A rejected cross-origin mutation must leave the session usable.
    let rejected = alice
        .post("/api/auth/sign-out", json!({}))
        .header("origin", "https://untrusted.example")
        .send()
        .await?;
    assert_eq!(
        Browser::json(rejected, StatusCode::FORBIDDEN).await?["message"],
        "Invalid origin"
    );
    assert_eq!(alice.profile().await?["userId"], alice_user["user"]["id"]);

    let old_cookie = alice.cookies()?;
    let response = alice.post("/api/auth/sign-out", json!({})).send().await?;
    let body = Browser::json(response, StatusCode::OK).await?;
    assert_eq!(body["success"], true);
    assert!(
        alice.cookies().is_err(),
        "signout must expire the client's cookie"
    );
    assert_eq!(
        alice.get("/private").send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    // Prove server-side revocation too, independently of the jar forgetting it.
    assert_eq!(
        anonymous
            .get("/private")
            .header("cookie", old_cookie)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(bob.profile().await?["userId"], bob_user["user"]["id"]);
    server.shutdown().await
}

async fn delivered_reset_link_changes_credentials_once_and_revokes_existing_sessions(
    backend: Backend,
) -> TestResult {
    let mut server = Server::start(backend).await?;
    let browser = Browser::new(&server)?;
    let user = browser.signup("reset@example.test").await?;
    let reset = Browser::new(&server)?;
    let response = reset
        .post(
            "/api/auth/request-password-reset",
            json!({
                "email":"reset@example.test", "redirectTo":format!("{}/reset", server.origin)
            }),
        )
        .send()
        .await?;
    assert_eq!(
        Browser::json(response, StatusCode::OK).await?["status"],
        true
    );
    // This records only delivery; the real handler creates and persists the token.
    let delivery = server.delivery().await?;
    assert_eq!(delivery.user["id"], user["user"]["id"]);
    let response = reset.client.get(&delivery.url).send().await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let destination = url::Url::parse(
        response
            .headers()
            .get("location")
            .expect("reset redirect")
            .to_str()?,
    )?;
    assert_eq!(destination.origin().ascii_serialization(), server.origin);
    assert_eq!(destination.path(), "/reset");
    let token = destination
        .query_pairs()
        .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
        .expect("delivered reset token");
    let reset_body = json!({"token":token, "newPassword":"replacement-password-456"});
    let response = reset
        .post("/api/auth/reset-password", reset_body.clone())
        .send()
        .await?;
    assert_eq!(
        Browser::json(response, StatusCode::OK).await?["status"],
        true
    );
    assert_eq!(
        browser.get("/private").send().await?.status(),
        StatusCode::UNAUTHORIZED
    );

    let response = reset
        .post("/api/auth/reset-password", reset_body)
        .send()
        .await?;
    assert_eq!(
        Browser::json(response, StatusCode::BAD_REQUEST).await?["message"],
        "Invalid token"
    );
    let response = reset
        .post(
            "/api/auth/sign-in/email",
            json!({"email":"reset@example.test", "password":support::PASSWORD}),
        )
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = reset
        .post(
            "/api/auth/sign-in/email",
            json!({"email":"reset@example.test", "password":"replacement-password-456"}),
        )
        .send()
        .await?;
    let signed_in: Value = Browser::json(response, StatusCode::OK).await?;
    assert_eq!(signed_in["user"]["id"], user["user"]["id"]);
    assert_eq!(reset.profile().await?["userId"], user["user"]["id"]);
    server.shutdown().await
}

macro_rules! journeys {
    ($module:ident,$backend:expr) => {
        mod $module {
            use super::*;
            #[tokio::test]
            async fn cookies_authenticate_isolated_clients_and_signout_revokes_the_credential()
            -> TestResult {
                super::cookies_authenticate_isolated_clients_and_signout_revokes_the_credential(
                    $backend,
                )
                .await
            }
            #[tokio::test]
            async fn delivered_reset_link_changes_credentials_once_and_revokes_existing_sessions()
            -> TestResult {
                super::delivered_reset_link_changes_credentials_once_and_revokes_existing_sessions(
                    $backend,
                )
                .await
            }
        }
    };
}
journeys!(on_sqlx, Backend::Sqlx);
journeys!(on_seaorm, Backend::SeaOrm);
