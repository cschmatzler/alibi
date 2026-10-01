use super::*;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

async fn start_github_mock_server(
    profile: Value,
    emails: Value,
) -> (String, String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = std::sync::Arc::clone(&requests);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let profile = profile.clone();
            let emails = emails.clone();
            let requests_2 = std::sync::Arc::clone(&captured_requests);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(
                    (buffer)
                        .get(..read)
                        .expect("fixture contains the requested index"),
                )
                .to_string();
                requests_2.lock().await.push(request.clone());

                let (status, body) = if request.contains("/user/emails") {
                    ("200 OK", emails.to_string())
                } else if request.contains("/user") {
                    ("200 OK", profile.to_string())
                } else {
                    (
                        "404 Not Found",
                        serde_json::json!({ "error": "not found" }).to_string(),
                    )
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );

                drop(stream.write_all(response.as_bytes()).await);
                drop(stream.flush().await);
            });
        }
    });

    let base_url = format!("http://127.0.0.1:{}", addr.port());
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    (
        format!("{base_url}/user"),
        format!("{base_url}/user/emails"),
        requests,
    )
}

// Upstream source: packages/core/src/social-providers/github.ts :: github().createAuthorizationURL default scope list.
#[test]
fn github_provider_uses_ts_default_scopes() {
    let provider = OAuthProvider::github("github-client-id", "github-client-secret");

    assert_eq!(
        provider.scopes,
        vec!["read:user".to_owned(), "user:email".to_owned()]
    );
    assert!(provider.get_user_info.is_some());
    assert!(provider.map_user_info.is_none());
}

// Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo fallback from profile.email to /user/emails, login fallback for name, and request headers.
#[tokio::test]
async fn github_provider_get_user_info_uses_email_fallback_and_login_name() {
    let (user_url, emails_url, requests) = start_github_mock_server(
        serde_json::json!({
            "id": 42,
            "login": "octocat",
            "name": null,
            "email": null,
            "avatar_url": "https://avatars.githubusercontent.com/u/42?v=4",
        }),
        serde_json::json!([
            {
                "email": "octocat@example.com",
                "primary": true,
                "verified": true,
                "visibility": "private"
            },
            {
                "email": "secondary@example.com",
                "primary": false,
                "verified": false,
                "visibility": "private"
            }
        ]),
    )
    .await;

    let provider = OAuthProvider::github_with_endpoints(
        "github-client-id",
        "github-client-secret",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        &user_url,
        &emails_url,
    );
    let handler = provider.get_user_info.as_ref().unwrap();

    let response = handler
        .get_user_info(OAuthUserInfoRequest {
            access_token: Some("github-access-token".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.user.id, "42");
    assert_eq!(response.user.email, "octocat@example.com");
    assert_eq!(response.user.name.as_deref(), Some("octocat"));
    assert_eq!(
        response.user.image.as_deref(),
        Some("https://avatars.githubusercontent.com/u/42?v=4")
    );
    assert!(response.user.email_verified);
    assert_eq!(
        (*(response.data)
            .get("email")
            .expect("fixture contains the requested index")),
        serde_json::json!("octocat@example.com")
    );

    let requests = requests.lock().await;
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        let lowered = request.to_ascii_lowercase();
        assert!(lowered.contains("authorization: bearer github-access-token"));
        assert!(lowered.contains("user-agent: better-auth"));
    }
}

// Upstream source: packages/core/src/social-providers/github.ts :: github().getUserInfo keeps profile.email when present and resolves verified status from the matching email record.
#[tokio::test]
async fn github_provider_get_user_info_keeps_inline_email() {
    let (user_url, emails_url, _) = start_github_mock_server(
        serde_json::json!({
            "id": "github-inline-email",
            "login": "octocat",
            "name": "Octo Cat",
            "email": "public@example.com",
            "avatar_url": null,
        }),
        serde_json::json!([
            {
                "email": "primary@example.com",
                "primary": true,
                "verified": true,
                "visibility": "private"
            },
            {
                "email": "public@example.com",
                "primary": false,
                "verified": false,
                "visibility": "public"
            }
        ]),
    )
    .await;

    let provider = OAuthProvider::github_with_endpoints(
        "github-client-id",
        "github-client-secret",
        "https://github.com/login/oauth/authorize",
        "https://github.com/login/oauth/access_token",
        &user_url,
        &emails_url,
    );
    let handler = provider.get_user_info.as_ref().unwrap();

    let response = handler
        .get_user_info(OAuthUserInfoRequest {
            access_token: Some("github-access-token".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(response.user.email, "public@example.com");
    assert_eq!(response.user.name.as_deref(), Some("Octo Cat"));
    assert!(!response.user.email_verified);
}
