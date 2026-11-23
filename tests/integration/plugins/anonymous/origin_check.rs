//! Anonymous sign-in validates the request origin like the other sign-ins.
//! Upstream: packages/better-auth/src/plugins/anonymous/anon.test.ts
//! "anonymous sign-in origin validation".
#![allow(
    clippy::unwrap_used,
    reason = "integration setup and dispatch must succeed"
)]

use crate::contract::helpers::{TestAuthOptions, create_test_auth_with_options};
use alibi::{AuthRequest, HttpMethod};

fn sign_in(headers: &[(&str, &str)]) -> AuthRequest {
    let mut request = AuthRequest::new(HttpMethod::Post, "/sign-in/anonymous");
    for (name, value) in headers {
        drop(
            request
                .headers
                .insert((*name).to_owned(), (*value).to_owned()),
        );
    }
    request
}

#[tokio::test]
async fn anonymous_sign_in_rejects_untrusted_origins() {
    let auth = create_test_auth_with_options(TestAuthOptions {
        anonymous_enabled: true,
        ..Default::default()
    })
    .await;
    for headers in [
        &[
            ("origin", "https://untrusted.example"),
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-mode", "no-cors"),
        ][..],
        &[("origin", "https://untrusted.example")][..],
    ] {
        let response = Box::pin(auth.handle_request(sign_in(headers)))
            .await
            .unwrap();
        assert_eq!(response.status, 403, "{headers:?}");
        assert_eq!(response.headers.get_all("set-cookie").count(), 0);
    }
    for headers in [
        &[
            ("origin", "http://localhost:3000"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "cors"),
        ][..],
        &[][..],
    ] {
        let response = Box::pin(auth.handle_request(sign_in(headers)))
            .await
            .unwrap();
        assert_eq!(response.status, 200, "{headers:?}");
    }
}
