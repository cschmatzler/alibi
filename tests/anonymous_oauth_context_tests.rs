//! Legacy state authority is exercised through real anonymous issuance and OAuth HTTP.
#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library and integration targets"
)]
#![cfg(feature = "axum")]
#![allow(
    clippy::unwrap_used,
    reason = "public lifecycle regression setup is fatal"
)]

#[cfg(test)]
#[path = "anonymous_oauth_context_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use axum::{
    Json, Router,
    routing::{get, post},
};
use better_auth::plugins::anonymous::{AnonymousConfig, AnonymousLink, LinkAnonymousAccount};
use better_auth::plugins::oauth::OAuthProvider;
use better_auth::plugins::{AnonymousPlugin, EmailPasswordPlugin, OAuthPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::{
    AuthRequest, AuthResponse, AuthResult, AuthSession, AuthUser, AuthVerification, HttpMethod,
};
use better_auth_seaorm::sea_orm::{ConnectionTrait, Statement};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

struct Linker(Arc<Mutex<Vec<Value>>>);

#[async_trait]
impl LinkAnonymousAccount for Linker {
    async fn link(&self, accounts: &AnonymousLink, _request: &AuthRequest) -> AuthResult<()> {
        self.0.lock().unwrap().push(json!({
            "anonymousUser": accounts.anonymous_user, "anonymousSession": accounts.anonymous_session,
            "newUser": accounts.new_user, "newSession": accounts.new_session,
        }));
        Ok(())
    }
}

fn request(path: &str, body: Option<Value>, cookies: Option<&str>) -> AuthRequest {
    let mut request = AuthRequest::new(
        if body.is_some() {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        path,
    );
    drop(
        request
            .headers
            .insert("origin".into(), "http://localhost:42615".into()),
    );
    if let Some(body) = body {
        request.body = Some(body.to_string().into_bytes());
        drop(
            request
                .headers
                .insert("content-type".into(), "application/json".into()),
        );
    }
    if let Some(cookies) = cookies {
        drop(request.headers.insert("cookie".into(), cookies.into()));
    }
    request
}

fn cookies(response: &AuthResponse) -> String {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| value.split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

async fn initiate(
    auth: &BetterAuth<Schema>,
    cookie: &str,
    foreign: &str,
) -> (String, String, Value) {
    let response = auth.handle_request(request("/api/auth/sign-in/social", Some(json!({
        "provider":"gitlab", "callbackURL":"/completed", "disableRedirect":true,
        "additionalData":{"serverContext":{"anonymousUserId":foreign},"_serverContextProof":"forged", "application":{"kept":true}},
    })), Some(cookie))).await.unwrap();
    assert_eq!(response.status, 200);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let url = url::Url::parse(body.get("url").unwrap().as_str().unwrap()).unwrap();
    let state = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    let row = auth
        .store()
        .get_verification_by_identifier(&format!("oauth:{state}"))
        .await
        .unwrap()
        .unwrap();
    (
        state,
        cookies(&response),
        serde_json::from_str(row.value()).unwrap(),
    )
}

async fn callback(auth: &BetterAuth<Schema>, state: &str, cookie: &str) -> AuthResponse {
    let mut request = request("/api/auth/callback/gitlab", None, Some(cookie));
    drop(
        request
            .query
            .insert("code".into(), "actual-local-code".into()),
    );
    drop(request.query.insert("state".into(), state.into()));
    auth.handle_request(request).await.unwrap()
}
