#![cfg(test)]
//! Explicit application errors stay observable at the direct session API.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[path = "support/session_policy_store.rs"]
mod policy_store;

#[cfg(test)]
#[path = "session_policy_error_integration_tests/tests.rs"]
mod tests;

use better_auth::plugins::SessionManagementPlugin;
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::store::{SessionStore, UserStore};
use better_auth_core::{
    AuthRequest, AuthResponse, AuthSession, AuthUser, CreateSession, CreateUser, HttpMethod,
};
use better_auth_seaorm::{Database, SeaOrmStore};
use chrono::{Duration, Utc};
use policy_store::{PolicyStore, Schema};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

const ORIGIN: &str = "http://session-policy.fixture.test";

async fn get(auth: &BetterAuth<Schema>, path: &str, cookie: &str) -> (AuthResponse, Value) {
    let mut req = AuthRequest::new(HttpMethod::Get, format!("/api/auth{path}"));
    drop(req.headers.insert("cookie".into(), cookie.into()));
    let response = auth.handle_request(req).await.unwrap();
    let body = serde_json::from_slice(&response.body).unwrap();
    (response, body)
}
