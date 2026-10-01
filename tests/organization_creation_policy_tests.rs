#![cfg(test)]
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]
//! Public partial-policy overrides preserve fixed limits and persisted session selection.

#[cfg(test)]
#[path = "organization_creation_policy_tests/tests.rs"]
mod tests;

use async_trait::async_trait;
use better_auth::plugins::organization::{OrganizationConfig, OrganizationCreationPolicy};
use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin};
use better_auth::{AuthBuilder, AuthConfig, BetterAuth};
use better_auth_core::utils::cookie_utils::create_session_cookie;
use better_auth_core::wire::UserView;
use better_auth_core::{AuthRequest, AuthResponse, AuthResult, HttpMethod};
use better_auth_seaorm::sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use better_auth_seaorm::store::entities::{member, organization, session};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};
use std::sync::Arc;

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://creation-policy.fixture.test";

#[derive(Debug)]
struct PartialOverride;

#[async_trait]
impl OrganizationCreationPolicy for PartialOverride {
    async fn allow_creation(&self, _user: &UserView) -> AuthResult<Option<bool>> {
        Ok(Some(true))
    }
    // Intentionally use the public default limit callback (None), preserving the fixed limit.
}

async fn post(
    auth: &BetterAuth<Schema>,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> (AuthResponse, Value) {
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(request.headers.insert("origin".into(), ORIGIN.into()));
    if let Some(cookie) = cookie {
        drop(request.headers.insert("cookie".into(), cookie.into()));
    }
    request.body = Some(serde_json::to_vec(&body).unwrap());
    let response = auth.handle_request(request).await.unwrap();
    let value = serde_json::from_slice(&response.body).unwrap();
    (response, value)
}
