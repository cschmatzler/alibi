#![cfg(test)]
//! Persisted precision must survive every public organization JSON projection.
#![expect(
    unused_crate_dependencies,
    reason = "Cargo shares package dependencies across its library, binaries, and integration tests"
)]

#[cfg(test)]
#[path = "organization_timestamp_integration_tests/tests.rs"]
mod tests;

use better_auth::plugins::organization::types::{
    BasicMemberResponse, CreatedOrganizationResponse, MemberResponse, OrganizationResponse,
};

use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin};

use better_auth::{AuthBuilder, AuthConfig, BetterAuth};

use better_auth_core::{AuthRequest, CreateInvitation, HttpMethod};

use better_auth_seaorm::sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, Set};

use better_auth_seaorm::store::entities::{invitation, member, organization};

use better_auth_seaorm::{Database, SeaOrmStore};

use chrono::{DateTime, Utc};

use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

const ORIGIN: &str = "http://organization-timestamp.fixture.test";

const SOURCE: &str = "2001-02-03T04:05:06.227234Z";

const WIRE: &str = "2001-02-03T04:05:06.227Z";

async fn request(
    auth: &BetterAuth<Schema>,
    method: HttpMethod,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
    organization_id: Option<&str>,
) -> (better_auth_core::AuthResponse, Value) {
    let mut req = AuthRequest::new(method, format!("/api/auth{path}"));
    drop(req.headers.insert("origin".into(), ORIGIN.into()));
    if let Some(cookie) = cookie {
        drop(req.headers.insert("cookie".into(), cookie.into()));
    }
    if let Some(body) = body {
        drop(
            req.headers
                .insert("content-type".into(), "application/json".into()),
        );
        req.body = Some(serde_json::to_vec(&body).unwrap());
    }
    if let Some(id) = organization_id {
        drop(req.query.insert("organizationId".into(), id.into()));
    }
    let response = auth.handle_request(req).await.unwrap();
    let payload = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response.status, 200, "{path}: {payload}");
    (response, payload)
}
