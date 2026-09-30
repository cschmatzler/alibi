//! The differential identity harness cannot represent a deliberately blank ID.
//! Preserve that pinned-runtime request contract at the real SQL-backed handler.
#![expect(
    clippy::unwrap_used,
    reason = "real SQL setup and public-handler results must succeed"
)]
use better_auth::plugins::{EmailPasswordPlugin, OrganizationPlugin};
use better_auth::{AuthBuilder, AuthConfig};
use better_auth_core::{AuthRequest, AuthSession, HttpMethod};
use better_auth_seaorm::{Database, SeaOrmStore};
use serde_json::{Value, json};

type Schema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

#[tokio::test]
async fn blank_organization_selector_uses_persisted_active_organization_without_mutation() {
    let origin = "http://organization-selector.fixture.test";
    let config = AuthConfig::new("organization-selector-fixture-secret-at-least-32-characters")
        .base_url(origin);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(OrganizationPlugin::new())
        .build()
        .await
        .unwrap();
    let mut signup = AuthRequest::new(HttpMethod::Post, "/api/auth/sign-up/email");
    _ = signup.headers.insert("origin".into(), origin.into());
    _ = signup
        .headers
        .insert("content-type".into(), "application/json".into());
    _ = signup.body=Some(serde_json::to_vec(&json!({"email":"selector@fixture.test","name":"Selector Owner","password":"selector-password123"})).unwrap());
    let response = auth.handle_request(signup).await.unwrap();
    assert_eq!(response.status, 200);
    let data: Value = serde_json::from_slice(&response.body).unwrap();
    let cookie = response
        .headers
        .get("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let user_id = data["user"]["id"].as_str().unwrap();
    let mut create = AuthRequest::new(HttpMethod::Post, "/api/auth/organization/create");
    _ = create.headers.insert("origin".into(), origin.into());
    _ = create.headers.insert("cookie".into(), cookie.clone());
    _ = create
        .headers
        .insert("content-type".into(), "application/json".into());
    _ = create.body =
        Some(serde_json::to_vec(&json!({"name":"Selected","slug":"selected"})).unwrap());
    let created = auth.handle_request(create).await.unwrap();
    assert_eq!(created.status, 200);
    let organization: Value = serde_json::from_slice(&created.body).unwrap();
    let before = auth.store().get_user_sessions(user_id).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(
        before.first().unwrap().active_organization_id(),
        organization["id"].as_str()
    );
    let mut lookup = AuthRequest::new(HttpMethod::Get, "/api/auth/organization/get-organization");
    _ = lookup.headers.insert("cookie".into(), cookie);
    _ = lookup.query.insert("organizationId".into(), String::new());
    _ = lookup
        .query
        .insert("organizationSlug".into(), String::new());
    let result = auth.handle_request(lookup).await.unwrap();
    assert_eq!(result.status, 200);
    let body: Value = serde_json::from_slice(&result.body).unwrap();
    assert_eq!(body["id"], organization["id"]);
    assert_eq!(body["metadata"], Value::Null);
    assert!(body.get("members").is_none());
    assert_eq!(
        auth.store().get_user_sessions(user_id).await.unwrap(),
        before
    );
}
