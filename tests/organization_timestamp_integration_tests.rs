//! Persisted precision must survive every public organization JSON projection.
#![expect(
    clippy::unwrap_used,
    reason = "persisted integration setup and endpoint results must succeed"
)]

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
    _ = req.headers.insert("origin".into(), ORIGIN.into());
    if let Some(cookie) = cookie {
        _ = req.headers.insert("cookie".into(), cookie.into());
    }
    if let Some(body) = body {
        _ = req
            .headers
            .insert("content-type".into(), "application/json".into());
        req.body = Some(serde_json::to_vec(&body).unwrap());
    }
    if let Some(id) = organization_id {
        _ = req.query.insert("organizationId".into(), id.into());
    }
    let response = auth.handle_request(req).await.unwrap();
    let payload = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response.status, 200, "{path}: {payload}");
    (response, payload)
}

#[tokio::test]
async fn organization_json_preserves_persisted_instants_at_javascript_millisecond_precision() {
    let config = AuthConfig::new("organization-timestamp-fixture-secret-at-least-32-characters")
        .base_url(ORIGIN);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database.clone()))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(OrganizationPlugin::new())
        .build()
        .await
        .unwrap();
    let (registered, signup) = request(&auth, HttpMethod::Post, "/sign-up/email", Some(json!({"email":"timestamp-owner@fixture.test","password":"timestamp-password123","name":"Timestamp Owner"})), None, None).await;
    let cookie = registered
        .headers
        .get("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let user_id = signup.pointer("/user/id").and_then(Value::as_str).unwrap();
    let (_, created) = request(
        &auth,
        HttpMethod::Post,
        "/organization/create",
        Some(json!({"name":"Timestamp Organization","slug":"timestamp-organization"})),
        Some(cookie),
        None,
    )
    .await;
    let organization_id = created.get("id").and_then(Value::as_str).unwrap();
    let member_id = created
        .pointer("/members/0/id")
        .and_then(Value::as_str)
        .unwrap();
    let source: DateTime<Utc> = SOURCE.parse().unwrap();
    let mut org = organization::Entity::find_by_id(organization_id)
        .one(&database)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    org.created_at = Set(source);
    org.updated_at = Set(source);
    _ = org.update(&database).await.unwrap();
    let mut owner = member::Entity::find_by_id(member_id)
        .one(&database)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    owner.created_at = Set(source);
    _ = owner.update(&database).await.unwrap();

    let (_, full) = request(
        &auth,
        HttpMethod::Get,
        "/organization/get-full-organization",
        None,
        Some(cookie),
        Some(organization_id),
    )
    .await;
    assert_eq!(full.get("createdAt"), Some(&json!(WIRE)));
    assert_eq!(full.pointer("/members/0/createdAt"), Some(&json!(WIRE)));
    assert_eq!(full.pointer("/members/0/id"), Some(&json!(member_id)));
    assert_eq!(full.pointer("/members/0/userId"), Some(&json!(user_id)));
    assert_eq!(
        full.pointer("/members/0/organizationId"),
        Some(&json!(organization_id))
    );
    assert_eq!(full.pointer("/members/0/role"), Some(&json!("owner")));

    // The typed server interfaces serialize the same actual rows. This covers
    // create/accept DTOs and core entities outside the full-organization route.
    let org = auth
        .store()
        .get_organization_by_id(organization_id)
        .await
        .unwrap()
        .unwrap();
    let owner = auth
        .store()
        .get_member_by_id(member_id)
        .await
        .unwrap()
        .unwrap();
    let user = auth.store().get_user_by_id(user_id).await.unwrap().unwrap();
    assert_eq!(org.created_at, source);
    assert_eq!(owner.created_at, source);
    for value in [
        serde_json::to_value(&org).unwrap(),
        serde_json::to_value(CreatedOrganizationResponse::from_organization(&org)).unwrap(),
        serde_json::to_value(OrganizationResponse::from_organization(&org)).unwrap(),
    ] {
        assert_eq!(value.get("createdAt"), Some(&json!(WIRE)));
        assert_eq!(value.get("id"), Some(&json!(organization_id)));
        assert_eq!(value.get("name"), Some(&json!("Timestamp Organization")));
    }
    assert_eq!(
        serde_json::to_value(&org).unwrap().get("updatedAt"),
        Some(&json!(WIRE))
    );
    for value in [
        serde_json::to_value(&owner).unwrap(),
        serde_json::to_value(BasicMemberResponse::from_member(&owner)).unwrap(),
        serde_json::to_value(MemberResponse::from_member_and_user(&owner, &user)).unwrap(),
    ] {
        assert_eq!(value.get("createdAt"), Some(&json!(WIRE)));
        assert_eq!(value.get("id"), Some(&json!(member_id)));
        assert_eq!(value.get("organizationId"), Some(&json!(organization_id)));
        assert_eq!(value.get("userId"), Some(&json!(user_id)));
        assert_eq!(value.get("role"), Some(&json!("owner")));
    }
    let expires: DateTime<Utc> = "2035-02-03T04:05:06.227234Z".parse().unwrap();
    let invitation = auth
        .store()
        .create_invitation(CreateInvitation::new(
            organization_id,
            "timestamp-invitee@fixture.test",
            "member",
            user_id,
            expires,
        ))
        .await
        .unwrap();
    let mut row = invitation::Entity::find_by_id(&invitation.id)
        .one(&database)
        .await
        .unwrap()
        .unwrap()
        .into_active_model();
    row.created_at = Set(source);
    _ = row.update(&database).await.unwrap();
    let persisted = auth
        .store()
        .get_invitation_by_id(&invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.created_at, source);
    assert_eq!(persisted.expires_at, expires);
    let encoded = serde_json::to_value(&persisted).unwrap();
    assert_eq!(encoded.get("createdAt"), Some(&json!(WIRE)));
    assert_eq!(
        encoded.get("expiresAt"),
        Some(&json!("2035-02-03T04:05:06.227Z"))
    );
    assert_eq!(encoded.get("organizationId"), Some(&json!(organization_id)));
    assert_eq!(encoded.get("inviterId"), Some(&json!(user_id)));
}
