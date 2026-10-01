use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep the ordered integration scenario and its persistence assertions together"
)]
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
    drop(signup.headers.insert("origin".into(), origin.into()));
    drop(
        signup
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    signup.body=Some(serde_json::to_vec(&json!({"email":"selector@fixture.test","name":"Selector Owner","password":"selector-password123"})).unwrap());
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
        .to_owned();
    let user_id = (*(*(data)
        .get("user")
        .expect("fixture contains the requested index"))
    .get("id")
    .expect("fixture contains the requested index"))
    .as_str()
    .unwrap();
    let mut create = AuthRequest::new(HttpMethod::Post, "/api/auth/organization/create");
    drop(create.headers.insert("origin".into(), origin.into()));
    drop(create.headers.insert("cookie".into(), cookie.clone()));
    drop(
        create
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    create.body = Some(serde_json::to_vec(&json!({"name":"Selected","slug":"selected"})).unwrap());
    let created = auth.handle_request(create).await.unwrap();
    assert_eq!(created.status, 200);
    let organization: Value = serde_json::from_slice(&created.body).unwrap();
    let before = auth.store().get_user_sessions(user_id).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(
        before.first().unwrap().active_organization_id(),
        (*(organization)
            .get("id")
            .expect("fixture contains the requested index"))
        .as_str()
    );
    for route in [
        "/api/auth/organization/get-organization",
        "/api/auth/organization/get-full-organization",
    ] {
        let mut lookup = AuthRequest::new(HttpMethod::Get, route);
        drop(lookup.headers.insert("cookie".into(), cookie.clone()));
        drop(lookup.query.insert("organizationId".into(), String::new()));
        drop(
            lookup
                .query
                .insert("organizationSlug".into(), String::new()),
        );
        let result = auth.handle_request(lookup).await.unwrap();
        assert_eq!(result.status, 200);
        let body: Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(
            (*(body).get("id").unwrap_or(&Value::Null)),
            (*(organization)
                .get("id")
                .expect("fixture contains the requested index"))
        );
        assert_eq!(
            (*(body).get("metadata").unwrap_or(&Value::Null)),
            Value::Null
        );
        if route.ends_with("get-organization") {
            assert!(body.get("members").is_none());
        } else {
            assert_eq!(
                (*(body).get("members").unwrap_or(&Value::Null))
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
    assert_eq!(
        auth.store().get_user_sessions(user_id).await.unwrap(),
        before
    );
}
