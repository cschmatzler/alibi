use super::*;

#[tokio::test]
async fn public_partial_policy_keeps_fixed_membership_limit_and_current_selection() {
    let config =
        AuthConfig::new("organization-creation-native-secret-at-least-32-chars").base_url(ORIGIN);
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database.clone()))
        .plugin(EmailPasswordPlugin::new().enable_username(false))
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            allow_user_to_create_organization: false,
            organization_limit: Some(1.0),
            creation_policy: Some(Arc::new(PartialOverride)),
            ..Default::default()
        }))
        .build()
        .await
        .unwrap();
    let (response, issued) = post(&auth, "/sign-up/email", json!({
        "email":"partial@creation-policy.fixture.test", "name":"Partial Policy", "password":"password123"
    }), None).await;
    assert_eq!(response.status, 200);
    let token = issued.get("token").and_then(Value::as_str).unwrap();
    let cookie = create_session_cookie(token, auth.config());
    let (response_2, first) = post(
        &auth,
        "/organization/create",
        json!({"name":"First", "slug":"partial-first"}),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        response_2.status, 200,
        "the allow callback overrides fixed false"
    );
    let selected_before = session::Entity::find()
        .filter(session::Column::Token.eq(token))
        .one(&database)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        selected_before.active_organization_id.as_deref(),
        Some(first.get("id").and_then(Value::as_str).unwrap())
    );
    let persisted_before = organization::Entity::find().all(&database).await.unwrap();
    let members_before = member::Entity::find().all(&database).await.unwrap();
    assert_eq!(persisted_before.len(), 1);
    assert_eq!(members_before.len(), 1);
    let (response_3, denied) = post(
        &auth,
        "/organization/create",
        json!({"name":"Second", "slug":"partial-second"}),
        Some(&cookie),
    )
    .await;
    assert_eq!(
        response_3.status, 403,
        "None from the default limit callback retains the configured limit"
    );
    assert_eq!(
        denied,
        json!({"code":"YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS", "message":"You have reached the maximum number of organizations"})
    );
    assert_eq!(
        organization::Entity::find().all(&database).await.unwrap(),
        persisted_before
    );
    assert_eq!(
        member::Entity::find().all(&database).await.unwrap(),
        members_before
    );
    assert_eq!(
        session::Entity::find()
            .filter(session::Column::Token.eq(token))
            .one(&database)
            .await
            .unwrap()
            .unwrap(),
        selected_before
    );
}
