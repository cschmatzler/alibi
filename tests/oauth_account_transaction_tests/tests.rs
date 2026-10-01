use super::*;

#[tokio::test]
async fn rejected_account_insert_rolls_back_new_oauth_user_and_retry_commits_binding() {
    let config = AuthConfig::new("oauth-atomic-fixture-secret-at-least-32-characters");
    let database = Database::connect("sqlite::memory:").await.unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
        .await
        .unwrap();
    let mut provider = OAuthProvider::google("local-client", "local-secret");
    provider.verify_id_token = Some(Arc::new(Profile));
    provider.get_user_info = Some(Arc::new(Profile));
    let auth = AuthBuilder::new(config.clone())
        .store(SeaOrmStore::<Schema>::new(config, database.clone()))
        .plugin(OAuthPlugin::new().add_provider("google", provider))
        .build()
        .await
        .unwrap();
    _ = database.execute_raw(Statement::from_string(DbBackend::Sqlite, "CREATE TRIGGER reject_oauth_account BEFORE INSERT ON accounts WHEN NEW.provider_id = 'google' BEGIN SELECT RAISE(FAIL, 'account insert veto'); END".to_owned())).await.unwrap();
    let rejected = auth.handle_request(request()).await.unwrap();
    assert_eq!(rejected.status, 403);
    assert!(
        !rejected
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
    );
    assert!(
        auth.store()
            .get_account("google", "google-transaction-owner")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.store()
            .get_user_by_email("atomic@oauth.fixture.test")
            .await
            .unwrap()
            .is_none(),
        "a failed account insert must roll back its newly created user"
    );
    _ = database
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "DROP TRIGGER reject_oauth_account".to_owned(),
        ))
        .await
        .unwrap();
    let accepted = auth.handle_request(request()).await.unwrap();
    assert_eq!(accepted.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&accepted.body).unwrap();
    let token = (*(body).get("token").unwrap_or(&serde_json::Value::Null))
        .as_str()
        .unwrap();
    let user = auth
        .store()
        .get_user_by_email("atomic@oauth.fixture.test")
        .await
        .unwrap()
        .unwrap();
    let account = auth
        .store()
        .get_account("google", "google-transaction-owner")
        .await
        .unwrap()
        .unwrap();
    let session = auth.store().get_session(token).await.unwrap().unwrap();
    assert_eq!(account.user_id(), user.id());
    assert_eq!(session.user_id(), user.id());
    assert_eq!(
        (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
            .get("id")
            .unwrap_or(&serde_json::Value::Null)),
        user.id().to_string()
    );
    assert!(
        accepted
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
    );
}
