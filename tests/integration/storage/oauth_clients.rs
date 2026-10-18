//! Atomic registration owns the row and every newly ensured resource relation.
use super::{Backend, Db, TestResult, backend_tests};
use alibi::store::oauth_clients::{
    OAuthClientRegistrationWriteError, PersistOAuthClientRegistration,
};
use alibi::store::{CreateOAuthClient, OAuthClientStore};
use chrono::Utc;
use serde_json::json;

backend_tests!(oauth_registration_rolls_back_row_and_links_on_storage_fault);

async fn oauth_registration_rolls_back_row_and_links_on_storage_fault<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("atomic-registration-test-secret-long-enough")
        .await?;
    let now = Utc::now();
    for identifier in ["first", "fault", "retained", "collision"] {
        store
            .create_oauth_resource(alibi::store::CreateOAuthResource {
                identifier: identifier.into(),
                metadata: json!({"name":identifier}),
                created_at: now,
            })
            .await?;
    }
    let input = PersistOAuthClientRegistration {
        client: CreateOAuthClient {
            client_id: "document".into(),
            user_id: None,
            client_secret: None,
            metadata: json!({"client_discovery_id":"document-owner","client_name":"Initial","redirect_uris":[]}),
            created_at: now,
        },
        discovery_id: "document-owner".into(),
        replace: false,
        existing_created_at: Some(now),
        resources: vec!["first".into(), "fault".into()],
        updated_at: now,
    };
    _ = db.execute("CREATE TRIGGER registration_fault BEFORE INSERT ON \"oauthClientResource\" WHEN NEW.\"resourceId\"='fault' BEGIN SELECT RAISE(ABORT,'real registration storage failure'); END", &[]).await?;
    let before = db.tables(&["oauthClient", "oauthClientResource"]).await?;
    let error = store
        .persist_oauth_client_registration(input.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("real registration storage failure"),
        "{error}"
    );
    assert_eq!(
        db.tables(&["oauthClient", "oauthClientResource"]).await?,
        before,
        "a later relation fault must roll back the client and earlier link"
    );
    _ = db.execute("DROP TRIGGER registration_fault", &[]).await?;
    let mut initial = input.clone();
    initial.resources = vec!["retained".into()];
    let created = store
        .persist_oauth_client_registration(initial.clone())
        .await?
        .unwrap();
    _ = db.execute("UPDATE \"oauthClientResource\" SET metadata='{\"operator\":true}' WHERE \"clientId\"='document' AND \"resourceId\"='retained'", &[]).await?;
    let mut replacement = input.clone();
    replacement.replace = true;
    replacement.client.metadata["client_name"] = json!("Replacement");
    _ = db.execute("CREATE TRIGGER registration_fault BEFORE INSERT ON \"oauthClientResource\" WHEN NEW.\"resourceId\"='fault' BEGIN SELECT RAISE(ABORT,'real registration storage failure'); END", &[]).await?;
    let before = db.tables(&["oauthClient", "oauthClientResource"]).await?;
    let error = store
        .persist_oauth_client_registration(replacement.clone())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("real registration storage failure"),
        "{error}"
    );
    assert_eq!(
        db.tables(&["oauthClient", "oauthClientResource"]).await?,
        before,
        "replacement rollback retains the prior row, links, and their metadata"
    );
    _ = db.execute("DROP TRIGGER registration_fault", &[]).await?;
    replacement.discovery_id = "another-owner".into();
    assert!(
        store
            .persist_oauth_client_registration(replacement.clone())
            .await?
            .is_none()
    );
    assert_eq!(
        db.tables(&["oauthClient", "oauthClientResource"]).await?,
        before
    );
    replacement.discovery_id = "document-owner".into();
    let updated = store
        .persist_oauth_client_registration(replacement.clone())
        .await?
        .unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.metadata["client_name"], "Replacement");
    let mut links = store
        .list_oauth_client_resources("document")
        .await?
        .into_iter()
        .map(|link| link.resource_id)
        .collect::<Vec<_>>();
    links.sort();
    assert_eq!(links, vec!["fault", "first", "retained"]);
    let mut config = alibi::AuthConfig::new("atomic-registration-test-secret-long-enough");
    config.advanced.database.default_find_many_limit = 1;
    let limited = B::store(std::sync::Arc::new(config), &connection);
    assert_eq!(
        limited.list_oauth_client_resources("document").await?.len(),
        1
    );
    for resource_id in ["fault", "first", "retained"] {
        assert!(
            limited
                .has_oauth_client_resource("document", resource_id)
                .await?
        );
    }
    assert!(
        !limited
            .has_oauth_client_resource("document", "missing")
            .await?
    );
    assert_eq!(
        store
            .list_oauth_client_resources("document")
            .await?
            .into_iter()
            .find(|link| link.resource_id == "retained")
            .unwrap()
            .metadata,
        json!({"operator":true})
    );
    // An actual unique row collision remains distinguishable from a trigger failure.
    assert!(matches!(
        store.persist_oauth_client_registration(initial).await,
        Err(OAuthClientRegistrationWriteError::Collision {
            resource_id: None,
            ..
        })
    ));
    let before = db.tables(&["oauthClient", "oauthClientResource"]).await?;
    _ = db.execute("CREATE TRIGGER registration_link_collision BEFORE INSERT ON \"oauthClientResource\" WHEN NEW.\"resourceId\"='collision' AND NEW.id<>'winner' BEGIN INSERT INTO \"oauthClientResource\" (id,\"clientId\",\"resourceId\",\"createdAt\") VALUES('winner',NEW.\"clientId\",NEW.\"resourceId\",NEW.\"createdAt\"); END", &[]).await?;
    let mut collision = replacement.clone();
    collision.resources = vec!["collision".into()];
    collision.client.metadata["client_name"] = json!("Must roll back");
    assert!(
        matches!(store.persist_oauth_client_registration(collision).await, Err(OAuthClientRegistrationWriteError::Collision {resource_id: Some(id), ..}) if id == "collision")
    );
    assert_eq!(
        db.tables(&["oauthClient", "oauthClientResource"]).await?,
        before
    );
    _ = db
        .execute("DROP TRIGGER registration_link_collision", &[])
        .await?;
    store.delete_oauth_client("document").await?;
    assert!(
        store
            .persist_oauth_client_registration(replacement)
            .await?
            .is_none()
    );
    Ok(())
}
