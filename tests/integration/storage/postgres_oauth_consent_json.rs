use super::{Backend, Db, TestResult, postgres_tests};
use alibi::store::{
    CreateOAuthClient, CreateOAuthConsent, OAuthClientStore, OAuthConsent, UserStore,
};
use alibi::{AuthUser, CreateUser};
use serde_json::{Value, json};

postgres_tests!(oauth_consent_native_json_bindings_match_actual_postgres);

fn projection(consent: &OAuthConsent) -> Value {
    json!({"clientId":consent.client_id,"referenceId":consent.metadata["referenceId"],"scopes":consent.metadata["scopes"],
        "resources":consent.metadata["resources"],"requestedUserInfoClaims":consent.metadata["requestedUserInfoClaims"]})
}

async fn oauth_consent_native_json_bindings_match_actual_postgres<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("postgres-oauth-consent-json-secret-at-least-32")
        .await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-oauth-consent-json.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Consent owner")
                .with_email("consent-json@example.com"),
        )
        .await?;
    _ = store.create_oauth_client(CreateOAuthClient {
        client_id: "consent-json-client".into(), user_id: None, client_secret: None,
        metadata: json!({"redirect_uris":["https://client.example/callback"],"scope":"read","token_endpoint_auth_method":"none"}),
        created_at: "2026-01-01T00:00:00.123Z".parse()?,
    }).await?;
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        if action == "sql-failure" {
            _ = db.execute("ALTER TABLE \"oauthConsent\" ADD CONSTRAINT reject_consent_scopes CHECK (jsonb_array_length(scopes) < 2)", &[]).await?;
        }
        let outcome = match action {
            "create" => store
                .create_oauth_consent(CreateOAuthConsent {
                    client_id: "consent-json-client".into(),
                    user_id: Some(owner.id().into_owned()),
                    metadata: case["input"].clone(),
                    created_at: "2026-01-01T00:00:00.123Z".parse()?,
                })
                .await
                .map(Some),
            "update" | "sql-failure" => {
                store
                    .update_oauth_consent_metadata(
                        &id,
                        case["input"].clone(),
                        "2026-02-01T00:00:00.123Z".parse()?,
                    )
                    .await
            }
            "read" | "updated-read" => store.get_oauth_consent(&id).await,
            _ => panic!("unexpected source consent action: {action}"),
        };
        assert_eq!(
            json!(outcome.is_err()),
            case["failed"],
            "{action}: {outcome:?}"
        );
        let output = match outcome {
            Ok(Some(consent)) => {
                if action == "create" {
                    id = consent.id.clone();
                }
                assert_eq!(consent.id, id, "{action}");
                assert_eq!(
                    consent.user_id.as_deref(),
                    Some(owner.id().as_ref()),
                    "{action}"
                );
                projection(&consent)
            }
            Ok(None) => panic!("source consent must exist: {action}"),
            Err(error) => {
                assert!(
                    error.to_string().contains("reject_consent_scopes"),
                    "{error}"
                );
                Value::Null
            }
        };
        if action == "sql-failure" {
            _ = db
                .execute(
                    "ALTER TABLE \"oauthConsent\" DROP CONSTRAINT reject_consent_scopes",
                    &[],
                )
                .await?;
        }
        assert_eq!(output, case["output"], "{action}");
        let stored: Value = serde_json::from_str(&db.text("SELECT jsonb_build_object('clientId', \"clientId\", 'referenceId', \"referenceId\", 'scopes', scopes, 'resources', resources, 'requestedUserInfoClaims', \"requestedUserInfoClaims\")::text FROM \"oauthConsent\"", &[]).await?.unwrap())?;
        assert_eq!(stored, case["stored"], "{action}");
    }
    B::close(connection).await
}
