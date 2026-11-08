use super::{Backend, Db, TestResult, postgres_tests};
use alibi::store::{CreateOAuthResource, OAuthClientStore, OAuthResource};
use serde_json::{Value, json};

postgres_tests!(oauth_resource_native_json_bindings_match_actual_postgres);

fn projection(resource: &OAuthResource) -> Value {
    json!({"identifier":resource.identifier,"name":resource.metadata["name"],"allowedScopes":resource.metadata["allowedScopes"],
        "customClaims":resource.metadata["customClaims"],"metadata":resource.metadata["metadata"]})
}

async fn oauth_resource_native_json_bindings_match_actual_postgres<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("postgres-oauth-resource-json-secret-at-least-32")
        .await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-oauth-resource-json.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        if action == "sql-failure" {
            _ = db.execute("ALTER TABLE \"oauthResource\" ADD CONSTRAINT reject_resource_scopes CHECK (jsonb_array_length(\"allowedScopes\") < 2)", &[]).await?;
        }
        let outcome = match action {
            "create" => store
                .create_oauth_resource(CreateOAuthResource {
                    identifier: "https://resource.example".into(),
                    metadata: case["input"].clone(),
                    created_at: "2026-01-01T00:00:00.123Z".parse()?,
                })
                .await
                .map(Some),
            "sql-failure" | "update" => {
                store
                    .update_oauth_resource(
                        "https://resource.example",
                        case["input"].clone(),
                        "2026-02-01T00:00:00.123Z".parse()?,
                    )
                    .await
            }
            "read" | "updated-read" => store.get_oauth_resource("https://resource.example").await,
            _ => panic!("unexpected source resource action: {action}"),
        };
        assert_eq!(
            json!(outcome.is_err()),
            case["failed"],
            "{action}: {outcome:?}"
        );
        let output = match outcome {
            Ok(Some(resource)) => {
                if action == "create" {
                    id = resource.id.clone();
                }
                assert_eq!(resource.id, id, "{action}");
                projection(&resource)
            }
            Ok(None) => panic!("source resource must exist: {action}"),
            Err(error) => {
                assert!(
                    error.to_string().contains("reject_resource_scopes"),
                    "{error}"
                );
                Value::Null
            }
        };
        if action == "sql-failure" {
            _ = db
                .execute(
                    "ALTER TABLE \"oauthResource\" DROP CONSTRAINT reject_resource_scopes",
                    &[],
                )
                .await?;
        }
        assert_eq!(output, case["output"], "{action}");
        let stored: Value = serde_json::from_str(&db.text("SELECT jsonb_build_object('identifier', identifier, 'name', name, 'allowedScopes', \"allowedScopes\", 'customClaims', \"customClaims\", 'metadata', metadata)::text FROM \"oauthResource\"", &[]).await?.unwrap())?;
        assert_eq!(stored, case["stored"], "{action}");
    }
    B::close(connection).await
}
