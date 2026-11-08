use super::{Backend, Db, TestResult, postgres_tests};
use alibi::store::{CreateOAuthClient, OAuthClient, OAuthClientStore};
use serde_json::{Value, json};

postgres_tests!(oauth_client_native_json_bindings_match_actual_postgres);

fn metadata(updated: bool) -> Value {
    json!({"client_discovery_id":"registry-live","client_name":if updated {"Updated registry"} else {"Registry client"},"token_endpoint_auth_method":"none","disabled":false,
        "scope":if updated {"email profile"} else {"email"},
        "redirect_uris":[if updated {"https://app.fixture.test/after"} else {"https://app.fixture.test/callback"}],
        "grant_types":if updated {json!(["authorization_code","refresh_token"])} else {json!(["authorization_code"])},"response_types":["code"]})
}

fn projection(client: &OAuthClient) -> Value {
    json!({"clientId":client.client_id,"clientDiscoveryId":client.metadata["client_discovery_id"],"name":client.metadata["client_name"],
        "scopes":client.metadata["scope"].as_str().unwrap().split(' ').collect::<Vec<_>>(),"grantTypes":client.metadata["grant_types"],
        "responseTypes":client.metadata["response_types"],"redirectUris":client.metadata["redirect_uris"]})
}

async fn oauth_client_native_json_bindings_match_actual_postgres<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("postgres-oauth-json-secret-at-least-32-characters")
        .await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-oauth-client-json.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        if action == "sql-failure" {
            _ = db.execute("ALTER TABLE \"oauthClient\" ADD CONSTRAINT reject_oauth_scope CHECK (jsonb_array_length(scopes) < 2)", &[]).await?;
        }
        let outcome = match action {
            "create" => store
                .create_oauth_client(CreateOAuthClient {
                    client_id: "registry-client".into(),
                    user_id: None,
                    client_secret: None,
                    metadata: metadata(false),
                    created_at: "2026-01-01T00:00:00.123Z".parse()?,
                })
                .await
                .map(Some),
            "update" | "sql-failure" => {
                store
                    .update_oauth_client_metadata(
                        "registry-client",
                        metadata(true),
                        "2026-02-01T00:00:00.123Z".parse()?,
                    )
                    .await
            }
            "read" | "updated-read" => store.get_oauth_client("registry-client").await,
            _ => panic!("unexpected source OAuth JSON action: {action}"),
        };
        assert_eq!(
            json!(outcome.is_err()),
            case["failed"],
            "{action}: {outcome:?}"
        );
        let output = match outcome {
            Ok(Some(client)) => {
                if action == "create" {
                    id = client.id.clone();
                }
                assert_eq!(client.id, id, "{action}");
                projection(&client)
            }
            Ok(None) => panic!("source client must exist: {action}"),
            Err(error) => {
                assert!(error.to_string().contains("reject_oauth_scope"), "{error}");
                Value::Null
            }
        };
        if action == "sql-failure" {
            _ = db
                .execute(
                    "ALTER TABLE \"oauthClient\" DROP CONSTRAINT reject_oauth_scope",
                    &[],
                )
                .await?;
        }
        assert_eq!(output, case["output"], "{action}");
        let stored: Value = serde_json::from_str(&db.text("SELECT jsonb_build_object('clientId', \"clientId\", 'clientDiscoveryId', \"clientDiscoveryId\", 'name', name, 'scopes', scopes, 'grantTypes', \"grantTypes\", 'responseTypes', \"responseTypes\", 'redirectUris', \"redirectUris\")::text FROM \"oauthClient\"", &[]).await?.unwrap())?;
        assert_eq!(stored, case["stored"], "{action}");
    }
    B::close(connection).await
}
