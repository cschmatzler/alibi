use super::*;
use alibi::plugins::oauth_provider::{OAuthClientMetadata, RegisterClientMetadataDocumentInput};
use alibi::plugins::{OAuthProviderConfig, OAuthProviderPlugin};
use alibi::seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_MYSQL_URL pointing to a disposable database"]
async fn mysql_oauth_document_replacement_matches_actual_registration() -> TestResult {
    let base = std::env::var("BETTER_AUTH_TEST_MYSQL_URL")?;
    let admin = alibi::seaorm::Database::connect(base.clone()).await?;
    let database = format!("alibi_oauth_document_{}", uuid::Uuid::new_v4().simple());
    _ = admin
        .execute_unprepared(&format!(
            "CREATE DATABASE `{database}` CHARACTER SET utf8mb4"
        ))
        .await?;
    let mut url = url::Url::parse(&base)?;
    url.set_path(&format!("/{database}"));
    let connection = alibi::seaorm::Database::connect(url.as_str()).await?;
    for statement in include_str!("../../../fixtures/mysql-source-schema.sql")
        .split(';')
        .filter(|sql| !sql.trim().is_empty())
    {
        _ = connection.execute_unprepared(statement).await?;
    }
    let config = AuthConfig::new("mysql-oauth-document-secret-at-least-32-characters")
        .base_url("http://localhost");
    let provider = OAuthProviderPlugin::with_config(OAuthProviderConfig {
        disable_jwt_plugin: true,
        scopes: vec!["openid".into(), "profile".into()],
        ..Default::default()
    });
    let auth = AuthBuilder::new(config.clone())
        .store(<super::super::SeaOrm as Backend>::store(
            Arc::new(config),
            &connection,
        ))
        .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
        .plugin(provider.clone())
        .build()
        .await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../fixtures/mysql-oauth-document-replacement.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let client_id = "https://client.example/metadata.json";
    let mut original_id = String::new();
    let mut created_at = None;
    let mut existing = None;
    for case in cases {
        let action = case["action"].as_str().unwrap();
        if action != "create" && action != "missing" {
            existing = auth.store().get_oauth_client(client_id).await?;
        }
        if action == "sql-failure" {
            _ = connection.execute_raw(Statement::from_sql_and_values(DbBackend::MySql, "UPDATE oauthClient SET disabled = true, skipConsent = true, enableEndSession = true, clientCredentialsScopes = '[\"operator-scope\"]' WHERE clientId = ?", [client_id.into()])).await?;
            _ = connection.execute_unprepared("ALTER TABLE oauthClient ADD CONSTRAINT reject_refreshed_document CHECK (name <> 'Refreshed')").await?;
        }
        if action == "missing" {
            auth.store().delete_oauth_client(client_id).await?;
        }
        let metadata: OAuthClientMetadata = serde_json::from_value(
            json!({"client_id":"ignored","client_name":if action == "create" {"Document client"} else {"Refreshed"},"redirect_uris":[if action == "create" {"https://client.example/before"} else {"https://client.example/after"}],"token_endpoint_auth_method":"none"}),
        )?;
        let result = provider
            .register_client_metadata_document(
                RegisterClientMetadataDocumentInput {
                    metadata,
                    client_id: client_id.into(),
                    client_discovery_id: if action == "wrong-owner" {
                        "foreign-owner"
                    } else {
                        "mysql-document-owner"
                    }
                    .into(),
                    existing_client: if action == "create" {
                        None
                    } else {
                        existing.clone()
                    },
                },
                auth.context(),
            )
            .await;
        let (output, error) = match result {
            Ok(result) => {
                if action == "create" {
                    original_id = result.client.id.clone();
                    created_at = result.client.created_at;
                }
                assert_eq!(result.client.id, original_id, "{action}");
                assert_eq!(result.client.created_at, created_at, "{action}");
                let client = &result.client;
                let metadata = &client.metadata;
                (
                    json!({"created":result.created,"resources":result.resources,"clientSecret":result.client_secret,
                    "client":{"clientId":client.client_id,"clientDiscoveryId":metadata["client_discovery_id"],"name":metadata["client_name"],"applicationType":metadata["application_type"],
                        "scopes":metadata["scope"].as_str().unwrap().split(' ').collect::<Vec<_>>(),"clientCredentialsScopes":metadata["client_credentials_scopes"],"disabled":metadata["disabled"],
                        "skipConsent":metadata["skip_consent"],"enableEndSession":metadata["enable_end_session"],"redirectUris":metadata["redirect_uris"]}}),
                    Value::Null,
                )
            }
            Err(error) if action == "sql-failure" => {
                assert!(
                    error
                        .error
                        .to_string()
                        .contains("reject_refreshed_document"),
                    "{action}: {error:?}"
                );
                (Value::Null, json!({"sql_failure":true}))
            }
            Err(error) => {
                assert_eq!(error.error.status_code(), 400, "{action}: {error:?}");
                (Value::Null, error.body.unwrap().to_json_value()?)
            }
        };
        assert_eq!(output, case["output"], "{action}");
        assert_eq!(error, case["error"], "{action}");
        if action == "sql-failure" {
            _ = connection
                .execute_unprepared("ALTER TABLE oauthClient DROP CHECK reject_refreshed_document")
                .await?;
        }
        let mut stored = Vec::new();
        for row in connection.query_all_raw(Statement::from_string(DbBackend::MySql, "SELECT name, clientDiscoveryId, CAST(disabled AS SIGNED) AS disabled, CAST(skipConsent AS SIGNED) AS skipConsent, CAST(enableEndSession AS SIGNED) AS enableEndSession, CAST(scopes AS CHAR) AS scopes, CAST(clientCredentialsScopes AS CHAR) AS clientCredentialsScopes, CAST(redirectUris AS CHAR) AS redirectUris FROM oauthClient".to_owned())).await? {
            let mut value = json!({"name":row.try_get::<Option<String>>("", "name")?,"clientDiscoveryId":row.try_get::<Option<String>>("", "clientDiscoveryId")?,
                "disabled":row.try_get::<Option<i64>>("", "disabled")?,"skipConsent":row.try_get::<Option<i64>>("", "skipConsent")?,"enableEndSession":row.try_get::<Option<i64>>("", "enableEndSession")?});
            for field in ["scopes", "clientCredentialsScopes", "redirectUris"] { value[field] = serde_json::from_str(&row.try_get::<String>("", field)?)?; }
            stored.push(value);
        }
        assert_eq!(json!(stored), case["stored"], "{action}");
    }
    drop(auth);
    connection.close().await?;
    _ = admin
        .execute_unprepared(&format!("DROP DATABASE `{database}`"))
        .await?;
    admin.close().await?;
    Ok(())
}
