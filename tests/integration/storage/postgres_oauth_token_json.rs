use super::{Backend, Db, TestResult, postgres_tests};
use alibi::store::{
    CreateOAuthClient, CreateOAuthToken, OAuthClientStore, OAuthToken, OAuthTokenKind, UserStore,
};
use alibi::{AuthUser, CreateUser};
use serde_json::{Value, json};

postgres_tests!(oauth_token_native_json_bindings_match_actual_postgres);

fn projection(token: &OAuthToken) -> Value {
    json!({"token":token.token,"scopes":token.metadata["scopes"],"resources":token.metadata["resources"],
        "requestedUserInfoClaims":token.metadata["requestedUserInfoClaims"],"confirmation":token.metadata["confirmation"],"revoked":token.metadata["revoked"]})
}

async fn oauth_token_native_json_bindings_match_actual_postgres<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("postgres-oauth-token-json-secret-at-least-32")
        .await?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-oauth-token-json.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    let owner = store
        .create_user(
            CreateUser::new()
                .with_name("Token owner")
                .with_email("token-json@example.com"),
        )
        .await?;
    _ = store.create_oauth_client(CreateOAuthClient {
        client_id: "token-json-client".into(), user_id: None, client_secret: None,
        metadata: json!({"redirect_uris":["https://client.example/callback"],"scope":"read","token_endpoint_auth_method":"none"}),
        created_at: "2026-01-01T00:00:00.123Z".parse()?,
    }).await?;
    let mut id = String::new();
    for case in cases {
        let (kind, table) = match case["kind"].as_str().unwrap() {
            "access" => (OAuthTokenKind::Access, "oauthAccessToken"),
            "refresh" => (OAuthTokenKind::Refresh, "oauthRefreshToken"),
            name => panic!("unexpected source token kind: {name}"),
        };
        let action = case["action"].as_str().unwrap();
        let token = format!("{}-token-json", case["kind"].as_str().unwrap());
        if action == "sql-failure" {
            _ = db.execute(&format!("ALTER TABLE \"{table}\" ADD CONSTRAINT reject_token_scopes CHECK (jsonb_array_length(scopes) < 2)"), &[]).await?;
        }
        let outcome = match action {
            "create" | "sql-failure" => store.create_oauth_token(kind, CreateOAuthToken {
                token: if action == "create" { token.clone() } else { format!("rejected-{token}") },
                client_id: "token-json-client".into(), user_id: Some(owner.id().into_owned()), session_id: None, authorization_code_id: None,
                metadata: json!({"scopes":if action == "create" {json!(["read"])} else {json!(["read","write"])},
                    "resources":["https://resource.example"],"requestedUserInfoClaims":["email"],"confirmation":{"jkt":"application-proof"}}),
                created_at: "2026-01-01T00:00:00.123Z".parse()?, expires_at: "2031-01-01T00:00:00.123Z".parse()?,
            }).await.map(Some),
            "revoke" => {
                store.mark_oauth_token_revoked(kind, &id, "2030-02-03T04:05:06.789Z".parse()?).await?;
                store.get_oauth_token(kind, &token).await
            },
            "read" | "revoked-read" => store.get_oauth_token(kind, &token).await,
            _ => panic!("unexpected source token action: {action}"),
        };
        assert_eq!(
            json!(outcome.is_err()),
            case["failed"],
            "{table}/{action}: {outcome:?}"
        );
        let output = match outcome {
            Ok(Some(token)) => {
                if action == "create" {
                    id = token.id.clone();
                }
                assert_eq!(token.id, id, "{table}/{action}");
                projection(&token)
            }
            Ok(None) => panic!("source token must exist: {table}/{action}"),
            Err(error) => {
                assert!(error.to_string().contains("reject_token_scopes"), "{error}");
                Value::Null
            }
        };
        if action == "sql-failure" {
            _ = db
                .execute(
                    &format!("ALTER TABLE \"{table}\" DROP CONSTRAINT reject_token_scopes"),
                    &[],
                )
                .await?;
        }
        assert_eq!(output, case["output"], "{table}/{action}");
        let stored: Value = serde_json::from_str(&db.text(&format!("SELECT jsonb_build_object('token', token, 'scopes', scopes, 'resources', resources, 'requestedUserInfoClaims', \"requestedUserInfoClaims\", 'confirmation', confirmation, 'revoked', to_char(revoked AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'))::text FROM \"{table}\""), &[]).await?.unwrap())?;
        assert_eq!(stored, case["stored"], "{table}/{action}");
    }
    B::close(connection).await
}
