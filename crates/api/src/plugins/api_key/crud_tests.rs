use super::*;
use better_auth_core::{AuthConfig, CreateSession, CreateUser, HttpMethod};
use chrono::{Duration, Utc};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

type TestSchema = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;

async fn context() -> (AuthContext<TestSchema>, String, String) {
    let database = crate::plugins::test_helpers::create_test_database().await;
    let user = database
        .create_user(
            CreateUser::new()
                .with_email("crud@example.com")
                .with_name("CRUD user"),
        )
        .await
        .unwrap();
    let user_id = user.id().to_string();
    let session = database
        .create_session(CreateSession {
            additional_fields: better_auth_core::field_policy::FieldValues::default(),
            token: None,
            active_team_id: None,
            user_id: user_id.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
        })
        .await
        .unwrap();
    let token = better_auth_core::entity::AuthSession::token(&session).to_owned();
    (
        AuthContext::new(
            Arc::new(AuthConfig::new("a-secret-that-is-at-least-32-characters")),
            database,
        ),
        user_id,
        token,
    )
}

fn request(token: &str, path: &str, body: &serde_json::Value) -> AuthRequest {
    AuthRequest::from_parts(
        HttpMethod::Post,
        path.to_owned(),
        HashMap::from([(
            "cookie".to_owned(),
            format!(
                "better-auth.session_token={}",
                better_auth_core::utils::cookie_utils::sign_cookie_value(
                    token,
                    "a-secret-that-is-at-least-32-characters"
                )
            ),
        )]),
        Some(serde_json::to_vec(&body).unwrap()),
        HashMap::new(),
    )
}

async fn server_key(
    plugin: &ApiKeyPlugin,
    ctx: &AuthContext<TestSchema>,
    user_id: &str,
    config_id: &str,
) -> CreateKeyResponse {
    plugin
        .create_key(
            ctx,
            &CreateKeyRequest {
                user_id: Some(user_id.to_owned()),
                config_id: Some(config_id.to_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn list_without_configuration_includes_all_user_configurations() {
    let (ctx, user_id, _) = context().await;
    let plugin = ApiKeyPlugin::builder().build().configuration(ApiKeyConfig {
        config_id: "secondary".to_owned(),
        ..Default::default()
    });
    server_key(&plugin, &ctx, &user_id, "default").await;
    server_key(&plugin, &ctx, &user_id, "secondary").await;
    let list = list_keys_core(&user_id, &ListKeysQuery::default(), &plugin, &ctx)
        .await
        .unwrap();
    assert_eq!(list.total, 2);
    let list_2 = list_keys_core(
        &user_id,
        &ListKeysQuery {
            config_id: Some("secondary".to_owned()),
            ..Default::default()
        },
        &plugin,
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(list_2.total, 1);
    assert_eq!(
        (list_2.api_keys)
            .first()
            .expect("fixture contains the requested index")
            .config_id,
        "secondary"
    );
    let list_3 = list_keys_core(
        &user_id,
        &ListKeysQuery {
            config_id: Some("missing".to_owned()),
            ..Default::default()
        },
        &plugin,
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(list_3.total, 0);

    let no_default = ApiKeyPlugin::builder()
        .config_id("secondary".to_owned())
        .build();
    assert_eq!(
        list_keys_core(&user_id, &ListKeysQuery::default(), &no_default, &ctx)
            .await
            .unwrap()
            .total,
        2
    );
}

#[tokio::test]
async fn http_requests_cannot_impersonate_users_or_change_server_permissions() {
    let (ctx, user_id, token) = context().await;
    let plugin = ApiKeyPlugin::builder().build();
    let create = request(&token, "/api-key/create", &(json!({"userId":user_id})));
    assert_eq!(
        plugin
            .handle_create(&create, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    let key = server_key(&plugin, &ctx, &user_id, "default").await;
    let update = request(
        &token,
        "/api-key/update",
        &(json!({"keyId":key.api_key.id,"userId":"someone-else","enabled":false})),
    );
    assert_eq!(
        plugin
            .handle_update(&update, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    let update_2 = request(
        &token,
        "/api-key/update",
        &(json!({"keyId":key.api_key.id,"permissions":null})),
    );
    assert_eq!(
        plugin
            .handle_update(&update_2, &ctx)
            .await
            .unwrap_err()
            .to_string(),
        ApiKeyErrorCode::ServerOnlyProperty.message()
    );
    let update_3 = request(&token, "/api-key/update", &(json!({"keyId":"missing"})));
    assert_eq!(
        plugin
            .handle_update(&update_3, &ctx)
            .await
            .unwrap_err()
            .status_code(),
        404
    );
}

#[tokio::test]
async fn metadata_can_be_cleared_and_disabled_metadata_is_ignored_on_update() {
    let (ctx, user_id, token) = context().await;
    let enabled = ApiKeyPlugin::builder().enable_metadata(true).build();
    let key = enabled
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some(user_id.clone()),
                metadata: Some(json!(["initial"]).into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(key.api_key.metadata, Some(json!(["initial"])));
    let update = request(
        &token,
        "/api-key/update",
        &(json!({"keyId":key.api_key.id,"metadata":null})),
    );
    let response = enabled.handle_update(&update, &ctx).await.unwrap();
    assert!(
        (*(serde_json::from_slice::<serde_json::Value>(&response.body).unwrap())
            .get("metadata")
            .unwrap_or(&serde_json::Value::Null))
        .is_null()
    );
    let disabled = ApiKeyPlugin::builder().build();
    let update_2 = request(
        &token,
        "/api-key/update",
        &(json!({"keyId":key.api_key.id,"metadata":{"ignored":true},"enabled":false})),
    );
    let response_2 = disabled.handle_update(&update_2, &ctx).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&response_2.body).unwrap();
    assert!((*(result).get("metadata").unwrap_or(&serde_json::Value::Null)).is_null());
    assert_eq!(
        (*(result).get("enabled").unwrap_or(&serde_json::Value::Null)),
        false
    );
    let update_3 = request(
        &token,
        "/api-key/update",
        &(json!({"keyId":key.api_key.id,"metadata":null})),
    );
    assert_eq!(
        disabled
            .handle_update(&update_3, &ctx)
            .await
            .unwrap_err()
            .to_string(),
        ApiKeyErrorCode::NoValuesToUpdate.message()
    );
}

#[tokio::test]
async fn trusted_creation_and_update_preserve_permissions_and_fractional_expiration() {
    let (ctx, user_id, _) = context().await;
    let plugin = ApiKeyPlugin::builder()
        .key_expiration(KeyExpirationConfig {
            min_expires_in: 0.0,
            ..Default::default()
        })
        .build();
    let before = Utc::now();
    let key = plugin
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some(user_id.clone()),
                expires_in: Some(86400.25),
                remaining: Some(3.0),
                permissions: Some(ApiKeyPermissions::from([(
                    "device".to_owned(),
                    vec!["read".to_owned()],
                )])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(key.api_key.remaining, Some(3.0));
    assert_eq!(key.api_key.permissions, Some(json!({"device":["read"]})));
    let expires_at =
        chrono::DateTime::parse_from_rfc3339(key.api_key.expires_at.as_deref().unwrap())
            .unwrap()
            .with_timezone(&Utc);
    assert!((expires_at - before).num_milliseconds() >= 86_400_249);
    assert!((expires_at - Utc::now()).num_milliseconds() <= 86_400_250);
    let updated = plugin
        .update_key(
            &ctx,
            &UpdateKeyRequest {
                key_id: key.api_key.id.clone(),
                user_id: Some(user_id),
                remaining: Some(5.0),
                permissions: Some(None),
                expires_in: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.remaining, Some(5.0));
    assert_eq!(updated.permissions, Some(serde_json::Value::Null));
    assert_eq!(updated.expires_at, None);
    let stored = ctx
        .database
        .get_api_key_by_id(&key.api_key.id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored.key_hash, key.key);
}

#[tokio::test]
async fn list_rejects_invalid_pagination_instead_of_ignoring_it() {
    let (ctx, _, token) = context().await;
    let plugin = ApiKeyPlugin::builder().build();
    for (field, value) in [
        ("limit", "-1"),
        ("offset", "1.5"),
        ("limit", "bad"),
        ("sortDirection", "sideways"),
    ] {
        let mut req = request(&token, "/api-key/list", &(json!({})));
        req.query.insert(field.to_owned(), value.to_owned());
        let response = plugin.handle_list(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(
            (*(serde_json::from_slice::<serde_json::Value>(&response.body).unwrap())
                .get("code")
                .unwrap_or(&serde_json::Value::Null)),
            "VALIDATION_ERROR"
        );
    }
}

#[tokio::test]
async fn forced_cleanup_preserves_rows_on_store_failure_and_retries_without_throttle() {
    use better_auth_seaorm::sea_orm::{ConnectionTrait, DbBackend, Statement};
    let config = Arc::new(AuthConfig::new("forced-cleanup-application-secret32"));
    let connection = better_auth_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&connection)
        .await
        .unwrap();
    let database = Arc::new(better_auth_seaorm::SeaOrmStore::<TestSchema>::new(
        std::sync::Arc::clone(&config),
        connection.clone(),
    ));
    let ctx = AuthContext::new(config, database);
    let owner = ctx
        .database
        .create_user(CreateUser::new().with_email("cleanup@native.local"))
        .await
        .unwrap();
    let plugin = ApiKeyPlugin::with_config(ApiKeyConfig {
        key_expiration: KeyExpirationConfig {
            min_expires_in: 0.0,
            ..Default::default()
        },
        ..Default::default()
    });
    let key = plugin
        .create_key(
            &ctx,
            &CreateKeyRequest {
                user_id: Some(owner.id().to_string()),
                name: Some("expired".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let expired = ctx
        .database
        .update_api_key(
            &key.api_key.id,
            better_auth_core::UpdateApiKey {
                expires_at: Some(Some("1970-01-01T00:00:00.000Z".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    connection.execute_raw(Statement::from_string(DbBackend::Sqlite,"CREATE TRIGGER reject_api_key_cleanup BEFORE DELETE ON api_keys BEGIN SELECT RAISE(ABORT,'application cleanup rejected'); END")).await.unwrap();
    let failed = plugin.delete_all_expired_api_keys(&ctx).await;
    assert!(failed.success);
    assert!(failed.error.is_none());
    let retained = ctx
        .database
        .get_api_key_by_id(&key.api_key.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        better_auth_core::utils::json::to_value(&retained).unwrap(),
        better_auth_core::utils::json::to_value(&expired).unwrap()
    );
    connection
        .execute_raw(Statement::from_string(
            DbBackend::Sqlite,
            "DROP TRIGGER reject_api_key_cleanup",
        ))
        .await
        .unwrap();
    let retry = plugin.delete_all_expired_api_keys(&ctx).await;
    assert!(retry.success);
    assert!(retry.error.is_none());
    assert!(
        ctx.database
            .get_api_key_by_id(&key.api_key.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ctx.database
            .get_user_by_id(owner.id().as_ref())
            .await
            .unwrap()
            .unwrap(),
        owner
    );
}
