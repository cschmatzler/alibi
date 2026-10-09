//! Nullable plugin flags on the bundled user table.

use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::{AuthUser, CreateUser, UpdateUser, store::UserStore};

backend_tests!(
    disabled_plugin_creation_preserves_sql_null,
    explicit_flags_persist_without_initializing_unrelated_updates,
    installed_api_key_user_deletion,
);

postgres_tests!(
    disabled_plugin_creation_preserves_sql_null,
    explicit_flags_persist_without_initializing_unrelated_updates,
);

async fn disabled_plugin_creation_preserves_sql_null<B: Backend>(db: Db) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("nullable-plugin-fields-local-test-secret-32")
        .await?;
    let user = store
        .create_user(CreateUser::new().with_email("disabled-plugin@example.com"))
        .await?;
    assert!(!user.two_factor_enabled());
    assert!(!user.banned());
    assert_eq!(user.two_factor_enabled_value(), None);
    assert_eq!(user.banned_value(), None);
    assert_eq!(
        db.text(
            "SELECT CASE WHEN two_factor_enabled IS NULL AND banned IS NULL THEN 'null,null' END FROM users WHERE id = $1",
            &[user.id().as_ref()]
        )
        .await?,
        Some("null,null".to_owned())
    );
    B::close(connection).await
}

async fn explicit_flags_persist_without_initializing_unrelated_updates<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, store) = db
        .migrated::<B>("nullable-plugin-flags-explicit-local-secret-32")
        .await?;
    let unset = store
        .create_user(CreateUser::new().with_email("unset-fields@example.com"))
        .await?;
    let renamed = store
        .update_user(
            unset.id().as_ref(),
            UpdateUser {
                name: Some("Unrelated update".to_owned()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(renamed.two_factor_enabled_value(), None);
    assert_eq!(renamed.banned_value(), None);
    let configured = store
        .create_user(CreateUser {
            email: Some("explicit-fields@example.com".to_owned()),
            two_factor_enabled: Some(true),
            banned: Some(true),
            ..Default::default()
        })
        .await?;
    let persisted = store
        .get_user_by_id(configured.id().as_ref())
        .await?
        .ok_or("created configured user disappeared")?;
    assert!(persisted.two_factor_enabled());
    assert!(persisted.banned());
    assert_eq!(persisted.two_factor_enabled_value(), Some(true));
    assert_eq!(persisted.banned_value(), Some(true));
    let disabled = store
        .update_user(
            configured.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                banned: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(disabled.two_factor_enabled_value(), Some(false));
    assert_eq!(disabled.banned_value(), Some(false));
    let initialized = store
        .update_user(
            unset.id().as_ref(),
            UpdateUser {
                two_factor_enabled: Some(false),
                banned: Some(false),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(initialized.two_factor_enabled_value(), Some(false));
    assert_eq!(initialized.banned_value(), Some(false));
    B::close(connection).await
}

// Shared public deletion owner for generated core-only schemas and the bundled
// installed-key schema. Only the latter has independent credential SQL checks.
const DELETION_SECRET: &str = "installed-cleanup-secret-at-least-32-characters";
const DELETION_ORIGIN: &str = "http://localhost:43181";

pub(crate) fn deletion_config() -> alibi::AuthConfig {
    alibi::AuthConfig::new(DELETION_SECRET).base_url(DELETION_ORIGIN)
}

fn deletion_request(path: &str, body: serde_json::Value, cookie: &str) -> alibi::AuthRequest {
    use alibi::{AuthRequest, HttpMethod};
    let mut request = AuthRequest::new(HttpMethod::Post, path);
    request.body = Some(body.to_string().into_bytes());
    drop(
        request
            .headers
            .insert("origin".into(), DELETION_ORIGIN.into()),
    );
    drop(
        request
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    drop(request.headers.insert("cookie".into(), cookie.into()));
    request
}

async fn signup<S: alibi::AuthSchema>(
    auth: &alibi::BetterAuth<S>,
    email: &str,
) -> TestResult<(String, String)> {
    let response = Box::pin(auth.handle_request(deletion_request(
        "/sign-up/email",
        serde_json::json!({"email":email,"password":"password123","name":"Deletion owner"}),
        "",
    )))
    .await?;
    assert_eq!(
        response.status,
        200,
        "signup: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body: serde_json::Value = serde_json::from_slice(&response.body)?;
    let cookie = response
        .headers
        .get_all("set-cookie")
        .map(|cookie| cookie.split(';').next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("; ");
    Ok((
        body["user"]["id"].as_str().ok_or("missing user")?.into(),
        cookie,
    ))
}

async fn create_key<S: alibi::AuthSchema>(
    auth: &alibi::BetterAuth<S>,
    cookie: &str,
) -> TestResult<(String, String)> {
    let response = Box::pin(auth.handle_request(deletion_request(
        "/api-key/create",
        serde_json::json!({"name":"owned credential"}),
        cookie,
    )))
    .await?;
    assert_eq!(
        response.status,
        200,
        "create key: {}",
        String::from_utf8_lossy(&response.body)
    );
    let body: serde_json::Value = serde_json::from_slice(&response.body)?;
    Ok((
        body["id"].as_str().ok_or("missing key")?.into(),
        body["key"].as_str().ok_or("missing plaintext key")?.into(),
    ))
}

pub(crate) async fn public_user_deletion<S: alibi::AuthSchema>(
    store: std::sync::Arc<dyn alibi::store::AuthStore<S>>,
    admin: bool,
    installed_keys: Option<&Db>,
) -> TestResult {
    use alibi::AuthBuilder;
    use alibi::plugins::{
        AdminConfig, AdminPlugin, ApiKeyPlugin, EmailPasswordPlugin, UserManagementPlugin,
    };
    use alibi::{AuthRequest, HttpMethod};
    use serde_json::{Value, json};
    let plugins = |builder: alibi::AuthBuilder<S>| {
        let builder = builder.plugin(EmailPasswordPlugin::new());
        if installed_keys.is_some() {
            builder.plugin(ApiKeyPlugin::with_config(Default::default()))
        } else {
            builder
        }
    };
    // Bootstrap the admin through the real password handler, then configure its
    // explicit ID. No admin columns are required by the generated core schema.
    let bootstrap = plugins(AuthBuilder::new(deletion_config()).store_arc(store.clone()))
        .build()
        .await?;
    let (admin_id, admin_cookie) = Box::pin(signup(
        &bootstrap,
        if admin {
            "admin-admin@deletion.test"
        } else {
            "admin-self@deletion.test"
        },
    ))
    .await?;
    let foreign_key = if installed_keys.is_some() {
        Some(Box::pin(create_key(&bootstrap, &admin_cookie)).await?)
    } else {
        None
    };
    let auth = plugins(AuthBuilder::new(deletion_config()).store_arc(store.clone()))
        .plugin(
            UserManagementPlugin::new()
                .delete_user_enabled(true)
                .require_delete_verification(false),
        )
        .plugin(AdminPlugin::with_config(AdminConfig {
            admin_user_ids: Some(vec![admin_id.clone()]),
            ..Default::default()
        }))
        .build()
        .await?;
    let email = if admin {
        "admin-target@deletion.test"
    } else {
        "self-target@deletion.test"
    };
    let (owner, cookie) = Box::pin(signup(&auth, email)).await?;
    let owned_key = if installed_keys.is_some() {
        Some(Box::pin(create_key(&auth, &cookie)).await?)
    } else {
        None
    };
    if let (Some(db), Some((foreign_key, _)), Some((owned_key, _))) =
        (installed_keys, &foreign_key, &owned_key)
    {
        let foreign_before = db
            .text("SELECT key FROM api_keys WHERE id = $1", &[foreign_key])
            .await?;
        if admin {
            {
                let (table, label) = ("users", "user veto");
                // A user-delete failure retains the identity and its keys.
                // Earlier account/session removals are separate HTTP effects.
                let condition = format!("OLD.id = '{owner}'");
                _ = db.execute(&format!("CREATE TRIGGER cleanup_veto BEFORE DELETE ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT, '{label}'); END"), &[]).await?;
                let response = Box::pin(auth.handle_request(deletion_request(
                    "/admin/remove-user",
                    json!({"userId":owner}),
                    &admin_cookie,
                )))
                .await?;
                assert_eq!(response.status, 500, "{label} must abort deletion");
                assert_eq!(
                    db.count_where("SELECT COUNT(*) FROM users WHERE id = $1", &[&owner])
                        .await?,
                    1
                );
                assert_eq!(
                    db.count_where("SELECT COUNT(*) FROM api_keys WHERE id = $1", &[owned_key])
                        .await?,
                    1
                );
                assert_eq!(
                    db.text("SELECT key FROM api_keys WHERE id = $1", &[foreign_key])
                        .await?,
                    foreign_before
                );
                _ = db.execute("DROP TRIGGER cleanup_veto", &[]).await?;
            }
        }
    }
    let (path, input, actor_cookie) = if admin {
        ("/admin/remove-user", json!({"userId":owner}), &admin_cookie)
    } else {
        ("/delete-user", json!({}), &cookie)
    };
    let response =
        Box::pin(auth.handle_request(deletion_request(path, input, actor_cookie))).await?;
    assert_eq!(
        response.status,
        200,
        "{path}: {}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body)?["success"],
        true
    );
    assert!(store.get_user_by_id(&owner).await?.is_none());
    assert!(store.get_user_by_id(&admin_id).await?.is_some());
    let mut session = AuthRequest::new(HttpMethod::Get, "/get-session");
    drop(session.headers.insert("cookie".into(), cookie.clone()));
    let response = Box::pin(auth.handle_request(session)).await?;
    assert_eq!(response.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body)?,
        Value::Null
    );
    let signin = Box::pin(auth.handle_request(deletion_request(
        "/sign-in/email",
        json!({"email":email,"password":"password123"}),
        "",
    )))
    .await?;
    assert_eq!(signin.status, 401);
    if let (Some(db), Some((foreign_key, foreign_plaintext)), Some((_, owned_plaintext))) =
        (installed_keys, &foreign_key, &owned_key)
    {
        for (plaintext, expected) in [(foreign_plaintext, true), (owned_plaintext, true)] {
            let verified = Box::pin(auth.dispatch_endpoint(
                ApiKeyPlugin::verify_endpoint(&alibi::plugins::api_key::ApiKeyVerificationInput {
                    key: plaintext.clone(),
                    config_id: None,
                    permissions: None,
                })?,
                Default::default(),
            ))
            .await?
            .decode()?;
            assert_eq!(
                verified.valid, expected,
                "programmatic verification retains both keys after owner deletion"
            );
        }
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM api_keys WHERE reference_id = $1",
                &[&owner]
            )
            .await?,
            1
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM api_keys WHERE id = $1 AND reference_id = $2",
                &[foreign_key, &admin_id]
            )
            .await?,
            1
        );
        // Removing the plugin also preserves the existing key table and rows.
        let (disabled_owner, disabled_cookie) = Box::pin(signup(
            &auth,
            if admin {
                "disabled-admin@deletion.test"
            } else {
                "disabled-self@deletion.test"
            },
        ))
        .await?;
        let (disabled_key, _) = Box::pin(create_key(&auth, &disabled_cookie)).await?;
        let without_plugin = AuthBuilder::new(deletion_config())
            .store_arc(store)
            .plugin(
                UserManagementPlugin::new()
                    .delete_user_enabled(true)
                    .require_delete_verification(false),
            )
            .build()
            .await?;
        let response = Box::pin(without_plugin.handle_request(deletion_request(
            "/delete-user",
            json!({}),
            &disabled_cookie,
        )))
        .await?;
        assert_eq!(response.status, 200);
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM users WHERE id = $1",
                &[&disabled_owner]
            )
            .await?,
            0
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM api_keys WHERE id = $1",
                &[&disabled_key]
            )
            .await?,
            1
        );
        assert_eq!(
            db.count_where(
                "SELECT COUNT(*) FROM api_keys WHERE id = $1 AND reference_id = $2",
                &[foreign_key, &admin_id]
            )
            .await?,
            1
        );
    }
    Ok(())
}

async fn installed_api_key_user_deletion<B: Backend>(db: Db) -> TestResult {
    let (connection, _) = db.migrated::<B>(DELETION_SECRET).await?;
    let store = std::sync::Arc::new(B::store(
        std::sync::Arc::new(deletion_config()),
        &connection,
    ));
    for admin in [false, true] {
        Box::pin(public_user_deletion(store.clone(), admin, Some(&db))).await?;
    }
    B::close(connection).await
}
