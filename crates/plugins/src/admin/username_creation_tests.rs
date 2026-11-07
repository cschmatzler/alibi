use super::*;
use crate::email_password::{EmailPasswordPlugin, UsernameConfig, UsernameNormalization};
use alibi_core::field_policy::{SessionFields, UserFields};
use alibi_core::{AuthInitContext, AuthPlugin, AuthUser};
use std::sync::Mutex;

async fn username_context(
    policy: UsernameConfig,
    events: Option<Arc<Mutex<Vec<String>>>>,
) -> AuthContext<TestSchema> {
    let (mut ctx, _, _, _, _) = create_admin_context().await;
    let mut init = AuthInitContext::new(ctx.config.clone(), ctx.database.clone());
    if let Some(events) = events.clone() {
        init.register_user_create_transform(move |mut data| {
            events.lock().unwrap().push("before".into());
            data.username = Some("ORDERED".into());
            Ok(data)
        });
    }
    let plugin = EmailPasswordPlugin::new()
        .enable_username(true)
        .username_config(policy.clone());
    <EmailPasswordPlugin as AuthPlugin<TestSchema>>::on_init(&plugin, &mut init)
        .await
        .unwrap();
    init.extensions
        .insert(UserFields(SessionFields(policy.fields())));
    let mut adapter_fields = policy.fields();
    adapter_fields.extend(init.config.user.additional_fields.clone());
    init.extensions
        .insert(alibi_core::field_policy::AdapterFieldPolicies {
            user: alibi_core::field_policy::SessionAdapterFields(Arc::new(adapter_fields)),
            ..Default::default()
        });
    if let Some(events) = events {
        init.register_user_create_transform(move |data| {
            events
                .lock()
                .unwrap()
                .push(format!("after:{}", data.username.as_deref().unwrap()));
            Ok(data)
        });
    }
    ctx.metadata = init.metadata.clone();
    ctx.extensions = init.extensions.clone();
    ctx.database = init.database_with_registered_transforms();
    ctx
}

mod username_update {
    include!("username_update_tests.rs");
}

fn provision(email: &str, data: serde_json::Value) -> types::CreateUserRequest {
    let mut input = types::CreateUserRequest::new(email, "Username");
    input.data = Some(data.as_object().unwrap().clone());
    input
}

#[tokio::test]
async fn admin_username_creation_validates_raw_fields_and_preserves_display_fallback() {
    let ctx = username_context(UsernameConfig::default(), None).await;
    for (index, username, status) in [
        (0, serde_json::json!(42), 500),
        (1, serde_json::json!("ab"), 400),
        (2, serde_json::json!("not allowed"), 400),
    ] {
        let email = format!("invalid-username-{index}@fixture.test");
        let error = handlers::create_user_core(
            &provision(&email, serde_json::json!({"username": username})),
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status_code(), status, "{error:?}");
        assert!(
            ctx.database
                .get_user_by_email(&(email).into())
                .await
                .unwrap()
                .is_none()
        );
    }
    let user = handlers::create_user_core(
        &provision(
            "mixed-username@fixture.test",
            serde_json::json!({"username":"MiXeD","displayUsername":false}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(user.user.username.as_deref(), Some("mixed"));
    assert_eq!(user.user.display_username.as_deref(), Some("MiXeD"));
    let error = handlers::create_user_core(
        &provision(
            "duplicate-username@fixture.test",
            serde_json::json!({"username":"MIXED"}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        alibi_core::AuthError::Upstream {
            code: "USERNAME_IS_ALREADY_TAKEN",
            ..
        }
    ));

    let policy = UsernameConfig {
        normalization: UsernameNormalization::Preserve,
        ..UsernameConfig::default()
    };
    let ctx = username_context(policy, None).await;
    let preserved = handlers::create_user_core(
        &provision(
            "preserve-username@fixture.test",
            serde_json::json!({"username":"KeEpCaSe"}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(preserved.user.username.as_deref(), Some("KeEpCaSe"));
    let numeric = handlers::create_user_core(
        &provision(
            "number-username@fixture.test",
            serde_json::json!({"username":42,"displayUsername":false}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(numeric.user.username.as_deref(), Some("42"));
    assert_eq!(numeric.user.display_username.as_deref(), Some("42"));
    let duplicate = handlers::create_user_core(
        &provision(
            "number-duplicate@fixture.test",
            serde_json::json!({"username":42}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        duplicate,
        alibi_core::AuthError::Upstream {
            code: "USERNAME_IS_ALREADY_TAKEN",
            ..
        }
    ));
}

#[tokio::test]
async fn admin_username_async_validator_runs_between_application_hooks_and_stops_on_error() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let policy = UsernameConfig {
        validator: Some(Arc::new(move |value: String| {
            let log = log.clone();
            async move {
                tokio::task::yield_now().await;
                log.lock().unwrap().push(format!("validator:{value}"));
                Ok(true)
            }
        })),
        ..UsernameConfig::default()
    };
    let ctx = username_context(policy, Some(events.clone())).await;
    let user = handlers::create_user_core(
        &provision(
            "ordered-username@fixture.test",
            serde_json::json!({"username":"bad value"}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(user.user.username.as_deref(), Some("ordered"));
    assert_eq!(
        *events.lock().unwrap(),
        ["before", "validator:ORDERED", "after:ordered"]
    );

    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let policy = UsernameConfig {
        validator: Some(Arc::new(move |_: String| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push("validator".into());
                Err(alibi_core::AuthError::internal("validator rejected"))
            }
        })),
        ..UsernameConfig::default()
    };
    let ctx = username_context(policy, Some(events.clone())).await;
    let error = handlers::create_user_core(
        &provision(
            "validator-error@fixture.test",
            serde_json::json!({"username":"initial"}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert_eq!(error.status_code(), 500);
    assert_eq!(*events.lock().unwrap(), ["before", "validator"]);
    assert!(
        ctx.database
            .get_user_by_email(&("validator-error@fixture.test").into())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn admin_username_duplicate_hook_uses_current_transaction_and_endpoint_skip() {
    let ctx = username_context(UsernameConfig::default(), None).await;
    alibi_core::store::transaction(ctx.database.as_ref(), |tx| {
        Box::pin(async move {
            let mut input = CreateUser::new().with_email("username-tx-first@fixture.test");
            input.username = Some("IN_TRANSACTION".into());
            let created = tx.create_user(input).await?;
            assert_eq!(created.username(), Some("in_transaction"));
            let mut input = CreateUser::new().with_email("username-tx-second@fixture.test");
            input.username = Some("in_transaction".into());
            let error = tx.create_user(input).await.unwrap_err();
            assert!(matches!(
                error,
                alibi_core::AuthError::Upstream {
                    code: "USERNAME_IS_ALREADY_TAKEN",
                    ..
                }
            ));
            assert!(
                tx.get_user_by_email(&("username-tx-second@fixture.test").into())
                    .await?
                    .is_none()
            );
            Ok(())
        })
    })
    .await
    .unwrap();

    let request = alibi_core::AuthRequest::new(alibi_core::HttpMethod::Post, "/sign-up/email");
    let mut input = CreateUser::new().with_email("username-skip@fixture.test");
    input.username = Some("X".into());
    let created =
        alibi_core::hooks::with_request_hook_context(&request, ctx.database.create_user(input))
            .await
            .unwrap();
    assert_eq!(created.username(), Some("x"));
}

#[tokio::test]
async fn admin_username_memory_scalars_keep_strict_lookup_and_preserved_case() {
    use alibi_core::store::stateless::{StatelessSchema, StatelessStore};
    let config = Arc::new(alibi_core::AuthConfig::default());
    let physical = Arc::new(StatelessStore::default());
    let mut init = AuthInitContext::new(config.clone(), physical);
    let policy = UsernameConfig {
        normalization: UsernameNormalization::Preserve,
        ..UsernameConfig::default()
    };
    let plugin = EmailPasswordPlugin::new()
        .enable_username(true)
        .username_config(policy.clone());
    <EmailPasswordPlugin as AuthPlugin<StatelessSchema>>::on_init(&plugin, &mut init)
        .await
        .unwrap();
    init.extensions
        .insert(UserFields(SessionFields(policy.fields())));
    let ctx = AuthContext::with_metadata(
        config,
        init.database_with_registered_transforms(),
        init.metadata.clone(),
    )
    .with_extensions(init.extensions.clone());
    for (email, value) in [
        ("memory-numeric@fixture.test", serde_json::json!(4242)),
        ("memory-text@fixture.test", serde_json::json!("4242")),
        ("memory-case@fixture.test", serde_json::json!("KeEpCaSe")),
    ] {
        let response = handlers::create_user_core(
            &provision(
                email,
                serde_json::json!({"username":value,"displayUsername":false}),
            ),
            &AdminConfig::default(),
            &ctx,
        )
        .await
        .unwrap();
        let wire = serde_json::to_value(response.user).unwrap();
        assert_eq!(wire["username"], value);
        assert_eq!(wire["displayUsername"], value);
        let stored = ctx
            .database
            .get_user_by_email(&(email).into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_value(stored).unwrap()["username"], value);
    }
    let error = handlers::create_user_core(
        &provision(
            "memory-duplicate@fixture.test",
            serde_json::json!({"username":4242}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        alibi_core::AuthError::Upstream {
            code: "USERNAME_IS_ALREADY_TAKEN",
            ..
        }
    ));
}

#[tokio::test]
async fn admin_username_hidden_display_is_not_persisted_and_without_plugin_case_is_unchanged() {
    let policy = UsernameConfig {
        include_display_username: false,
        ..UsernameConfig::default()
    };
    let ctx = username_context(policy, None).await;
    let response = handlers::create_user_core(
        &provision(
            "hidden-display@fixture.test",
            serde_json::json!({"username":"MIXED","displayUsername":"Ignored"}),
        ),
        &AdminConfig::default(),
        &ctx,
    )
    .await
    .unwrap();
    let wire = serde_json::to_value(response.user).unwrap();
    assert_eq!(wire["username"], "mixed");
    assert!(wire.get("displayUsername").is_none());
    let stored = ctx
        .database
        .get_user_by_email(&("hidden-display@fixture.test").into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.display_username(), None);

    let (ctx, _, _, _, _) = create_admin_context().await;
    let mut input = CreateUser::new().with_email("no-username-plugin@fixture.test");
    input.username = Some("UnChanged".into());
    let stored = ctx.database.create_user(input).await.unwrap();
    assert_eq!(stored.username(), Some("UnChanged"));
}
