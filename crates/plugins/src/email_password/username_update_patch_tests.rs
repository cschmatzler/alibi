use super::username_hooks::UsernameUpdateHook;
use super::{UsernameConfig, UsernameNormalization};
use alibi_core::store::{
    DatabaseHookContext, DatabaseHooks, HookBackend, HookControl, UserUpdateHook,
    UserUpdateHookResult, UserUpdatePatch,
};
use alibi_core::utils::json::{JsObject, JsValue};
use alibi_core::{
    AuthConfig, AuthContext, AuthInitContext, AuthResult, AuthSchema, AuthStore, AuthTransaction,
    AuthUser, CreateUser, UpdateUser,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

fn text(value: &str) -> JsValue {
    JsValue::String(value.into())
}
fn object(values: &[(&str, JsValue)]) -> JsObject {
    values
        .iter()
        .map(|(name, value)| ((*name).into(), value.clone()))
        .collect()
}
struct Earlier;
#[async_trait]
impl<S: AuthSchema> UserUpdateHook<S> for Earlier {
    async fn before_update(
        &self,
        _: &str,
        _: &JsObject,
        _: &AuthContext<S>,
        _: Option<&dyn AuthTransaction<S>>,
    ) -> AuthResult<UserUpdateHookResult> {
        Ok(UserUpdateHookResult::Data(UserUpdatePatch(object(&[
            ("username", text("earlier")),
            ("name", text("earlier name")),
        ]))))
    }
}
#[derive(Default)]
struct Capture(Mutex<Vec<JsObject>>);
#[async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for Capture {
    async fn before_update_user(
        &self,
        _: &str,
        data: &mut JsObject,
        _: &DatabaseHookContext<'_, B>,
    ) -> AuthResult<HookControl> {
        self.0.lock().unwrap().push(data.clone());
        Ok(HookControl::Continue)
    }
}
fn call(path: &str) -> alibi_core::endpoint::EndpointCall {
    alibi_core::endpoint::EndpointCall::new(
        &alibi_core::endpoint::EndpointDefinition {
            name: "update-user",
            operation_id: "updateUser",
            path: Some(path.into()),
            method: alibi_core::HttpMethod::Post,
        },
        None,
        None,
        Default::default(),
    )
}
async fn exercise<S: AuthSchema>(physical: Arc<dyn AuthStore<S>>, capture: Arc<Capture>) {
    let mut create = CreateUser::new()
        .with_name("stored")
        .with_email("real-username-patch@test");
    create.id = Some("42".into());
    create.username = Some("oldusername".into());
    create.display_username = Some("unchanged display".into());
    let user = physical.create_user(create).await.unwrap();
    let id = user.id().into_owned();
    for include_display in [true, false] {
        let policy = UsernameConfig {
            normalization: UsernameNormalization::Preserve,
            include_display_username: include_display,
            ..Default::default()
        };
        let mut config = AuthConfig::default();
        config.user.additional_fields = policy.fields();
        let config = Arc::new(config);
        let mut init = AuthInitContext::<S>::new(config.clone(), physical.clone());
        init.register_user_update_hook(Arc::new(Earlier));
        init.register_user_update_hook(Arc::new(UsernameUpdateHook(policy.clone())));
        let db = init.database_with_registered_transforms();
        for display in [
            None,
            Some(JsValue::Bool(false)),
            Some(text("OriginalDisplay")),
        ] {
            let mut update = UpdateUser {
                name: Some("original name".into()),
                adapter_native_fields: [("username".into(), JsValue::Number(42.0))].into(),
                ..Default::default()
            };
            if let Some(display) = &display {
                _ = update
                    .adapter_native_fields
                    .insert("displayUsername".into(), display.clone());
            }
            let previous_display = physical
                .get_user_by_id(&id)
                .await
                .unwrap()
                .unwrap()
                .display_username()
                .map(str::to_owned);
            let result = alibi_core::endpoint::with_endpoint_call_context(
                call("/update-user"),
                db.update_user(&id, update),
            )
            .await
            .unwrap();
            if display.is_none() {
                assert_eq!(result.display_username(), previous_display.as_deref());
            }
            assert_eq!(result.username(), Some("42")); // actual SQLite TEXT affinity, not hook coercion
            assert_eq!(result.name(), Some("original name"));
            let observed = capture.0.lock().unwrap().last().unwrap().clone();
            assert_eq!(observed["username"], JsValue::Number(42.0));
            assert_eq!(observed["name"], text("original name"));
            if let Some(display) = display {
                assert_eq!(observed["displayUsername"], display);
            } else {
                assert!(!observed.contains_key("displayUsername"));
            }
        }
        let context = AuthContext::<S>::new(config, physical.clone());
        let hook = UsernameUpdateHook(policy);
        // Default regex validates numeric 42 without coercing the returned value.
        let numeric = object(&[
            ("username", JsValue::Number(42.0)),
            ("id", text(&id)),
            ("other", JsValue::Undefined),
        ]);
        let result = alibi_core::endpoint::with_endpoint_call_context(
            call("/admin/update-user"),
            hook.before_update("not-an-actor", &numeric, &context, None),
        )
        .await
        .unwrap();
        let UserUpdateHookResult::Data(UserUpdatePatch(data)) = result else {
            panic!("full original spread");
        };
        assert_eq!(data["username"], JsValue::Number(42.0));
        assert!(data.contains_key("other"));
        assert_eq!(data["other"], JsValue::Undefined);
        for path in ["/update-user", "/sign-up/email", "/admin/update-user"] {
            let lower = UsernameUpdateHook(UsernameConfig::default());
            assert!(
                alibi_core::endpoint::with_endpoint_call_context(
                    call(path),
                    lower.before_update(&id, &numeric, &context, None)
                )
                .await
                .is_err()
            );
        }
        // These two paths bypass length validation, but still normalize.
        let lower = UsernameUpdateHook(UsernameConfig::default());
        let short = object(&[("username", text("X"))]);
        for path in ["/update-user", "/sign-up/email"] {
            let result = alibi_core::endpoint::with_endpoint_call_context(
                call(path),
                lower.before_update(&id, &short, &context, None),
            )
            .await
            .unwrap();
            let UserUpdateHookResult::Data(UserUpdatePatch(data)) = result else {
                panic!()
            };
            assert_eq!(data["username"], text("x"));
            assert!(!data.contains_key("displayUsername"));
        }
        assert!(
            alibi_core::endpoint::with_endpoint_call_context(
                call("/admin/update-user"),
                lower.before_update(&id, &short, &context, None)
            )
            .await
            .is_err()
        );
    }
    let policy = UsernameConfig {
        normalization: UsernameNormalization::Preserve,
        min_length: 1,
        ..Default::default()
    };
    let hook = UsernameUpdateHook(policy);
    let context = AuthContext::<S>::new(Arc::new(AuthConfig::default()), physical.clone());
    let own_id = object(&[("id", text(&id)), ("username", text("42"))]);
    assert!(
        hook.before_update("different WHERE locator", &own_id, &context, None)
            .await
            .is_ok()
    );
    let no_id = object(&[("username", text("42"))]);
    assert!(
        hook.before_update(&id, &no_id, &context, None)
            .await
            .is_err()
    );
    let numeric_id = object(&[("id", JsValue::Number(42.0)), ("username", text("42"))]);
    assert!(
        hook.before_update(&id, &numeric_id, &context, None)
            .await
            .is_err()
    );
    let session_call = call("/admin/update-user");
    let actor = alibi_core::UserView::from(&user);
    let actor_session = alibi_core::SessionView {
        user_id: id.clone(),
        ..serde_json::from_value(serde_json::json!({
            "id":"session","userId":id,"token":"token","expiresAt":"2100-01-01T00:00:00Z",
            "createdAt":"2020-01-01T00:00:00Z","updatedAt":"2020-01-01T00:00:00Z"
        }))
        .unwrap()
    };
    session_call.record_authenticated_session(actor.clone(), actor_session.clone());
    // A truthy session ID beats the numeric original ID.
    assert!(
        alibi_core::endpoint::with_endpoint_call_context(
            session_call,
            hook.before_update(&id, &numeric_id, &context, None)
        )
        .await
        .is_ok()
    );
    let mut other_actor = actor;
    other_actor.id = "different".into();
    let session_call = call("/admin/update-user");
    session_call.record_authenticated_session(other_actor, actor_session);
    assert!(
        alibi_core::endpoint::with_endpoint_call_context(
            session_call,
            hook.before_update(&id, &own_id, &context, None)
        )
        .await
        .is_err()
    );

    let context = Arc::new(context);
    alibi_core::store::transaction(physical.as_ref(), move |tx| {
        Box::pin(async move {
            let mut competitor = CreateUser::new().with_email("local-competitor@test");
            competitor.username = Some("uncommitted".into());
            let _ = tx.create_user(competitor).await?;
            let original = object(&[("username", text("uncommitted"))]);
            assert!(
                hook.before_update("where-only", &original, &context, Some(tx))
                    .await
                    .is_err()
            );
            Err::<(), _>(alibi_core::AuthError::bad_request("rollback competitor"))
        })
    })
    .await
    .unwrap_err();
    assert!(
        physical
            .get_user_by_username("uncommitted")
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn real_username_original_patches_sqlite_seaorm() {
    use alibi_seaorm::store::__private_test_support as support;
    let db = alibi_seaorm::Database::connect("sqlite::memory:")
        .await
        .unwrap();
    support::migrator::run_migrations(&db).await.unwrap();
    let capture = Arc::new(Capture::default());
    let physical = alibi_seaorm::SeaOrmStore::<support::bundled_schema::BundledSchema>::new(
        AuthConfig::default(),
        db,
    )
    .with_hooks(vec![capture.clone()]);
    exercise(Arc::new(physical), capture).await;
}
#[tokio::test]
async fn real_username_original_patches_sqlite_sqlx() {
    use alibi_sqlx::store::__private_test_support as support;
    let pool = alibi_sqlx::sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let store = alibi_sqlx::SqlxStore::<support::bundled_schema::BundledSchema>::new(
        AuthConfig::default(),
        pool,
    );
    support::migrator::run_migrations(store.pool())
        .await
        .unwrap();
    let capture = Arc::new(Capture::default());
    exercise(Arc::new(store.with_hooks(vec![capture.clone()])), capture).await;
}
