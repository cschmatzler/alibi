use crate::store::{UserCreateHook, UserStore};
use crate::test_store::{BundledSchema, MemoryStore};
use crate::user_validation::{
    UserInfoValidator, UserValidationContext, UserValidationData, UserValidationRejection,
    UserValidationSource,
};
use crate::{
    AuthConfig, AuthContext, AuthError, AuthInitContext, AuthResult, AuthTransaction, CreateUser,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn raw_username_lookup_keeps_memory_scalar_equality() {
    use crate::utils::json::JsValue;
    let store = crate::store::stateless::StatelessStore::default();
    let mut raw = CreateUser::new().with_email("numeric@fixture.test");
    raw.adapter_native_fields
        .insert("username".into(), serde_json::json!(42));
    let numeric = store.create_user(raw).await.unwrap();
    assert!(
        store
            .get_user_by_username_value(&JsValue::String("42".into()))
            .await
            .unwrap()
            .is_none()
    );
    let mut text = CreateUser::new().with_email("text@fixture.test");
    text.username = Some("42".into());
    let string = store.create_user(text).await.unwrap();
    assert_eq!(
        store
            .get_user_by_username_value(&JsValue::Number(42.0))
            .await
            .unwrap()
            .unwrap()
            .id,
        numeric.id
    );
    assert_eq!(
        store
            .get_user_by_username_value(&JsValue::String("42".into()))
            .await
            .unwrap()
            .unwrap()
            .id,
        string.id
    );
}

#[tokio::test]
async fn typed_user_create_transform_invalidates_only_unchanged_raw_shadows() {
    use crate::utils::json::JsValue;
    let config = Arc::new(AuthConfig::default());
    let physical = Arc::new(MemoryStore::new(config.clone()));
    let mut init = AuthInitContext::<BundledSchema>::new(config, physical);
    init.register_user_create_transform(|mut data| {
        data.name = Some("typed replacement".into());
        data.email = Some("typed@fixture.test".into());
        data.username = Some("typed-user".into());
        Ok(data)
    });
    init.register_user_create_transform(|data| {
        assert_eq!(data.provider_name, None);
        assert_eq!(data.provider_email, None);
        assert!(!data.adapter_native_fields.contains_key("username"));
        Ok(data)
    });
    let database = init.database_with_registered_transforms();
    let mut input = CreateUser::new().with_email("original@fixture.test");
    input.provider_name = Some(JsValue::Null);
    input.provider_email = Some(JsValue::String("original@fixture.test".into()));
    input
        .adapter_native_fields
        .insert("username".into(), serde_json::json!(42));
    let user = database.create_user(input).await.unwrap();
    assert_eq!(user.name.as_deref(), Some("typed replacement"));
    assert_eq!(user.email.as_deref(), Some("typed@fixture.test"));
    assert_eq!(user.username.as_deref(), Some("typed-user"));
}

#[test]
fn raw_user_shadows_keep_explicit_edits_and_preserve_undefined_and_removal() {
    use crate::utils::json::{JsString, JsValue};
    let mut before = CreateUser::new().with_name("original");
    before.provider_name = Some(JsValue::String(JsString::from_code_units(vec![0xd800])));
    before.provider_email = Some(JsValue::Undefined);
    before.provider_image = Some(JsValue::Null);
    before
        .adapter_native_fields
        .insert("username".into(), serde_json::json!(42));

    before.id = Some("original-id".into());
    before
        .adapter_native_fields
        .insert("id".into(), serde_json::json!(42));
    let mut changed_id = before.clone();
    changed_id.id = Some("typed-id".into());
    changed_id.reconcile_native_shadows(&before);
    assert!(!changed_id.adapter_native_fields.contains_key("id"));
    let mut explicit_id = before.clone();
    explicit_id.id = Some("typed-id".into());
    explicit_id
        .adapter_native_fields
        .insert("id".into(), serde_json::Value::Null);
    explicit_id.reconcile_native_shadows(&before);
    assert_eq!(
        explicit_id.adapter_native_fields["id"],
        serde_json::Value::Null
    );

    let mut unchanged = before.clone();
    unchanged.reconcile_native_shadows(&before);
    assert_eq!(unchanged.provider_name, before.provider_name);
    assert_eq!(unchanged.provider_email, Some(JsValue::Undefined));
    assert_eq!(unchanged.provider_image, Some(JsValue::Null));

    for explicit in [Some(JsValue::Null), Some(JsValue::Undefined), None] {
        let mut edited = before.clone();
        edited.name = Some("typed replacement".into());
        edited.provider_name = explicit.clone();
        edited.username = Some("typed-user".into());
        edited
            .adapter_native_fields
            .insert("username".into(), serde_json::json!("explicit-raw"));
        edited.reconcile_native_shadows(&before);
        assert_eq!(edited.provider_name, explicit);
        assert_eq!(
            edited.adapter_native_fields["username"],
            serde_json::json!("explicit-raw")
        );
    }
    let mut removed = before.clone();
    removed.provider_name = None;
    removed.adapter_native_fields.remove("username");
    removed.reconcile_native_shadows(&before);
    assert_eq!(removed.provider_name, None);
    assert_eq!(removed.name.as_deref(), Some("original"));
    assert!(!removed.adapter_native_fields.contains_key("username"));
}

#[test]
fn update_raw_shadow_reconciliation_uses_the_same_explicit_edit_precedence() {
    use crate::utils::json::JsValue;
    let mut before = crate::UpdateUser::default();
    before.provider_name = Some(JsValue::Undefined);
    before.provider_image = Some(JsValue::Null);
    before
        .adapter_native_fields
        .insert("username".into(), serde_json::json!(42));

    let mut typed = before.clone();
    typed.name = Some("typed".into());
    typed.username = Some("typed-user".into());
    typed.reconcile_native_shadows(&before);
    assert_eq!(typed.provider_name, None);
    assert_eq!(typed.provider_image, Some(JsValue::Null));
    assert!(!typed.adapter_native_fields.contains_key("username"));

    for explicit in [Some(JsValue::Null), Some(JsValue::Undefined), None] {
        let mut edited = before.clone();
        edited.image = Some("typed-image".into());
        edited.provider_image = explicit.clone();
        edited.reconcile_native_shadows(&before);
        if explicit == before.provider_image {
            assert_eq!(edited.provider_image, None);
        } else {
            assert_eq!(edited.provider_image, explicit);
        }
        assert_eq!(edited.image.as_deref(), Some("typed-image"));
    }
}

type Events = Arc<Mutex<Vec<&'static str>>>;

struct Identity(Events);

#[async_trait]
impl UserInfoValidator for Identity {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _: &UserValidationContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        self.0.lock().unwrap().push("identity");
        Ok(
            (data.user.email.as_deref() == Some("identity-denied@fixture.test")).then(|| {
                UserValidationRejection {
                    error: "denied".into(),
                    error_description: None,
                }
            }),
        )
    }
}

struct Hook(Events);

#[async_trait]
impl UserCreateHook<BundledSchema> for Hook {
    async fn before_create(
        &self,
        mut data: CreateUser,
        _: &AuthContext<BundledSchema>,
        transaction: Option<&dyn AuthTransaction<BundledSchema>>,
    ) -> AuthResult<CreateUser> {
        assert!(transaction.is_none());
        tokio::task::yield_now().await;
        self.0.lock().unwrap().push("async");
        assert_eq!(data.username.as_deref(), Some("before"));
        if data.email.as_deref() == Some("hook-denied@fixture.test") {
            return Err(AuthError::bad_request("hook denied"));
        }
        data.username = Some("hook".into());
        Ok(data)
    }
}

#[tokio::test]
async fn ordered_user_create_hooks_follow_identity_admission_and_short_circuit() {
    let request = crate::AuthRequest::new(crate::HttpMethod::Post, "/admin/create-user");
    crate::hooks::with_request_hook_context(&request, ordered_user_create_hooks()).await;
}

async fn ordered_user_create_hooks() {
    let events: Events = Arc::default();
    let mut config = AuthConfig::default();
    config.user_validation = Some(Arc::new(Identity(events.clone())));
    let config = Arc::new(config);
    let physical = Arc::new(MemoryStore::new(config.clone()));
    let mut init = AuthInitContext::<BundledSchema>::new(config, physical.clone());
    let log = events.clone();
    init.register_user_create_transform(move |mut data| {
        log.lock().unwrap().push("before");
        data.username = Some("before".into());
        Ok(data)
    });
    init.register_user_create_hook(Arc::new(Hook(events.clone())));
    let log = events.clone();
    init.register_user_create_transform(move |data| {
        log.lock().unwrap().push("after");
        assert_eq!(data.username.as_deref(), Some("hook"));
        Ok(data)
    });
    let database = init.database_with_registered_transforms();
    let user = database
        .create_user_with_source(
            CreateUser::new().with_email("created@fixture.test"),
            UserValidationSource::creation("admin"),
        )
        .await
        .unwrap();
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["identity", "before", "async", "after"]
    );
    assert_eq!(
        physical
            .get_user_by_id(&user.id)
            .await
            .unwrap()
            .unwrap()
            .username
            .as_deref(),
        Some("hook")
    );
    for (email, expected) in [
        ("identity-denied@fixture.test", vec!["identity"]),
        (
            "hook-denied@fixture.test",
            vec!["identity", "before", "async"],
        ),
    ] {
        events.lock().unwrap().clear();
        assert!(
            database
                .create_user_with_source(
                    CreateUser::new().with_email(email),
                    UserValidationSource::creation("admin"),
                )
                .await
                .is_err()
        );
        assert_eq!(*events.lock().unwrap(), expected);
        assert!(
            physical
                .get_user_by_email(&email.into())
                .await
                .unwrap()
                .is_none()
        );
    }
    events.lock().unwrap().clear();
    assert!(
        database
            .create_user(CreateUser::new().with_email("no-source@fixture.test"))
            .await
            .is_err()
    );
    assert!(events.lock().unwrap().is_empty());
}
