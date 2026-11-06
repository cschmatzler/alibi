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
        assert!(physical.get_user_by_email(email).await.unwrap().is_none());
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
