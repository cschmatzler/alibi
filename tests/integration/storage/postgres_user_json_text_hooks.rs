use super::{Backend, Db, SeaOrm, Sqlx, TestResult};
use alibi::store::{DatabaseHookContext, DatabaseHooks, HookBackend, HookControl};
use alibi::{Alibi, AuthBuilder, AuthConfig, AuthSchema, AuthUser, CreateUser, UpdateUser};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct HookState {
    action: String,
    events: Vec<Value>,
}

struct TextHooks(Arc<Mutex<HookState>>);

#[async_trait::async_trait]
impl<S: AuthSchema, B: HookBackend> DatabaseHooks<S, B> for TextHooks {
    async fn before_create_user(
        &self,
        user: &mut CreateUser,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        let mut state = self.0.lock().unwrap();
        state
            .events
            .push(json!({"phase":"create.before","metadata":user.metadata}));
        if state.action.ends_with("replace") {
            user.metadata = Some(json!(["hook", {"nested":true}, null]));
        }
        Ok(HookControl::Continue)
    }

    async fn after_create_user(
        &self,
        user: &S::User,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        let fields = user.additional_js_fields()?;
        self.0.lock().unwrap().events.push(json!({"phase":"create.after","metadata":fields.get("metadata").ok_or_else(|| alibi::AuthError::internal("metadata callback field missing"))?}));
        Ok(())
    }

    async fn before_update_user(
        &self,
        _: &str,
        update: &mut alibi::utils::json::JsObject,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<HookControl> {
        let mut state = self.0.lock().unwrap();
        state.events.push(json!({"phase":"update.before","metadata":update.get("metadata").ok_or_else(|| alibi::AuthError::internal("metadata callback field missing"))?}));
        if state.action.ends_with("replace") {
            _ = update.insert(
                "metadata".into(),
                json!(["hook", {"nested":true}, null]).into(),
            );
        } else if state.action == "update-clear" {
            _ = update.insert("metadata".into(), alibi::utils::json::JsValue::Null);
        }
        Ok(HookControl::Continue)
    }

    async fn after_update_user(
        &self,
        user: &S::User,
        _: &DatabaseHookContext<'_, B>,
    ) -> alibi::AuthResult<()> {
        let fields = user.additional_js_fields()?;
        self.0.lock().unwrap().events.push(json!({"phase":"update.after","metadata":fields.get("metadata").ok_or_else(|| alibi::AuthError::internal("metadata callback field missing"))?}));
        Ok(())
    }
}

async fn setup(db: &Db) -> TestResult<AuthConfig> {
    let contract: Value =
        serde_json::from_str(include_str!("../../fixtures/postgres-user-json-text.json"))?;
    _ = db
        .execute(contract["table_sql"].as_str().unwrap(), &[])
        .await?;
    let mut config = AuthConfig::new("postgres-user-text-hooks-secret-at-least-32");
    _ = config.user.additional_fields.insert(
        "metadata".into(),
        alibi::field_policy::FieldConfig::new(json!({"type":"json"})),
    );
    Ok(config)
}

async fn check<S: AuthSchema>(db: &Db, auth: &Alibi<S>, state: &Mutex<HookState>) -> TestResult {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../fixtures/postgres-user-json-text-hooks.json"
    ))?;
    assert_eq!(fixture["better_auth"], "1.7.18");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let mut id = String::new();
    for case in cases {
        let action = case["action"].as_str().unwrap();
        {
            let mut state = state.lock().unwrap();
            state.action = action.into();
            state.events.clear();
        }
        let creating = action.starts_with("create-");
        let row = if creating {
            auth.store()
                .create_user(
                    CreateUser::new()
                        .with_name("Text hooks")
                        .with_email(format!("{action}@text-hooks.example.com"))
                        .with_metadata(case["input"].clone()),
                )
                .await?
        } else {
            auth.store()
                .update_user(
                    &id,
                    UpdateUser {
                        metadata: Some(case["input"].clone()),
                        ..Default::default()
                    },
                )
                .await?
        };
        if creating {
            id = row.id().into_owned();
        }
        assert_eq!(row.id().as_ref(), id, "{action}");
        assert_eq!(
            json!(state.lock().unwrap().events),
            case["events"],
            "{action}"
        );
        assert_eq!(
            serde_json::to_value(auth.context().trusted_user_view(&row)?)?["metadata"],
            case["output"],
            "{action}"
        );
        let readback = auth
            .store()
            .get_user_by_id(&id)
            .await?
            .ok_or("source user must exist")?;
        assert_eq!(
            serde_json::to_value(auth.context().trusted_user_view(&readback)?)?["metadata"],
            case["output"],
            "{action}"
        );
        assert_eq!(
            json!(
                db.text(
                    "SELECT metadata FROM \"applicationUser\" WHERE id = $1",
                    &[&id]
                )
                .await?
            ),
            case["stored"],
            "{action}"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_sqlx_user_text_hooks_match_actual_callback_phases() -> TestResult {
    let db = Db::postgres().await?;
    let config = setup(&db).await?;
    let connection = Sqlx::connect(&db.url, None).await?;
    let state = Arc::new(Mutex::new(HookState::default()));
    let store = alibi::sqlx::SqlxStore::<super::postgres_user_json_text::Schema>::new(
        config.clone(),
        connection.clone(),
    )
    .with_hooks(vec![Arc::new(TextHooks(state.clone()))]);
    let auth = AuthBuilder::new(config).store(store).build().await?;
    check(&db, &auth, &state).await?;
    drop(auth);
    Sqlx::close(connection).await
}

#[tokio::test]
#[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
async fn postgres_seaorm_user_text_hooks_match_actual_callback_phases() -> TestResult {
    let db = Db::postgres().await?;
    let config = setup(&db).await?;
    let connection = SeaOrm::connect(&db.url, None).await?;
    let state = Arc::new(Mutex::new(HookState::default()));
    let store = alibi::seaorm::SeaOrmStore::<super::postgres_seaorm_user_json_text::Schema>::new(
        config.clone(),
        connection.clone(),
    )
    .with_hooks(vec![Arc::new(TextHooks(state.clone()))]);
    let auth = AuthBuilder::new(config).store(store).build().await?;
    check(&db, &auth, &state).await?;
    drop(auth);
    SeaOrm::close(connection).await
}
