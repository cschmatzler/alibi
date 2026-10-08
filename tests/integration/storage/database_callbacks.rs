//! Application storage hooks observe admitted mutations and committed snapshots.
use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::AuthSchema;
use alibi_core::field_policy::FieldValues;
use alibi_core::store::{
    AccountStore, DatabaseHookContext, DatabaseHooks, HookBackend, HookControl, SessionStore,
    UserStore,
};
use alibi_core::utils::json::JsValue;
use alibi_core::verification::{VerificationCreation, VerificationSnapshot};
use alibi_core::{
    AuthAccount, AuthError, AuthResult, AuthSession, AuthUser, CreateAccount, CreateSession,
    CreateUser, CreateVerification, UpdateAccount, UpdateVerification,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

backend_tests!(database_callback_veto_mutation_missing_and_after_error_effects);
postgres_tests!(database_callback_veto_mutation_missing_and_after_error_effects);
#[derive(Clone, Default)]
struct Application {
    mode: Arc<Mutex<&'static str>>,
    events: Arc<Mutex<Vec<Value>>>,
}
impl Application {
    fn set(&self, mode: &'static str) {
        *self.mode.lock().unwrap() = mode;
        self.events.lock().unwrap().clear();
    }
    fn before(&self, phase: &'static str, value: Value) -> AuthResult<HookControl> {
        self.events.lock().unwrap().push(json!([phase, value]));
        Ok(if *self.mode.lock().unwrap() == phase {
            HookControl::Cancel
        } else {
            HookControl::Continue
        })
    }
    fn after(&self, phase: &'static str, value: Value) -> AuthResult<()> {
        self.events.lock().unwrap().push(json!([phase, value]));
        if *self.mode.lock().unwrap() == phase {
            Err(AuthError::forbidden("application after hook failed"))
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for Application {
    async fn before_create_account(
        &self,
        input: &mut CreateAccount,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        let result = self.before("account-create", json!(input.user_id))?;
        input.scope = Some("hook-created".into());
        Ok(result)
    }
    async fn before_update_account(
        &self,
        id: &str,
        input: &mut UpdateAccount,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        let result = self.before("account-update", json!(id))?;
        input.scope = Some("hook-updated".into());
        Ok(result)
    }
    async fn after_update_account(
        &self,
        input: &S::Account,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.after("account-updated", json!([input.id(), input.scope()]))
    }
    async fn before_delete_account(
        &self,
        input: &S::Account,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        self.before("account-delete", json!([input.id(), input.scope()]))
    }
    async fn after_delete_account(
        &self,
        input: &S::Account,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.after("account-deleted", json!([input.id(), input.scope()]))
    }
    async fn before_update_session(
        &self,
        token: &str,
        fields: &mut FieldValues,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        let result = self.before("session-update", json!(token))?;
        drop(fields.insert("ipAddress".into(), JsValue::String("198.51.100.77".into())));
        Ok(result)
    }
    async fn after_update_session_missing(
        &self,
        token: &str,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.after("session-missing", json!(token))
    }
    async fn after_update_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.after(
            "session-updated",
            json!([session.token(), session.ip_address()]),
        )
    }
    async fn before_delete_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        self.before(
            "session-delete",
            json!([session.token(), session.ip_address()]),
        )
    }
    async fn after_delete_session(
        &self,
        session: &S::Session,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.after(
            "session-deleted",
            json!([session.token(), session.ip_address()]),
        )
    }
    async fn after_delete_user(
        &self,
        user: &S::User,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.after("user-deleted", json!([user.id(), user.email()]))
    }
    async fn before_create_verification(
        &self,
        input: &mut CreateVerification,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        let result = self.before("verification-create", json!(input.identifier))?;
        input.value = "legacy-value".into();
        Ok(result)
    }
}
struct RecordVerification(Application);
#[async_trait]
impl<S: AuthSchema, H: HookBackend> DatabaseHooks<S, H> for RecordVerification {
    async fn before_create_verification_record(
        &self,
        input: &mut VerificationCreation,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<HookControl> {
        assert_eq!(input.created_at, input.updated_at);
        assert_eq!(input.value, "legacy-value");
        let result = self
            .0
            .before("verification-record", json!(input.identifier))?;
        input.identifier = format!("mapped-{}", input.identifier);
        input.value = "record-value".into();
        Ok(result)
    }
    async fn after_update_verification_record(
        &self,
        snapshot: Option<&VerificationSnapshot>,
        _: &DatabaseHookContext<'_, H>,
    ) -> AuthResult<()> {
        self.0.after(
            "verification-updated",
            match snapshot {
                Some(value) => json!([value.identifier()?, value.value()?]),
                None => Value::Null,
            },
        )
    }
}
fn account(user: &str) -> CreateAccount {
    CreateAccount {
        user_id: user.into(),
        provider_id: "application".into(),
        account_id: "subject".into(),
        scope: Some("submitted".into()),
        additional_fields: Default::default(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        password: None,
    }
}
async fn database_callback_veto_mutation_missing_and_after_error_effects<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, raw) = db
        .migrated::<B>("database-callback-contract-secret-32-characters")
        .await?;
    let hooks = Application::default();
    let store = B::hook(
        B::hook(raw, hooks.clone()),
        RecordVerification(hooks.clone()),
    );
    let user = store
        .create_user(CreateUser::new().with_email("callback@example.test"))
        .await?;
    let user_id = user.id().into_owned();
    hooks.set("account-create");
    assert!(store.create_account(account(&user_id)).await.is_err());
    assert_eq!(db.count("accounts").await?, 0);
    hooks.set("");
    let created = store.create_account(account(&user_id)).await?;
    let id = created.id().into_owned();
    assert_eq!(
        db.text("SELECT scope FROM accounts WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("hook-created")
    );
    hooks.set("account-update");
    let original = db.table("accounts").await?;
    assert!(
        store
            .update_account(&id, UpdateAccount::default())
            .await
            .is_err()
    );
    assert_eq!(db.table("accounts").await?, original);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        json!([["account-update", id]]).as_array().unwrap().clone()
    );
    hooks.set("account-updated");
    assert!(
        store
            .update_account(&id, UpdateAccount::default())
            .await
            .is_err()
    );
    assert_eq!(
        db.text("SELECT scope FROM accounts WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("hook-updated")
    );
    assert_eq!(
        hooks.events.lock().unwrap().last(),
        Some(&json!(["account-updated", [id, "hook-updated"]]))
    );
    hooks.set("account-delete");
    let retained = db.table("accounts").await?;
    store.delete_account(&id).await?;
    assert_eq!(db.table("accounts").await?, retained);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![json!(["account-delete", [id, "hook-updated"]])]
    );
    hooks.set("account-deleted");
    assert!(store.delete_account(&id).await.is_err());
    assert_eq!(db.count("accounts").await?, 0);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![
            json!(["account-delete", [id, "hook-updated"]]),
            json!(["account-deleted", [id, "hook-updated"]])
        ]
    );
    hooks.set("");
    let session = store
        .create_session(CreateSession {
            user_id: user_id.clone(),
            token: Some("callback-session".into()),
            expires_at: Utc::now() + Duration::hours(1),
            additional_fields: Default::default(),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    let before_session_update = db.table("sessions").await?;
    hooks.set("session-update");
    assert!(
        store
            .update_session_fields(session.token(), FieldValues::new())
            .await?
            .is_none()
    );
    assert_eq!(db.table("sessions").await?, before_session_update);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![json!(["session-update", session.token()])]
    );
    hooks.set("session-updated");
    assert!(
        store
            .update_session_fields(session.token(), FieldValues::new())
            .await
            .is_err()
    );
    assert_eq!(
        db.text("SELECT ip_address FROM sessions", &[])
            .await?
            .as_deref(),
        Some("198.51.100.77")
    );
    assert_eq!(
        hooks.events.lock().unwrap().last(),
        Some(&json!([
            "session-updated",
            [session.token(), "198.51.100.77"]
        ]))
    );
    hooks.set("");
    assert!(
        store
            .update_session_fields("absent", FieldValues::new())
            .await?
            .is_none()
    );
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![
            json!(["session-update", "absent"]),
            json!(["session-missing", "absent"])
        ]
    );
    hooks.set("session-delete");
    let retained = db.table("sessions").await?;
    store.delete_session(session.token()).await?;
    assert_eq!(db.table("sessions").await?, retained);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![json!([
            "session-delete",
            [session.token(), "198.51.100.77"]
        ])]
    );
    hooks.set("session-deleted");
    assert!(store.delete_session(session.token()).await.is_err());
    assert_eq!(db.count("sessions").await?, 0);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![
            json!(["session-delete", [session.token(), "198.51.100.77"]]),
            json!(["session-deleted", [session.token(), "198.51.100.77"]])
        ]
    );
    let auth = alibi::AuthBuilder::new(alibi::AuthConfig::new(
        "database-callback-contract-secret-32-characters",
    ))
    .store(store)
    .build()
    .await?;
    let store = auth.store();
    let proof = || CreateVerification {
        identifier: "proof".into(),
        value: "submitted".into(),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    for veto in ["verification-create", "verification-record"] {
        hooks.set(veto);
        assert!(
            auth.context()
                .verifications()
                .create(proof())
                .await?
                .is_none()
        );
        assert_eq!(db.count("verifications").await?, 0);
        assert_eq!(
            hooks.events.lock().unwrap().len(),
            if veto == "verification-create" { 1 } else { 2 }
        );
    }
    hooks.set("");
    assert!(
        auth.context()
            .verifications()
            .create(proof())
            .await?
            .is_some()
    );
    assert_eq!(db.count_where("SELECT COUNT(*) FROM verifications WHERE identifier='mapped-proof' AND value='record-value'",&[]).await?,1);
    hooks.set("verification-updated");
    assert!(
        store
            .update_verification_by_identifier(
                "mapped-proof",
                UpdateVerification {
                    value: Some("updated-value".into()),
                    ..Default::default()
                }
            )
            .await
            .is_err()
    );
    assert_eq!(
        db.text("SELECT value FROM verifications", &[])
            .await?
            .as_deref(),
        Some("updated-value")
    );
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![json!([
            "verification-updated",
            ["mapped-proof", "updated-value"]
        ])]
    );
    hooks.set("");
    assert!(
        store
            .update_verification_by_identifier(
                "absent",
                UpdateVerification {
                    value: Some("unwritten".into()),
                    ..Default::default()
                }
            )
            .await?
            .is_none()
    );
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![json!(["verification-updated", Value::Null])]
    );
    hooks.set("user-deleted");
    assert!(store.delete_user(&user_id).await.is_err());
    assert_eq!(db.count("users").await?, 0);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        vec![json!(["user-deleted", [user_id, "callback@example.test"]])]
    );
    B::close(connection).await
}
