//! The initialized (decorated) store delegates organization, verification, JWK and session operations.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use super::{Backend, Db, TestResult, backend_tests, postgres_tests};
use alibi::entity::AuthUser;
use alibi::store::{NumericTextInput, transaction};
use alibi::types::{
    CreateInvitation, CreateJwk, CreateOrganization, CreateSession, CreateTeam, CreateUser,
    CreateVerification, UpdateTeam,
};
use alibi::{AuthBuilder, AuthConfig};
use alibi::{AuthError, AuthSession};
use chrono::{Duration, Utc};
use std::sync::Arc;

backend_tests!(
    decorated_store_delegates_organization_verification_and_jwk_operations,
    text_number_coercion_uses_the_database_cast,
    hooks_without_overrides_admit_every_lifecycle_operation,
    required_null_fields_take_their_configured_creation_default,
    cancelling_user_hooks_surface_creation_cancelled
);
postgres_tests!(
    decorated_store_delegates_organization_verification_and_jwk_operations,
    text_number_coercion_uses_the_database_cast,
    hooks_without_overrides_admit_every_lifecycle_operation,
    required_null_fields_take_their_configured_creation_default,
    cancelling_user_hooks_surface_creation_cancelled
);

const SECRET: &str = "decorated-store-secret-at-least-32-characters";

async fn decorated_store_delegates_organization_verification_and_jwk_operations<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET);
    let auth = AuthBuilder::new(config.clone())
        .store(B::store(Arc::new(config), &connection))
        .build()
        .await?;
    let store = auth.store();
    let organization = store
        .create_organization(CreateOrganization::new("acme", "acme"))
        .await?
        .id;
    let owner = store
        .create_user(CreateUser::new().with_email("owner@example.test"))
        .await?
        .id()
        .into_owned();
    let team = store
        .create_team(CreateTeam {
            name: "Before".into(),
            organization_id: organization.clone(),
            updated_at: None,
        })
        .await?;
    let renamed = store
        .update_team(
            &organization,
            &team.id,
            UpdateTeam {
                name: Some("After".into()),
            },
        )
        .await?;
    assert_eq!(renamed.name, "After");
    drop(store.add_team_member(&team.id, &owner, None).await?);
    assert_eq!(store.remove_team_member(&team.id, &owner).await?, 1);
    assert_eq!(store.remove_team_member(&team.id, &owner).await?, 0);

    let invitation = store
        .create_invitation(CreateInvitation::new(
            &organization,
            "guest@example.test",
            "member",
            &owner,
            Utc::now() + Duration::hours(1),
        ))
        .await?;
    let later = Utc::now() + Duration::days(2);
    let reissued = store
        .update_invitation_expiry(&invitation.id, later)
        .await?;
    assert_eq!(reissued.expires_at.timestamp(), later.timestamp());
    assert!(matches!(
        store.update_invitation_expiry("missing", later).await,
        Err(AuthError::NotFound(_) | AuthError::Api { .. } | AuthError::Upstream { .. })
    ));

    let _ = store
        .create_verification(CreateVerification {
            identifier: "by-value".into(),
            value: "lookup-code".into(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await?;
    let found = store.get_verification_by_value("lookup-code").await?;
    assert!(found.is_some());
    assert!(store.get_verification_by_value("absent").await?.is_none());

    let stored = transaction::<B::Schema, _, _>(store.as_ref(), |tx| {
        Box::pin(async move {
            let created = tx
                .create_jwk(CreateJwk {
                    id: Some("key-1".into()),
                    public_key: "public".into(),
                    private_key: "private".into(),
                    created_at: Utc::now(),
                    expires_at: None,
                    alg: Some("EdDSA".into()),
                    crv: Some("Ed25519".into()),
                })
                .await?;
            Ok((created.id, tx.list_jwks().await?.len()))
        })
    })
    .await?;
    assert_eq!(stored, ("key-1".to_owned(), 1));
    assert_eq!(store.list_jwks().await?.len(), 1);
    Ok(())
}

async fn text_number_coercion_uses_the_database_cast<B: Backend>(db: Db) -> TestResult {
    let (_, store) = db.migrated::<B>(SECRET).await?;
    assert_eq!(
        alibi::store::UserStore::coerce_user_text_number(&store, NumericTextInput::Integer(42))
            .await?,
        "42"
    );
    let real =
        alibi::store::UserStore::coerce_user_text_number(&store, NumericTextInput::Real(1.5))
            .await?;
    assert_eq!(real.parse::<f64>()?, 1.5);
    assert!(
        alibi::store::UserStore::coerce_user_text_number(&store, NumericTextInput::Real(f64::NAN))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn stateless_store_lists_only_requested_ephemeral_sessions() -> TestResult {
    let config = AuthConfig::new(SECRET);
    let mut config = config;
    config.session = config.session.stateless();
    let auth = AuthBuilder::without_database(config).build().await?;
    let store = auth.store();
    let mut tokens = Vec::new();
    for index in 0..2 {
        let user = store
            .create_user(CreateUser::new().with_email(format!("eph{index}@example.test")))
            .await?;
        let session = store
            .create_session(CreateSession {
                additional_fields: Default::default(),
                token: None,
                user_id: user.id().into_owned(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await?;
        tokens.push(session.token().to_owned());
    }
    let listed = store.get_sessions_by_tokens(&tokens[..1]).await?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].token(), tokens[0]);
    Ok(())
}

struct Silent;
impl<S: alibi::AuthSchema, H: alibi::store::HookBackend> alibi::store::DatabaseHooks<S, H>
    for Silent
{
}

async fn hooks_without_overrides_admit_every_lifecycle_operation<B: Backend>(db: Db) -> TestResult {
    use alibi::entity::AuthAccount;
    use alibi::store::{AccountStore, SessionStore, UserStore};
    use alibi::{CreateAccount, UpdateAccount, UpdateUser};

    let (_, raw) = db.migrated::<B>(SECRET).await?;
    let store = B::hook(raw, Silent);
    let user = store
        .create_user(CreateUser::new().with_email("silent@example.test"))
        .await?;
    let id = user.id().into_owned();
    let renamed = store
        .update_user(
            &id,
            UpdateUser {
                name: Some("Silent".into()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(renamed.name(), Some("Silent"));
    let account = store
        .create_account(CreateAccount {
            user_id: id.clone(),
            account_id: "remote".into(),
            provider_id: "provider".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            password: None,
            scope: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            additional_fields: Default::default(),
        })
        .await?;
    let _ = store
        .update_account(&account.id(), UpdateAccount::default())
        .await?;
    store.delete_account(&account.id()).await?;
    let session = store
        .create_session(CreateSession {
            additional_fields: Default::default(),
            token: None,
            user_id: id.clone(),
            expires_at: Utc::now() + Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
        })
        .await?;
    store.delete_session(session.token()).await?;
    store.delete_user(&id).await?;
    assert_eq!(db.count("users").await?, 0);
    Ok(())
}

async fn required_null_fields_take_their_configured_creation_default<B: Backend>(
    db: Db,
) -> TestResult {
    use alibi::AuthInitContext;
    use alibi::field_policy::{FieldConfig, FieldDefault};
    use alibi::utils::json::JsValue;

    let (_, raw) = db.migrated::<B>(SECRET).await?;
    let mut config = AuthConfig::new(SECRET);
    let mut field = FieldConfig::new(serde_json::json!({"type":"string"}));
    field.required = true;
    field.default = Some(FieldDefault::Value(JsValue::String("member".into())));
    drop(config.user.additional_fields.insert("role".into(), field));
    let init = AuthInitContext::<B::Schema>::new(Arc::new(config), Arc::new(raw));
    let store = init.database_with_registered_transforms();
    let mut input = CreateUser::new().with_email("defaulted@example.test");
    drop(input.additional_fields.insert("role".into(), JsValue::Null));
    let user = store.create_user(input).await?;
    assert_eq!(user.role(), Some("member"));
    assert_eq!(
        db.text("SELECT role FROM users", &[]).await?.as_deref(),
        Some("member")
    );
    Ok(())
}

struct RefuseUsers;
#[async_trait::async_trait]
impl<S: alibi::AuthSchema, H: alibi::store::HookBackend> alibi::store::DatabaseHooks<S, H>
    for RefuseUsers
{
    async fn before_create_user(
        &self,
        _: &mut CreateUser,
        _: &alibi::store::DatabaseHookContext<'_, H>,
    ) -> alibi::AuthResult<alibi::store::HookControl> {
        Ok(alibi::store::HookControl::Cancel)
    }
}

async fn cancelling_user_hooks_surface_creation_cancelled<B: Backend>(db: Db) -> TestResult {
    use alibi::store::UserStore;

    let (_, raw) = db.migrated::<B>(SECRET).await?;
    let store = B::hook(raw, RefuseUsers);
    let error = store
        .create_user(CreateUser::new().with_email("refused@example.test"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthError::UserCreationCancelled),
        "{error:?}"
    );
    assert_eq!(db.count("users").await?, 0);
    Ok(())
}
