#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "integration tests intentionally use direct assertions over concrete JSON payloads"
)]
#![expect(
    unreachable_pub,
    reason = "SeaORM DeriveEntityModel requires pub types"
)]

mod user {

    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: Option<String>,
        pub email: Option<String>,
        pub email_verified: bool,
        pub image: Option<String>,
        pub username: Option<String>,
        pub display_username: Option<String>,
        pub two_factor_enabled: bool,
        pub role: Option<String>,
        pub banned: bool,
        pub ban_reason: Option<String>,
        pub ban_expires: Option<DateTimeUtc>,
        pub metadata: Json,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub tenant_id: i64,
        pub locale: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthUser for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn email(&self) -> Option<&str> {
            self.email.as_deref()
        }
        fn name(&self) -> Option<&str> {
            self.name.as_deref()
        }
        fn email_verified(&self) -> bool {
            self.email_verified
        }
        fn image(&self) -> Option<&str> {
            self.image.as_deref()
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
        fn username(&self) -> Option<&str> {
            self.username.as_deref()
        }
        fn display_username(&self) -> Option<&str> {
            self.display_username.as_deref()
        }
        fn two_factor_enabled(&self) -> bool {
            self.two_factor_enabled
        }
        fn role(&self) -> Option<&str> {
            self.role.as_deref()
        }
        fn banned(&self) -> bool {
            self.banned
        }
        fn ban_reason(&self) -> Option<&str> {
            self.ban_reason.as_deref()
        }
        fn ban_expires(&self) -> Option<DateTime<Utc>> {
            self.ban_expires
        }
        fn metadata(&self) -> &serde_json::Value {
            &self.metadata
        }
    }

    impl SeaOrmUserModel for Model {
        type Id = i32;

        type Entity = Entity;

        type ActiveModel = ActiveModel;

        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }

        fn email_column() -> Self::Column {
            Column::Email
        }

        fn username_column() -> Option<Self::Column> {
            Some(Column::Username)
        }

        fn name_column() -> Self::Column {
            Column::Name
        }

        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }

        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_error| AuthError::bad_request("Invalid user id"))
        }

        fn new_active(
            id: Option<Self::Id>,
            create_user: CreateUser,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            ActiveModel {
                id: id.map_or(NotSet, Set),
                name: Set(create_user.name),
                email: Set(create_user.email),
                email_verified: Set(create_user.email_verified.unwrap_or(false)),
                image: Set(create_user.image),
                username: Set(create_user.username),
                display_username: Set(create_user.display_username),
                two_factor_enabled: Set(false),
                role: Set(create_user.role),
                banned: Set(false),
                ban_reason: Set(None),
                ban_expires: Set(None),
                metadata: Set(create_user.metadata.unwrap_or(json!({}))),
                created_at: Set(now),
                updated_at: Set(now),
                tenant_id: Set(1),
                locale: Set("en".to_owned()),
            }
        }

        fn apply_update(active: &mut Self::ActiveModel, update: UpdateUser, now: DateTime<Utc>) {
            if let Some(email) = update.email {
                active.email = Set(Some(email));
            }
            if let Some(name) = update.name {
                active.name = Set(Some(name));
            }
            if let Some(image) = update.image {
                active.image = Set(Some(image));
            }
            if let Some(email_verified) = update.email_verified {
                active.email_verified = Set(email_verified);
            }
            if let Some(username) = update.username {
                active.username = Set(Some(username));
            }
            if let Some(display_username) = update.display_username {
                active.display_username = Set(Some(display_username));
            }
            if let Some(role) = update.role {
                active.role = Set(Some(role));
            }
            if let Some(two_factor_enabled) = update.two_factor_enabled {
                active.two_factor_enabled = Set(two_factor_enabled);
            }
            if let Some(metadata) = update.metadata {
                active.metadata = Set(metadata);
            }
            if let Some(banned) = update.banned {
                active.banned = Set(banned);
                if !banned {
                    active.ban_reason = Set(None);
                    active.ban_expires = Set(None);
                }
            }
            if update.banned != Some(false) {
                if let Some(ban_reason) = update.ban_reason {
                    active.ban_reason = Set(Some(ban_reason));
                }
                if let Some(ban_expires) = update.ban_expires {
                    active.ban_expires = Set(ban_expires);
                }
            }
            active.updated_at = Set(now);
        }
    }
}

mod session {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub expires_at: DateTimeUtc,
        pub token: String,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
        pub ip_address: Option<String>,
        pub user_agent: Option<String>,
        pub user_id: i32,
        pub impersonated_by: Option<String>,
        #[sea_orm(column_name = "active_event_id")]
        pub active_organization_id: Option<String>,
        pub active_team_id: Option<String>,
        pub active: bool,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthSession for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        fn token(&self) -> &str {
            &self.token
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
        fn ip_address(&self) -> Option<&str> {
            self.ip_address.as_deref()
        }
        fn user_agent(&self) -> Option<&str> {
            self.user_agent.as_deref()
        }
        fn user_id(&self) -> Cow<'_, str> {
            Cow::Owned(self.user_id.to_string())
        }
        fn impersonated_by(&self) -> Option<&str> {
            self.impersonated_by.as_deref()
        }
        fn active_organization_id(&self) -> Option<&str> {
            self.active_organization_id.as_deref()
        }
        fn active_team_id(&self) -> Option<&str> {
            self.active_team_id.as_deref()
        }
        fn active(&self) -> bool {
            self.active
        }
    }

    impl SeaOrmSessionModel for Model {
        type Id = i32;
        type UserId = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn token_column() -> Self::Column {
            Column::Token
        }
        fn user_id_column() -> Self::Column {
            Column::UserId
        }
        fn active_column() -> Self::Column {
            Column::Active
        }
        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_error| AuthError::bad_request("Invalid session id"))
        }
        fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId> {
            user_id
                .parse()
                .map_err(|_error| AuthError::bad_request("Invalid session user id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            token: String,
            create_session: CreateSession,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            let user_id = create_session
                .user_id
                .parse()
                .expect("session user ids come from validated auth user identifiers");
            ActiveModel {
                id: id.map_or(NotSet, Set),
                expires_at: Set(create_session.expires_at),
                token: Set(token),
                created_at: Set(now),
                updated_at: Set(now),
                ip_address: Set(create_session.ip_address),
                user_agent: Set(create_session.user_agent),
                user_id: Set(user_id),
                impersonated_by: Set(create_session.impersonated_by),
                active_organization_id: Set(create_session.active_organization_id),
                active_team_id: Set(create_session.active_team_id),
                active: Set(true),
            }
        }
        fn set_expires_at(active: &mut Self::ActiveModel, expires_at: DateTime<Utc>) {
            active.expires_at = Set(expires_at);
        }
        fn set_updated_at(active: &mut Self::ActiveModel, updated_at: DateTime<Utc>) {
            active.updated_at = Set(updated_at);
        }
        fn set_active_organization_id(
            active: &mut Self::ActiveModel,
            organization_id: Option<String>,
        ) {
            active.active_organization_id = Set(organization_id);
        }
    }
}

mod account {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "accounts")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub account_id: String,
        pub provider_id: String,
        pub user_id: i32,
        pub access_token: Option<String>,
        pub refresh_token: Option<String>,
        pub id_token: Option<String>,
        pub access_token_expires_at: Option<DateTimeUtc>,
        pub refresh_token_expires_at: Option<DateTimeUtc>,
        pub scope: Option<String>,
        pub password: Option<String>,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthAccount for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn account_id(&self) -> &str {
            &self.account_id
        }
        fn provider_id(&self) -> &str {
            &self.provider_id
        }
        fn user_id(&self) -> Cow<'_, str> {
            Cow::Owned(self.user_id.to_string())
        }
        fn access_token(&self) -> Option<&str> {
            self.access_token.as_deref()
        }
        fn refresh_token(&self) -> Option<&str> {
            self.refresh_token.as_deref()
        }
        fn id_token(&self) -> Option<&str> {
            self.id_token.as_deref()
        }
        fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
            self.access_token_expires_at
        }
        fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
            self.refresh_token_expires_at
        }
        fn scope(&self) -> Option<&str> {
            self.scope.as_deref()
        }
        fn password(&self) -> Option<&str> {
            self.password.as_deref()
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    impl SeaOrmAccountModel for Model {
        type Id = i32;
        type UserId = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn provider_id_column() -> Self::Column {
            Column::ProviderId
        }
        fn account_id_column() -> Self::Column {
            Column::AccountId
        }
        fn user_id_column() -> Self::Column {
            Column::UserId
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_error| AuthError::bad_request("Invalid account id"))
        }
        fn parse_user_id(user_id: &str) -> AuthResult<Self::UserId> {
            user_id
                .parse()
                .map_err(|_error| AuthError::bad_request("Invalid account user id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            create_account: CreateAccount,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            let user_id = create_account
                .user_id
                .parse()
                .expect("account user ids come from validated auth user identifiers");
            ActiveModel {
                id: id.map_or(NotSet, Set),
                account_id: Set(create_account.account_id),
                provider_id: Set(create_account.provider_id),
                user_id: Set(user_id),
                access_token: Set(create_account.access_token),
                refresh_token: Set(create_account.refresh_token),
                id_token: Set(create_account.id_token),
                access_token_expires_at: Set(create_account.access_token_expires_at),
                refresh_token_expires_at: Set(create_account.refresh_token_expires_at),
                scope: Set(create_account.scope),
                password: Set(create_account.password),
                created_at: Set(now),
                updated_at: Set(now),
            }
        }
        fn apply_update(active: &mut Self::ActiveModel, update: UpdateAccount, now: DateTime<Utc>) {
            if let Some(access_token) = update.access_token {
                active.access_token = Set(Some(access_token));
            }
            if let Some(refresh_token) = update.refresh_token {
                active.refresh_token = Set(Some(refresh_token));
            }
            if let Some(id_token) = update.id_token {
                active.id_token = Set(Some(id_token));
            }
            if let Some(access_token_expires_at) = update.access_token_expires_at {
                active.access_token_expires_at = Set(Some(access_token_expires_at));
            }
            if let Some(refresh_token_expires_at) = update.refresh_token_expires_at {
                active.refresh_token_expires_at = Set(Some(refresh_token_expires_at));
            }
            if let Some(scope) = update.scope {
                active.scope = Set(Some(scope));
            }
            if let Some(password) = update.password {
                active.password = Set(Some(password));
            }
            active.updated_at = Set(now);
        }
    }
}

mod verification {
    use super::*;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)]
    #[sea_orm(table_name = "verifications")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub identifier: String,
        pub value: String,
        pub expires_at: DateTimeUtc,
        pub created_at: DateTimeUtc,
        pub updated_at: DateTimeUtc,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}

    impl AuthVerification for Model {
        fn id(&self) -> Cow<'_, str> {
            Cow::Owned(self.id.to_string())
        }
        fn identifier(&self) -> &str {
            &self.identifier
        }
        fn value(&self) -> &str {
            &self.value
        }
        fn expires_at(&self) -> DateTime<Utc> {
            self.expires_at
        }
        fn created_at(&self) -> DateTime<Utc> {
            self.created_at
        }
        fn updated_at(&self) -> DateTime<Utc> {
            self.updated_at
        }
    }

    impl SeaOrmVerificationModel for Model {
        type Id = i32;
        type Entity = Entity;
        type ActiveModel = ActiveModel;
        type Column = Column;

        fn id_column() -> Self::Column {
            Column::Id
        }
        fn identifier_column() -> Self::Column {
            Column::Identifier
        }
        fn value_column() -> Self::Column {
            Column::Value
        }
        fn expires_at_column() -> Self::Column {
            Column::ExpiresAt
        }
        fn created_at_column() -> Self::Column {
            Column::CreatedAt
        }
        fn parse_id(id: &str) -> AuthResult<Self::Id> {
            id.parse()
                .map_err(|_error| AuthError::bad_request("Invalid verification id"))
        }
        fn new_active(
            id: Option<Self::Id>,
            verification: CreateVerification,
            now: DateTime<Utc>,
        ) -> Self::ActiveModel {
            ActiveModel {
                id: id.map_or(NotSet, Set),
                identifier: Set(verification.identifier),
                value: Set(verification.value),
                expires_at: Set(verification.expires_at),
                created_at: Set(now),
                updated_at: Set(now),
            }
        }
    }
}

use better_auth::plugins::{
    AccountManagementPlugin, EmailPasswordPlugin, PasswordManagementPlugin, SessionManagementPlugin,
};
use better_auth::prelude::{
    AuthAccount, AuthRequest, AuthSession, AuthUser, AuthVerification, CreateAccount,
    CreateSession, CreateUser, CreateVerification, HttpMethod, UpdateAccount, UpdateUser,
};
use better_auth::{AuthConfig, AuthError, AuthResult, AuthSchema, BetterAuth};
use better_auth_seaorm::sea_orm;
use better_auth_seaorm::sea_orm::entity::prelude::*;
use better_auth_seaorm::sea_orm::{ActiveValue::NotSet, ActiveValue::Set, ConnectionTrait, Schema};
use better_auth_seaorm::{
    Database, DatabaseConnection, SeaOrmAccountModel, SeaOrmSessionModel, SeaOrmStore,
    SeaOrmUserModel, SeaOrmVerificationModel,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use std::borrow::Cow;

#[derive(Debug)]
pub struct LegacySchema;

impl AuthSchema for LegacySchema {
    type User = user::Model;
    type Session = session::Model;
    type Account = account::Model;
    type Verification = verification::Model;
}

fn test_session_cookie(token: &str) -> String {
    format!(
        "better-auth.session_token={}",
        better_auth_core::utils::cookie_utils::sign_cookie_value(
            token,
            "test-secret-key-that-is-at-least-32-characters-long"
        )
    )
}

async fn test_database() -> DatabaseConnection {
    let database = Database::connect("sqlite::memory:")
        .await
        .expect("sqlite test database should connect");
    run_app_migrations(&database)
        .await
        .expect("legacy schema migrations should run");
    database
}

async fn run_app_migrations(database: &DatabaseConnection) -> Result<(), DbErr> {
    let schema = Schema::new(database.get_database_backend());
    for statement in [
        schema
            .create_table_from_entity(user::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(session::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(account::Entity)
            .if_not_exists()
            .to_owned(),
        schema
            .create_table_from_entity(verification::Entity)
            .if_not_exists()
            .to_owned(),
    ] {
        let _ignored_execute = database.execute(&statement).await?;
    }
    Ok(())
}

fn test_config() -> AuthConfig {
    AuthConfig::new("test-secret-key-that-is-at-least-32-characters-long")
        .base_url("http://localhost:3000")
        .password_min_length(8)
}

async fn create_auth() -> BetterAuth<LegacySchema> {
    let config = test_config();
    let store = SeaOrmStore::<LegacySchema>::new(config.clone(), test_database().await);
    BetterAuth::<LegacySchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await
        .expect("legacy auth should build")
}

fn request(method: HttpMethod, path: &str, body: Option<serde_json::Value>) -> AuthRequest {
    let mut req = AuthRequest::new(method, path);
    if let Some(body) = body {
        req.body = Some(body.to_string().into_bytes());
        drop(
            req.headers
                .insert("content-type".to_owned(), "application/json".to_owned()),
        );
    }
    req
}

fn auth_request(method: HttpMethod, path: &str, token: &str) -> AuthRequest {
    let mut req = AuthRequest::new(method, path);
    drop(
        req.headers
            .insert("cookie".to_owned(), test_session_cookie(token)),
    );
    drop(
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned()),
    );
    req
}

async fn seed_legacy_user(database: &DatabaseConnection) -> i32 {
    let now = Utc::now();
    let password_hash = better_auth_core::hash_password(None, "legacy-password")
        .await
        .expect("seed password should hash");
    let user = user::ActiveModel {
        id: NotSet,
        name: Set(Some("Legacy User".to_owned())),
        email: Set(Some("legacy@example.com".to_owned())),
        email_verified: Set(true),
        image: Set(None),
        username: Set(Some("legacy_user".to_owned())),
        display_username: Set(Some("legacy_user".to_owned())),
        two_factor_enabled: Set(false),
        role: Set(Some("user".to_owned())),
        banned: Set(false),
        ban_reason: Set(None),
        ban_expires: Set(None),
        metadata: Set(json!({ "imported": true })),
        created_at: Set(now),
        updated_at: Set(now),
        tenant_id: Set(42),
        locale: Set("fr".to_owned()),
    }
    .insert(database)
    .await
    .expect("legacy user should insert");

    drop(
        account::ActiveModel {
            id: NotSet,
            account_id: Set(user.id.to_string()),
            provider_id: Set("credential".to_owned()),
            user_id: Set(user.id),
            access_token: Set(None),
            refresh_token: Set(None),
            id_token: Set(None),
            access_token_expires_at: Set(None),
            refresh_token_expires_at: Set(None),
            scope: Set(None),
            password: Set(Some(password_hash)),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(database)
        .await
        .expect("legacy credential account should insert"),
    );

    user.id
}

#[cfg(test)]
mod tests {
    use super::*;
    use better_auth_core::{
        field_policy::{FieldConfig, FieldValues},
        utils::json::JsValue,
    };

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates storage and handler errors"
    )]
    async fn declared_typed_session_fields_use_manual_schema_bindings_and_preserve_policies()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = test_database().await;
        let user_id = seed_legacy_user(&database).await.to_string();
        for (name, physical, native) in [
            (
                "activeOrganizationId",
                "active_event_id",
                "organization-native",
            ),
            ("activeTeamId", "active_team_id", "team-native"),
            ("impersonatedBy", "impersonated_by", "admin-native"),
        ] {
            let transformed = format!("stored:{native}");
            for (replacement, expected) in [
                (None, Some(native)),
                (
                    Some(Some(JsValue::String(transformed.clone()))),
                    Some(transformed.as_str()),
                ),
                (Some(None), None),
                (Some(Some(JsValue::Null)), None),
                (Some(Some(JsValue::Number(42.0))), Some("42")),
            ] {
                for hidden in [false, true] {
                    let mut config = test_config();
                    let field = FieldConfig::new(json!({"type":"string"})).read_only();
                    let field = if let Some(replacement) = replacement.clone() {
                        field.transform_adapter_input(move |value| {
                            assert_eq!(value.as_ref().and_then(JsValue::as_str), Some(native));
                            let replacement = replacement.clone();
                            async move { Ok(replacement) }
                        })
                    } else {
                        field
                    };
                    drop(config.session.additional_fields.insert(
                        name.into(),
                        if hidden {
                            field.field_name(physical).hidden()
                        } else {
                            field
                        },
                    ));
                    let auth = BetterAuth::<LegacySchema>::new(config.clone())
                        .store(SeaOrmStore::<LegacySchema>::new(config, database.clone()))
                        .plugin(SessionManagementPlugin::new())
                        .build()
                        .await?;
                    let created = auth
                        .store()
                        .create_session(CreateSession {
                            additional_fields: FieldValues::new(),
                            token: None,
                            user_id: user_id.clone(),
                            expires_at: Utc::now() + chrono::Duration::hours(1),
                            ip_address: None,
                            user_agent: None,
                            active_organization_id: Some("organization-native".into()),
                            active_team_id: Some("team-native".into()),
                            impersonated_by: Some("admin-native".into()),
                        })
                        .await?;
                    let persisted = auth.store().get_session(&created.token).await?.unwrap();
                    for (field_name, expected_native, actual) in [
                        (
                            "activeOrganizationId",
                            "organization-native",
                            persisted.active_organization_id(),
                        ),
                        ("activeTeamId", "team-native", persisted.active_team_id()),
                        (
                            "impersonatedBy",
                            "admin-native",
                            persisted.impersonated_by(),
                        ),
                    ] {
                        let expected_value = if field_name == name {
                            expected
                        } else {
                            Some(expected_native)
                        };
                        assert_eq!(actual, expected_value, "{field_name}");
                    }
                    let response = auth
                        .handle_request(auth_request(
                            HttpMethod::Get,
                            "/api/auth/get-session",
                            &created.token,
                        ))
                        .await?;
                    assert_eq!(response.status, 200);
                    let projection: serde_json::Value = serde_json::from_slice(&response.body)?;
                    assert_eq!(
                        projection["session"].get(name),
                        (!hidden).then(|| json!(expected)).as_ref()
                    );
                    let mut update =
                        auth_request(HttpMethod::Post, "/api/auth/update-session", &created.token);
                    update.body = Some(serde_json::to_vec(&json!({(name): "client-controlled"}))?);
                    drop(
                        update
                            .headers
                            .insert("content-type".into(), "application/json".into()),
                    );
                    let response = auth.handle_request(update).await?;
                    assert_eq!(response.status, 400);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&response.body)?["code"],
                        "FIELD_NOT_ALLOWED"
                    );
                    let unchanged = auth.store().get_session(&created.token).await?.unwrap();
                    assert_eq!(
                        unchanged.active_organization_id,
                        persisted.active_organization_id
                    );
                    assert_eq!(unchanged.active_team_id, persisted.active_team_id);
                    assert_eq!(unchanged.impersonated_by, persisted.impersonated_by);
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn numeric_user_schema_cleans_team_memberships_without_a_bundled_user_foreign_key()
    -> Result<(), Box<dyn std::error::Error>> {
        use better_auth_core::store::{
            MemberStore, OrganizationStore, TeamStore, UserStore, WalletAddressStore,
        };
        use better_auth_core::types::{
            AddTeamMemberResult, CreateMember, CreateOrganization, CreateTeam, CreateWalletAddress,
        };
        let database = test_database().await;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await?;
        let store = SeaOrmStore::<LegacySchema>::new(test_config(), database.clone());
        let user = store
            .create_user(CreateUser::new().with_email("numeric-team@example.com"))
            .await?;
        assert_eq!(user.id, 1);
        let wallet_address = "0x52908400098527886E0F7030069857D2E4169EE7";
        let wallet = store
            .create_wallet_address(CreateWalletAddress::new("0001", wallet_address, 1.0))
            .await?;
        assert_eq!(wallet.user_id, "1");
        let other_user = store
            .create_user(CreateUser::new().with_email("numeric-other@example.com"))
            .await?;
        let other_wallet = store
            .create_wallet_address(CreateWalletAddress::new("2", wallet_address, 100.0))
            .await?;
        assert_eq!(other_user.id, 2);
        let first_org = store
            .create_organization(CreateOrganization::new("Numeric first", "numeric-first"))
            .await?;
        let second_org = store
            .create_organization(CreateOrganization::new("Numeric second", "numeric-second"))
            .await?;
        let first_member = store
            .create_member(CreateMember::new(&first_org.id, "1", "member"))
            .await?;
        drop(
            store
                .create_member(CreateMember::new(&second_org.id, "1", "member"))
                .await?,
        );
        let first = store
            .create_team(CreateTeam {
                name: "First".to_owned(),
                organization_id: first_org.id.clone(),
                updated_at: None,
            })
            .await?;
        let second = store
            .create_team(CreateTeam {
                name: "Second".to_owned(),
                organization_id: second_org.id.clone(),
                updated_at: None,
            })
            .await?;
        assert!(matches!(
            store.add_team_member(&first.id, "1", Some(1)).await?,
            AddTeamMemberResult::Added(_)
        ));
        assert!(matches!(
            store.add_team_member(&second.id, "1", Some(1)).await?,
            AddTeamMemberResult::Added(_)
        ));
        store.delete_member(&first_member.id).await?;
        assert!(store.get_team_member(&first.id, "1").await?.is_none());
        assert!(store.get_team_member(&second.id, "1").await?.is_some());
        assert_eq!(
            store
                .get_team(None, &first.id)
                .await?
                .map(|team| team.member_count),
            Some(0)
        );
        let _ignored_execute_unprepared = database.execute_unprepared("CREATE TRIGGER numeric_wallet_delete_abort BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'numeric wallet deletion veto'); END").await?;
        assert!(store.delete_user("0001").await.is_err());
        assert!(store.get_user_by_id("1").await?.is_some());
        assert_eq!(
            store.get_wallet_address(wallet_address, Some(1.0)).await?,
            Some(wallet)
        );
        assert!(store.get_team_member(&second.id, "1").await?.is_some());
        assert_eq!(
            store
                .get_team(None, &second.id)
                .await?
                .map(|team| team.member_count),
            Some(1)
        );
        let _ignored_execute_unprepared_2 = database
            .execute_unprepared("DROP TRIGGER numeric_wallet_delete_abort")
            .await?;
        store.delete_user("0001").await?;
        assert!(store.get_user_by_id("1").await?.is_none());
        assert!(store.list_user_teams("1").await?.is_empty());
        assert!(store.get_team_member(&second.id, "1").await?.is_none());
        assert_eq!(
            store
                .get_team(None, &second.id)
                .await?
                .map(|team| team.member_count),
            Some(0)
        );
        assert!(
            store
                .get_wallet_address(wallet_address, Some(1.0))
                .await?
                .is_none()
        );
        assert_eq!(
            store.get_wallet_address(wallet_address, None).await?,
            Some(other_wallet)
        );
        assert!(store.get_user_by_id("2").await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn legacy_numeric_schema_signup_flow_uses_numeric_ids_and_defaults() {
        let auth = create_auth().await;

        let signup = request(
            HttpMethod::Post,
            "/sign-up/email",
            Some(json!({
                "email": "new@example.com",
                "password": "Password123!",
                "name": "New User",
            })),
        );
        let response = auth
            .handle_request(signup)
            .await
            .expect("signup should succeed");
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid json");
        let token = body["token"]
            .as_str()
            .expect("token should exist")
            .to_owned();

        let stored_user = auth
            .store()
            .get_user_by_email("new@example.com")
            .await
            .expect("lookup should succeed")
            .expect("user should exist");
        assert!(stored_user.id > 0);
        assert_eq!(stored_user.tenant_id, 1);
        assert_eq!(stored_user.locale, "en");
        assert_eq!(body["user"]["id"], stored_user.id.to_string());

        // Raw numeric pages must use this application's native ID parser and retain
        // its physical custom fields, rather than a bundled string-ID projection.
        let paged = auth
            .store()
            .list_users_by_ids_page(&[format!("00{}", stored_user.id)], 1.0)
            .await
            .expect("numeric alias page should use the custom ID parser");
        assert_eq!(
            serde_json::to_value(paged).expect("page JSON"),
            serde_json::to_value(vec![stored_user.clone()]).expect("stored JSON")
        );
        assert!(matches!(
            auth.store()
                .list_users_by_ids_page(&[format!("{}suffix", stored_user.id)], 1.0,)
                .await,
            Err(AuthError::BadRequest(_))
        ));

        let session_response = auth
            .handle_request(auth_request(HttpMethod::Get, "/get-session", &token))
            .await
            .expect("get-session should succeed");
        assert_eq!(session_response.status, 200);
        let session_body: serde_json::Value =
            serde_json::from_slice(&session_response.body).expect("valid session json");
        assert_eq!(session_body["user"]["id"], stored_user.id.to_string());

        let accounts_response = auth
            .handle_request(auth_request(HttpMethod::Get, "/list-accounts", &token))
            .await
            .expect("list-accounts should succeed");
        assert_eq!(accounts_response.status, 200);
        let accounts_body: serde_json::Value =
            serde_json::from_slice(&accounts_response.body).expect("valid accounts json");
        assert_eq!(accounts_body.as_array().expect("array").len(), 1);
        assert_eq!(accounts_body[0]["userId"], stored_user.id.to_string());
        assert_eq!(accounts_body[0]["providerId"], "credential");
    }

    #[tokio::test]
    async fn legacy_numeric_schema_existing_user_can_sign_in() {
        let database = test_database().await;
        let legacy_user_id = seed_legacy_user(&database).await;
        let config = test_config();
        let store = SeaOrmStore::<LegacySchema>::new(config.clone(), database);
        let auth = BetterAuth::<LegacySchema>::new(config)
            .store(store)
            .plugin(EmailPasswordPlugin::new().enable_signup(true))
            .plugin(SessionManagementPlugin::new())
            .plugin(PasswordManagementPlugin::new())
            .plugin(AccountManagementPlugin::new())
            .build()
            .await
            .expect("legacy auth should build");

        let signin = request(
            HttpMethod::Post,
            "/sign-in/email",
            Some(json!({
                "email": "legacy@example.com",
                "password": "legacy-password",
            })),
        );
        let response = auth
            .handle_request(signin)
            .await
            .expect("signin should succeed");
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid json");
        let token = body["token"]
            .as_str()
            .expect("token should exist")
            .to_owned();
        assert_eq!(body["user"]["id"], legacy_user_id.to_string());

        let session_response = auth
            .handle_request(auth_request(HttpMethod::Get, "/get-session", &token))
            .await
            .expect("get-session should succeed");
        let session_body: serde_json::Value =
            serde_json::from_slice(&session_response.body).expect("valid session json");
        assert_eq!(session_body["user"]["id"], legacy_user_id.to_string());
        assert_eq!(
            session_body["session"]["userId"],
            legacy_user_id.to_string()
        );
    }

    #[tokio::test]
    async fn legacy_numeric_schema_store_verifications_use_public_string_ids() {
        let auth = create_auth().await;

        let verification = auth
            .store()
            .create_verification(CreateVerification {
                identifier: "verify:legacy".to_owned(),
                value: "token-123".to_owned(),
                expires_at: Utc::now() + chrono::Duration::minutes(30),
            })
            .await
            .expect("verification should insert");

        assert!(!verification.id().is_empty());

        let loaded = auth
            .store()
            .get_verification_by_identifier("verify:legacy")
            .await
            .expect("lookup should succeed");
        assert!(loaded.is_some());

        auth.store()
            .delete_verification(&verification.id())
            .await
            .expect("delete should succeed");

        let loaded_2 = auth
            .store()
            .get_verification_by_identifier("verify:legacy")
            .await
            .expect("lookup should succeed");
        assert!(loaded_2.is_none());

        let reservation = auth
            .store()
            .reserve_verification(CreateVerification {
                identifier: "numeric-reservation".to_owned(),
                value: "claim".to_owned(),
                expires_at: Utc::now() + chrono::Duration::minutes(30),
            })
            .await;
        assert!(
            reservation.is_err(),
            "numeric schemas must fail closed without a deterministic reservation binding"
        );
        assert!(
            auth.store()
                .get_latest_verification_by_identifier("numeric-reservation")
                .await
                .expect("raw lookup should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn manual_numeric_session_schema_fails_closed_for_unbound_configured_fields() {
        let mut config = test_config();
        drop(config.session.additional_fields.insert(
            "label".into(),
            better_auth::field_policy::FieldConfig::new(json!({"type":"string"})),
        ));
        let auth = BetterAuth::<LegacySchema>::new(config.clone())
            .store(SeaOrmStore::<LegacySchema>::new(
                config,
                test_database().await,
            ))
            .plugin(EmailPasswordPlugin::new())
            .plugin(SessionManagementPlugin::new())
            .build()
            .await
            .expect("manual schema still builds with default methods");
        let signup = auth.handle_request(request(HttpMethod::Post,"/sign-up/email",Some(json!({"email":"unbound-session@example.com","password":"Password123!","name":"Manual"})))).await.expect("signup succeeds without field bindings");
        assert_eq!(signup.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&signup.body).expect("signup JSON");
        let token = body["token"].as_str().expect("token");
        let before = auth
            .store()
            .get_session(token)
            .await
            .expect("lookup")
            .expect("stored session");
        let mut update = auth_request(HttpMethod::Post, "/update-session", token);
        update.body = Some(br#"{"label":"must-not-save","userId":"foreign"}"#.to_vec());
        drop(
            update
                .headers
                .insert("content-type".into(), "application/json".into()),
        );
        let rejected = auth
            .handle_request(update)
            .await
            .expect("fail-closed response");
        assert_eq!(rejected.status, 500);
        assert_eq!(rejected.body, Vec::<u8>::new());
        let after = auth
            .store()
            .get_session(token)
            .await
            .expect("lookup")
            .expect("session preserved");
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.user_id, before.user_id);
        assert_eq!(after.token, before.token);
    }

    /// Trusted patches distinguish absent expiry from explicit SQL NULL for both
    /// generated string-ID entities and application-owned numeric-ID entities.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn nullable_ban_expiry_patch_preserves_ban_and_other_principals()
    -> Result<(), Box<dyn std::error::Error>> {
        #[expect(
            clippy::too_many_lines,
            reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
        )]
        async fn check<S: AuthSchema>(
            store: SeaOrmStore<S>,
        ) -> Result<(), Box<dyn std::error::Error>>
        where
            S::User: SeaOrmUserModel,
            S::Session: SeaOrmSessionModel,
        {
            use better_auth_core::store::{SessionStore, UserStore};
            use better_auth_core::wire::{SessionView, UserView};
            use sea_orm::Statement;
            let owner = store
                .create_user(CreateUser::new().with_email("ban-owner@patch.fixture.test"))
                .await?;
            let foreign = store
                .create_user(CreateUser::new().with_email("ban-foreign@patch.fixture.test"))
                .await?;
            let foreign_before = serde_json::to_value(UserView::from(&foreign))?;
            let mut sessions = Vec::new();
            for user in [&owner, &foreign] {
                let session = store
                    .create_session(CreateSession {
                        additional_fields: FieldValues::default(),
                        token: None,
                        user_id: user.id().into_owned(),
                        expires_at: Utc::now() + chrono::Duration::days(1),
                        ip_address: None,
                        user_agent: Some("ban-patch-storage-proof".to_owned()),
                        impersonated_by: None,
                        active_organization_id: None,
                        active_team_id: None,
                    })
                    .await?;
                sessions.push((
                    session.token().to_owned(),
                    serde_json::to_value(SessionView::from(&session))?,
                ));
            }
            let expiry: DateTime<Utc> = "2030-01-02T03:04:05.125Z".parse()?;
            let set: UpdateUser = serde_json::from_value(
                json!({"banned":true,"ban_reason":"retained reason","ban_expires":expiry}),
            )?;
            let banned = store.update_user(&owner.id(), set).await?;
            assert_eq!(banned.ban_expires(), Some(expiry));
            let omitted: UpdateUser = serde_json::from_value(json!({"name":"unrelated rename"}))?;
            let encoded_omitted = serde_json::to_value(&omitted)?;
            assert!(encoded_omitted.get("ban_expires").is_none());
            let renamed = store
                .update_user(&owner.id(), serde_json::from_value(encoded_omitted)?)
                .await?;
            assert_eq!(
                renamed.ban_expires(),
                Some(expiry),
                "omitting an expiry must retain the stored date"
            );
            for clear_input in [
                json!({"banned":true,"ban_expires":null}),
                json!({"ban_expires":null}),
            ] {
                let clear: UpdateUser = serde_json::from_value(clear_input)?;
                let encoded_clear = serde_json::to_value(&clear)?;
                assert_eq!(
                    encoded_clear.get("ban_expires"),
                    Some(&serde_json::Value::Null)
                );
                let cleared = store
                    .update_user(&owner.id(), serde_json::from_value(encoded_clear)?)
                    .await?;
                assert_eq!(
                    cleared.ban_expires(),
                    None,
                    "an explicit null expiry must clear the date without unbanning"
                );
                assert!(cleared.banned());
                assert_eq!(cleared.ban_reason(), Some("retained reason"));
                assert_eq!(cleared.name(), Some("unrelated rename"));
                assert_eq!(cleared.email(), owner.email());
                let row = store
                    .connection()
                    .query_one_raw(Statement::from_sql_and_values(
                        store.connection().get_database_backend(),
                        "SELECT ban_expires FROM users WHERE id = ?",
                        vec![owner.id().into_owned().into()],
                    ))
                    .await?
                    .ok_or_else(|| std::io::Error::other("ban owner disappeared"))?;
                assert_eq!(row.try_get::<Option<String>>("", "ban_expires")?, None);
                assert_eq!(
                    serde_json::to_value(UserView::from(
                        &store
                            .get_user_by_id(&foreign.id())
                            .await?
                            .ok_or_else(|| std::io::Error::other("foreign user disappeared"))?
                    ))?,
                    foreign_before
                );
                for (token, before) in &sessions {
                    assert_eq!(
                        serde_json::to_value(SessionView::from(
                            &store
                                .get_session(token)
                                .await?
                                .ok_or_else(|| std::io::Error::other("session disappeared"))?
                        ))?,
                        *before
                    );
                }
                let reset: UpdateUser = serde_json::from_value(json!({"ban_expires":expiry}))?;
                assert_eq!(
                    store.update_user(&owner.id(), reset).await?.ban_expires(),
                    Some(expiry)
                );
            }
            Ok(())
        }
        type Bundled =
            better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
        let bundled = Database::connect("sqlite::memory:").await?;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&bundled)
            .await?;
        check(SeaOrmStore::<Bundled>::new(test_config(), bundled)).await?;
        check(SeaOrmStore::<LegacySchema>::new(
            test_config(),
            test_database().await,
        ))
        .await?;
        Ok(())
    }

    /// Numeric application session IDs and a manual model without active-team support
    /// must update their own columns, then fail closed and roll back unsupported scope.
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "public custom-schema test asserts actual persisted state and propagates setup failures"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn invitation_transaction_uses_manual_numeric_session_columns_and_rolls_back_missing_team_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        use better_auth_core::store::{
            MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore, transaction,
        };
        use better_auth_core::{CreateMember, CreateOrganization, CreateTeam};
        let database = test_database().await;
        better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database)
            .await?;
        let store = SeaOrmStore::<LegacySchema>::new(test_config(), database.clone());
        let owner = store
            .create_user(CreateUser::new().with_email("manual-invitation-owner@example.test"))
            .await?;
        let other = store
            .create_user(CreateUser::new().with_email("manual-invitation-peer@example.test"))
            .await?;
        let org = store
            .create_organization(CreateOrganization::new(
                "Manual scope",
                "manual-invitation-scope",
            ))
            .await?;
        let team = store
            .create_team(CreateTeam {
                name: "Manual team".into(),
                organization_id: org.id.clone(),
                updated_at: None,
            })
            .await?;
        let session = store
            .create_session(CreateSession {
                user_id: owner.id().into_owned(),
                token: None,
                expires_at: Utc::now() + chrono::Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
                additional_fields: FieldValues::default(),
            })
            .await?;
        let peer = store
            .create_session(CreateSession {
                user_id: other.id().into_owned(),
                token: None,
                expires_at: Utc::now() + chrono::Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
                additional_fields: FieldValues::default(),
            })
            .await?;
        let (token, organization_id, user_id) = (
            session.token.clone(),
            org.id.clone(),
            owner.id().into_owned(),
        );
        let value = organization_id.clone();
        let committed = transaction(&store, move |tx| {
            Box::pin(async move {
                let member = tx
                    .create_member(CreateMember {
                        organization_id: value.clone(),
                        user_id,
                        role: "member".into(),
                    })
                    .await?;
                let selected = tx
                    .update_session_active_organization(&token, Some(&organization_id))
                    .await?;
                assert!(selected.id > 0);
                Ok(member)
            })
        })
        .await?;
        assert_eq!(committed.user_id, owner.id().as_ref());
        let before = store
            .get_session(&session.token)
            .await?
            .ok_or("missing manual session")?;
        assert_eq!(before.id, session.id);
        assert_eq!(
            before.active_organization_id.as_deref(),
            Some(org.id.as_str())
        );
        assert_eq!(
            serde_json::to_value(
                store
                    .get_session(&peer.token)
                    .await?
                    .ok_or("missing peer")?
            )?,
            serde_json::to_value(&peer)?
        );
        let (token_2, team_id, user_id_2, organization_id_2) = (
            session.token.clone(),
            team.id.clone(),
            owner.id().into_owned(),
            org.id.clone(),
        );
        let rejected: AuthResult<()> = transaction(&store, move |tx| {
            Box::pin(async move {
                assert!(tx.get_team(&organization_id_2, &team_id).await?.is_some());
                drop(tx.add_team_member(&team_id, &user_id_2, Some(1)).await?);
                drop(
                    tx.update_session_active_team(&token_2, Some(&team_id))
                        .await?,
                );
                Ok(())
            })
        })
        .await;
        assert!(
            matches!(rejected, Err(AuthError::Internal(message)) if message == "the session schema has no active-team field")
        );
        assert!(
            store
                .get_team_member(&team.id, &owner.id())
                .await?
                .is_none()
        );
        assert_eq!(store.list_organization_members(&org.id).await?.len(), 1);
        assert_eq!(
            serde_json::to_value(
                store
                    .get_session(&session.token)
                    .await?
                    .ok_or("missing rolled-back session")?
            )?,
            serde_json::to_value(before)?
        );
        assert_eq!(
            serde_json::to_value(
                store
                    .get_session(&peer.token)
                    .await?
                    .ok_or("missing unchanged peer")?
            )?,
            serde_json::to_value(peer)?
        );
        Ok(())
    }
}
