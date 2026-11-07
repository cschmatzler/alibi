//! # Alibi Core
//!
//! Core abstractions for the Alibi authentication framework.
//! Contains traits, types, configuration, and error handling.

#![cfg_attr(
    test,
    allow(
        unused_results,
        unreachable_pub,
        reason = "test code intentionally discards setup return values and exposes helpers broadly"
    )
)]

extern crate self as alibi;

pub mod adapter_record;
pub mod authenticated_user;
pub mod background_tasks;
pub mod config;
#[doc(hidden)]
pub mod database_sql;
pub mod email;
pub mod endpoint;
pub mod entity;
pub mod error;
pub mod field_policy;
pub mod hooks;
pub mod middleware;
pub mod openapi;
pub mod plugin;
pub mod schema;
pub mod session;
pub mod store;
#[cfg(test)]
pub(crate) mod test_store {
    use crate::utils::LockUnpoisoned;
    // LCOV_EXCL_START
    #[cfg(test)]
    mod factor_extension_contract_tests {
        use super::*;

        #[tokio::test]
        async fn unsupported_factor_security_extensions_fail_closed() {
            let store = MemoryStore::default();
            let now = Utc::now();
            let errors = [
                store
                    .update_two_factor("factor", crate::UpdateTwoFactor::default())
                    .await
                    .unwrap_err(),
                store
                    .increment_two_factor_failure("factor")
                    .await
                    .unwrap_err(),
                store
                    .set_two_factor_lock_if_count_at_least("factor", 0.0, now)
                    .await
                    .unwrap_err(),
                store
                    .clear_expired_two_factor_lock("factor", now)
                    .await
                    .unwrap_err(),
                store.reset_two_factor_failures("factor").await.unwrap_err(),
                store
                    .compare_and_swap_two_factor_backup_codes("factor", "old", "new")
                    .await
                    .unwrap_err(),
            ];
            for error in errors {
                assert!(matches!(error, AuthError::NotImplemented(_)));
                assert_eq!(error.status_code(), 501);
            }
        }
    }

    #[cfg(test)]
    mod session_contract_tests {
        use super::*;

        #[tokio::test]
        #[expect(
            clippy::panic_in_result_fn,
            reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
        )]
        async fn default_batch_lookup_deduplicates_keys_and_preserves_expired_sessions()
        -> AuthResult<()> {
            let store = MemoryStore::new(test_config());
            let user = store
                .create_user(CreateUser::new().with_email("default-batch@example.com"))
                .await?;
            let now = Utc::now();
            for (token, expiry) in [
                (Some("z-token"), now + chrono::Duration::hours(1)),
                (Some("a-token"), now - chrono::Duration::minutes(1)),
                (None, now + chrono::Duration::hours(1)),
            ] {
                let row = store
                    .create_session(CreateSession {
                        additional_fields: crate::field_policy::FieldValues::default(),
                        token: token.map(str::to_owned),
                        user_id: user.id.clone(),
                        expires_at: expiry,
                        ip_address: None,
                        user_agent: None,
                        impersonated_by: None,
                        active_organization_id: None,
                        active_team_id: None,
                    })
                    .await?;
                if token.is_none() {
                    assert_eq!(row.token.len(), 32);
                    assert!(row.token.bytes().all(|byte| byte.is_ascii_alphanumeric()));
                }
            }
            let result = store
                .get_sessions_by_tokens(&[
                    "z-token".to_owned(),
                    "a-token".to_owned(),
                    "missing".to_owned(),
                    "z-token".to_owned(),
                ])
                .await?;
            assert_eq!(
                result
                    .iter()
                    .map(|row| row.token.as_str())
                    .collect::<Vec<_>>(),
                vec!["a-token", "z-token"]
            );
            assert!(result.first().is_some_and(|row| row.expires_at < now));
            let duplicate = store
                .create_session(CreateSession {
                    additional_fields: crate::field_policy::FieldValues::default(),
                    token: Some("a-token".to_owned()),
                    user_id: user.id,
                    expires_at: now + chrono::Duration::hours(1),
                    ip_address: None,
                    user_agent: None,
                    impersonated_by: None,
                    active_organization_id: None,
                    active_team_id: None,
                })
                .await;
            assert!(duplicate.is_err());
            assert!(
                store
                    .get_session("a-token")
                    .await?
                    .is_some_and(|row| row.expires_at < now)
            );
            Ok(())
        }
    }

    use crate::config::AuthConfig;
    use crate::error::{AuthError, AuthResult};
    use crate::schema::AuthSchema;
    use crate::store::{
        AccountStore, ApiKeyStore, AuthStore, AuthTransaction, ConsumeApiKeyResult,
        DeviceCodeStore, InvitationStore, ListOrganizationMembersParams, MemberStore,
        OrganizationStore, PasskeyStore, SessionStore, TransactionStore, TwoFactorStore, UserStore,
        VerificationStore,
    };
    use crate::types::{
        ApiKey, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation, CreateMember,
        CreateOrganization, CreatePasskey, CreateSession, CreateTwoFactor, CreateUser,
        CreateVerification, DeviceCode, Invitation, InvitationStatus, ListUsersParams, Member,
        Organization, Passkey, TwoFactor, UpdateAccount, UpdateApiKey, UpdateDeviceCode,
        UpdateOrganization, UpdatePasskeyAuthentication, UpdateUser,
    };
    use crate::wire::{AccountView, SessionView, UserView, VerificationView};
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    pub struct BundledSchema;

    impl AuthSchema for BundledSchema {
        type User = UserView;
        type Session = SessionView;
        type Account = AccountView;
        type Verification = VerificationView;
    }

    #[derive(Default, Clone)]
    struct State {
        users: Vec<(crate::store::memory_user_id::MemoryUserId, UserView)>,
        sessions: HashMap<String, SessionView>,
        accounts: HashMap<String, AccountView>,
        verifications: HashMap<String, VerificationView>,
        device_codes: HashMap<String, DeviceCode>,
    }

    #[derive(Default)]
    pub struct MemoryStore {
        state: Mutex<State>,
    }

    impl crate::store::TeamStore for MemoryStore {}

    impl crate::store::OrganizationRoleStore for MemoryStore {}

    impl crate::store::WalletAddressStore for MemoryStore {}

    impl crate::store::JwkStore for MemoryStore {}

    impl MemoryStore {
        #[must_use]
        pub(crate) fn new(_config: Arc<AuthConfig>) -> Self {
            Self::default()
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, State> {
            self.state.lock_unpoisoned()
        }
    }

    struct MemoryTransaction {
        store: MemoryStore,
    }

    #[async_trait]
    impl AuthTransaction<BundledSchema> for MemoryTransaction {
        async fn get_user_by_email(
            &self,
            email: &crate::utils::json::JsString,
        ) -> AuthResult<Option<UserView>> {
            self.store.get_user_by_email(email).await
        }

        async fn get_account(
            &self,
            provider: &str,
            id: &crate::utils::json::JsString,
        ) -> AuthResult<Option<AccountView>> {
            self.store.get_account(provider, id).await
        }

        async fn update_user_prepared(
            &self,
            id: &str,
            update: crate::store::PreparedUserUpdate,
        ) -> AuthResult<UserView> {
            self.store.update_user_prepared(id, update).await
        }
        async fn update_user(&self, id: &str, update: crate::UpdateUser) -> AuthResult<UserView> {
            self.update_user_prepared(id, crate::store::PreparedUserUpdate::from_typed(&update))
                .await
        }

        async fn native_user_output_for(
            &self,
            user: &crate::UserView,
        ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
            Ok(user.native_user_fields())
        }

        async fn create_verification_record(
            &self,
            data: crate::verification::VerificationCreation,
            publication: crate::verification::VerificationPublication,
        ) -> AuthResult<Option<crate::verification::VerificationSnapshot>> {
            self.store
                .create_verification_record(data, publication)
                .await
        }
        async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
            self.store.get_user_by_id(id).await
        }
        async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
            self.store.create_passkey(data).await
        }
        async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<UserView> {
            create_user.email = create_user.email.map(|email| email.to_lowercase());
            self.create_user_prepared(crate::user_validation::PreparedUserCreation::from_data(
                create_user,
            ))
            .await
        }

        async fn create_user_prepared(
            &self,
            prepared: crate::user_validation::PreparedUserCreation,
        ) -> AuthResult<UserView> {
            self.store.create_user_prepared(prepared).await
        }

        async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
            self.store.create_account(create_account).await
        }

        async fn create_session(&self, create_session: CreateSession) -> AuthResult<SessionView> {
            self.store.create_session(create_session).await
        }
        async fn create_verification(
            &self,
            verification: CreateVerification,
        ) -> AuthResult<VerificationView> {
            self.store.create_verification(verification).await
        }
        async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
            self.store.delete_user_sessions(user_id).await
        }
        async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
            self.store.update_account(id, update).await
        }
        async fn consume_verification_snapshot(
            &self,
            identifier: &str,
        ) -> AuthResult<Option<VerificationView>> {
            self.store.consume_verification_snapshot(identifier).await
        }
    }

    #[async_trait]
    impl UserStore<BundledSchema> for MemoryStore {
        async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<UserView> {
            create_user.email = create_user.email.map(|email| email.to_lowercase());
            self.create_user_prepared(crate::user_validation::PreparedUserCreation::from_data(
                create_user,
            ))
            .await
        }

        async fn create_user_prepared(
            &self,
            prepared: crate::user_validation::PreparedUserCreation,
        ) -> AuthResult<UserView> {
            let (create_user, defaults) = prepared.into_parts();
            let mut create_user = defaults.apply(create_user)?;
            create_user
                .additional_fields
                .apply_adapter_transforms_async()
                .await?;
            let now = Utc::now();
            let supplied_id = crate::store::memory_user_id::MemoryUserId::supplied(
                create_user.adapter_native_fields.get("id"),
            )?;
            let (physical_id, id) = supplied_id.unwrap_or_else(|| {
                let id = create_user
                    .id
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                (crate::store::memory_user_id::MemoryUserId::string(&id), id)
            });
            let username = create_user.username;
            let native_fields = create_user.adapter_native_fields;
            let mut user = UserView {
                omitted_fields: std::collections::BTreeSet::default(),
                id: id.clone(),
                name: create_user.name,
                email: create_user.email,
                email_verified: create_user.email_verified.unwrap_or(false),
                image: create_user.image,
                created_at: create_user.created_at.unwrap_or(now),
                updated_at: create_user.updated_at.unwrap_or(now),
                username,
                display_username: create_user.display_username,
                two_factor_enabled: create_user.two_factor_enabled,
                role: create_user.role,
                banned: create_user.banned,
                ban_reason: None,
                ban_expires: None,
                metadata: create_user
                    .metadata
                    .unwrap_or_else(|| serde_json::json!({}))
                    .into(),
                is_anonymous: create_user.is_anonymous,
                phone_number: create_user.phone_number,
                phone_number_verified: create_user.phone_number_verified,
                last_login_method: create_user.last_login_method,
                extension_fields: create_user
                    .additional_fields
                    .into_iter()
                    .map(|(key, value)| (key.into(), value))
                    .collect(),
            };
            user.retain_native_user_fields(native_fields);
            self.lock().users.push((physical_id, user.clone()));
            Ok(user)
        }

        async fn native_user_output_for(
            &self,
            user: &UserView,
        ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
            Ok(user.native_user_fields())
        }

        async fn native_user_output(
            &self,
            id: &str,
        ) -> AuthResult<std::collections::BTreeMap<String, crate::utils::json::JsValue>> {
            Ok(self
                .get_user_by_id(id)
                .await?
                .map_or_else(Default::default, |user| user.native_user_fields()))
        }

        async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
            Ok(self
                .lock()
                .users
                .iter()
                .find(|(key, _)| *key == crate::store::memory_user_id::MemoryUserId::string(id))
                .map(|(_, user)| user.clone()))
        }

        async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
            let state = self.lock();
            Ok(state
                .users
                .iter()
                .filter(|(key, _)| {
                    ids.iter()
                        .any(|id| *key == crate::store::memory_user_id::MemoryUserId::string(id))
                })
                .map(|(_, user)| user.clone())
                .collect())
        }

        async fn get_user_by_email(
            &self,
            email: &crate::utils::json::JsString,
        ) -> AuthResult<Option<UserView>> {
            let normalized = email.to_lowercase();
            let Some(normalized) = normalized.as_str() else {
                return Ok(None);
            };
            Ok(self
                .lock()
                .users
                .iter()
                .map(|(_, user)| user)
                .find(|user| user.email.as_deref() == Some(normalized))
                .cloned())
        }

        async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
            let normalized = username.to_lowercase();
            Ok(self
                .lock()
                .users
                .iter()
                .map(|(_, user)| user)
                .find(|user| user.username.as_deref() == Some(&normalized))
                .cloned())
        }

        async fn get_user_by_username_value(
            &self,
            username: &crate::utils::json::JsValue,
        ) -> AuthResult<Option<UserView>> {
            Ok(self
                .lock()
                .users
                .iter()
                .map(|(_, user)| user)
                .find(|user| {
                    user.extension_fields
                        .get("username")
                        .cloned()
                        .or_else(|| {
                            user.username
                                .clone()
                                .map(|value| crate::utils::json::JsValue::String(value.into()))
                        })
                        .map(crate::utils::json::JsValue::from)
                        .as_ref()
                        == Some(username)
                })
                .cloned())
        }

        async fn get_user_by_phone_number(
            &self,
            phone_number: &str,
        ) -> AuthResult<Option<UserView>> {
            Ok(self
                .lock()
                .users
                .iter()
                .map(|(_, user)| user)
                .find(|user| user.phone_number.as_deref() == Some(phone_number))
                .cloned())
        }

        async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
            self.update_user_prepared(id, crate::store::PreparedUserUpdate::from_typed(&update))
                .await
        }

        async fn update_user_prepared(
            &self,
            id: &str,
            mut update: crate::store::PreparedUserUpdate,
        ) -> AuthResult<UserView> {
            update.apply_adapter_transforms().await?;
            let mut state = self.lock();
            let data = update
                .data
                .iter()
                .filter(|(key, _)| key.as_str().is_some_and(|key| update.declares(key)))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            crate::store::memory_user_id::MemoryUserId::update_rows(&mut state.users, id, data)
        }

        async fn delete_user(&self, id: &str) -> AuthResult<()> {
            self.lock()
                .users
                .retain(|(key, _)| *key != crate::store::memory_user_id::MemoryUserId::string(id));
            Ok(())
        }

        async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
            let state = self.lock();
            crate::store::memory_user_id::MemoryUserId::apply_list(
                state.users.iter().map(|(id, user)| (id, user)),
                &_params,
            )
        }
    }

    #[async_trait]
    impl SessionStore<BundledSchema> for MemoryStore {
        async fn update_session_fields(
            &self,
            token: &str,
            mut fields: crate::field_policy::FieldValues,
        ) -> AuthResult<Option<SessionView>> {
            let mut data = self.lock();
            let Some(session) = data.sessions.get_mut(token) else {
                return Ok(None);
            };
            fields.apply_adapter_transforms()?;
            for (name, value) in fields {
                _ = session.extension_fields.insert(name.into(), value);
            }
            session.updated_at = Utc::now();
            let locked_result = Ok(Some(session.clone()));
            drop(data);
            locked_result
        }
        async fn create_session(
            &self,
            mut create_session: CreateSession,
        ) -> AuthResult<SessionView> {
            for (name, value) in [
                (
                    "activeOrganizationId",
                    create_session.active_organization_id.as_ref(),
                ),
                ("activeTeamId", create_session.active_team_id.as_ref()),
                ("impersonatedBy", create_session.impersonated_by.as_ref()),
            ] {
                if let Some(value) = value {
                    create_session.additional_fields.preserve_creation_value(
                        name,
                        crate::utils::json::JsValue::String(value.clone().into()),
                    );
                }
            }
            create_session
                .additional_fields
                .apply_adapter_transforms()?;
            for (name, destination) in [
                (
                    "activeOrganizationId",
                    &mut create_session.active_organization_id,
                ),
                ("activeTeamId", &mut create_session.active_team_id),
                ("impersonatedBy", &mut create_session.impersonated_by),
            ] {
                if let Some(value) = create_session.additional_fields.shift_remove(name) {
                    *destination = value.as_str().map(str::to_owned);
                }
            }
            let now = Utc::now();
            let token = create_session
                .token
                .unwrap_or_else(crate::utils::sessions::generate_session_token);
            let session = SessionView {
                omitted_fields: std::collections::BTreeSet::default(),
                id: uuid::Uuid::new_v4().to_string(),
                expires_at: create_session.expires_at,
                token: token.clone(),
                created_at: now,
                updated_at: now,
                ip_address: create_session.ip_address.or_else(|| Some(String::new())),
                user_agent: create_session.user_agent.or_else(|| Some(String::new())),
                user_id: create_session.user_id,
                impersonated_by: create_session.impersonated_by,
                active_organization_id: create_session.active_organization_id,
                active_team_id: create_session.active_team_id,
                extension_fields: create_session
                    .additional_fields
                    .into_iter()
                    .map(|(name, value)| (name.into(), value))
                    .collect(),
            };
            let mut state = self.lock();
            if state.sessions.contains_key(&token) {
                return Err(AuthError::bad_request("Session token already exists"));
            }
            state.sessions.insert(token, session.clone());
            drop(state);

            Ok(session)
        }

        async fn get_session(&self, token: &str) -> AuthResult<Option<SessionView>> {
            Ok(self.lock().sessions.get(token).cloned())
        }

        async fn get_user_sessions(&self, user_id: &str) -> AuthResult<Vec<SessionView>> {
            Ok(self
                .lock()
                .sessions
                .values()
                .filter(|session| session.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn update_session_expiry(
            &self,
            token: &str,
            expires_at: DateTime<Utc>,
        ) -> AuthResult<()> {
            if let Some(session) = self.lock().sessions.get_mut(token) {
                session.expires_at = expires_at;
                session.updated_at = Utc::now();
                Ok(())
            } else {
                Err(AuthError::SessionNotFound)
            }
        }

        async fn refresh_session(
            &self,
            token: &str,
            expires_at: DateTime<Utc>,
        ) -> AuthResult<Option<SessionView>> {
            let mut state = self.lock();
            let Some(session) = state.sessions.get_mut(token) else {
                return Ok(None);
            };
            session.expires_at = expires_at;
            session.updated_at = Utc::now();
            let locked_result = Ok(Some(session.clone()));
            drop(state);
            locked_result
        }
        async fn delete_session(&self, token: &str) -> AuthResult<()> {
            self.lock().sessions.remove(token);
            Ok(())
        }

        async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
            self.lock()
                .sessions
                .retain(|_, session| session.user_id != user_id);
            Ok(())
        }

        async fn delete_expired_sessions(&self) -> AuthResult<usize> {
            let now = Utc::now();
            let mut state = self.lock();
            let before = state.sessions.len();
            state.sessions.retain(|_, session| session.expires_at > now);
            Ok(before - state.sessions.len())
        }

        async fn update_session_active_organization(
            &self,
            token: &str,
            organization_id: Option<&str>,
        ) -> AuthResult<SessionView> {
            let mut state = self.lock();
            let session = state
                .sessions
                .get_mut(token)
                .ok_or(AuthError::SessionNotFound)?;
            session.active_organization_id = organization_id.map(str::to_owned);
            session.updated_at = Utc::now();
            let locked_result = Ok(session.clone());
            drop(state);
            locked_result
        }

        async fn update_session_active_team(
            &self,
            token: &str,
            team_id: Option<&str>,
        ) -> AuthResult<SessionView> {
            let mut state = self.lock();
            let session = state
                .sessions
                .get_mut(token)
                .ok_or(AuthError::SessionNotFound)?;
            session.active_team_id = team_id.map(str::to_owned);
            session.updated_at = Utc::now();
            let locked_result = Ok(session.clone());
            drop(state);
            locked_result
        }
    }

    #[async_trait]
    impl AccountStore<BundledSchema> for MemoryStore {
        async fn create_account(&self, create_account: CreateAccount) -> AuthResult<AccountView> {
            let now = Utc::now();
            let account = AccountView {
                id: uuid::Uuid::new_v4().to_string(),
                account_id: create_account.account_id,
                provider_id: create_account.provider_id,
                user_id: create_account.user_id,
                access_token: create_account.access_token,
                refresh_token: create_account.refresh_token,
                id_token: create_account.id_token,
                access_token_expires_at: create_account.access_token_expires_at,
                refresh_token_expires_at: create_account.refresh_token_expires_at,
                scope: create_account.scope,
                password: create_account.password,
                created_at: now,
                updated_at: now,
            };
            self.lock()
                .accounts
                .insert(account.id.clone(), account.clone());
            Ok(account)
        }

        async fn get_account(
            &self,
            provider: &str,
            provider_account_id: &crate::utils::json::JsString,
        ) -> AuthResult<Option<AccountView>> {
            let storage = self.lock();
            let mut matches = storage.accounts.values().filter(|account| {
                account.provider_id == provider && *provider_account_id == account.account_id
            });
            let first = matches.next().cloned();
            if matches.next().is_some() {
                return Err(AuthError::Database(
                    crate::DatabaseError::AmbiguousAccount {
                        provider: provider.to_owned(),
                    },
                ));
            }
            Ok(first)
        }

        async fn get_user_accounts(&self, user_id: &str) -> AuthResult<Vec<AccountView>> {
            Ok(self
                .lock()
                .accounts
                .values()
                .filter(|account| account.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
            let mut state = self.lock();
            let account = state
                .accounts
                .get_mut(id)
                .ok_or_else(|| AuthError::not_found("Account not found"))?;
            if update.provider_token_nulls[0] {
                account.access_token = None;
            }
            if update.provider_token_nulls[1] {
                account.refresh_token = None;
            }
            if update.provider_token_nulls[2] {
                account.id_token = None;
            }
            if let Some(access_token) = update.access_token {
                account.access_token = Some(access_token);
            }
            if let Some(refresh_token) = update.refresh_token {
                account.refresh_token = Some(refresh_token);
            }
            if let Some(id_token) = update.id_token {
                account.id_token = Some(id_token);
            }
            if let Some(access_token_expires_at) = update.access_token_expires_at {
                account.access_token_expires_at = Some(access_token_expires_at);
            }
            if let Some(refresh_token_expires_at) = update.refresh_token_expires_at {
                account.refresh_token_expires_at = Some(refresh_token_expires_at);
            }
            if let Some(scope) = update.scope {
                account.scope = Some(scope);
            }
            if let Some(password) = update.password {
                account.password = Some(password);
            }
            account.updated_at = Utc::now();
            let locked_result = Ok(account.clone());
            drop(state);
            locked_result
        }

        async fn delete_account(&self, id: &str) -> AuthResult<()> {
            self.lock().accounts.remove(id);
            Ok(())
        }
    }

    #[async_trait]
    impl VerificationStore<BundledSchema> for MemoryStore {
        async fn create_verification_record(
            &self,
            data: crate::verification::VerificationCreation,
            publication: crate::verification::VerificationPublication,
        ) -> AuthResult<Option<crate::verification::VerificationSnapshot>> {
            let snapshot = if publication.store_in_database {
                let model = VerificationView {
                    id: data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                    identifier: data.identifier,
                    value: data.value,
                    expires_at: data.expires_at,
                    created_at: data.created_at,
                    updated_at: data.updated_at,
                };
                let mut state = self.lock();
                if state.verifications.contains_key(&model.id) {
                    return Err(AuthError::internal("duplicate verification primary ID"));
                }
                state.verifications.insert(model.id.clone(), model.clone());
                drop(state);
                crate::verification::VerificationSnapshot::from_model(&model)
            } else {
                data.snapshot()
            };
            publication.publish(&snapshot).await?;
            Ok(Some(snapshot))
        }

        async fn consume_verification_snapshot(
            &self,
            identifier: &str,
        ) -> AuthResult<Option<VerificationView>> {
            let mut state = self.lock();
            let found = state
                .verifications
                .values()
                .filter(|verification| verification.identifier == identifier)
                .max_by_key(|verification| verification.created_at)
                .cloned();
            state
                .verifications
                .retain(|_, sibling| sibling.identifier != identifier);
            drop(state);
            Ok(found)
        }

        async fn update_verification_by_identifier(
            &self,
            identifier: &str,
            data: crate::UpdateVerification,
        ) -> AuthResult<Option<crate::verification::VerificationSnapshot>> {
            let mut state = self.lock();
            let mut found = None;
            for model in state.verifications.values_mut() {
                if model.identifier == identifier {
                    model.updated_at = Utc::now();
                    if let Some(value) = &data.value {
                        model.value.clone_from(value);
                    }
                    if let Some(expiry) = data.expires_at {
                        model.expires_at = expiry;
                    }
                    if found.is_none() {
                        found = Some(crate::verification::VerificationSnapshot::from_model(model));
                    }
                }
            }
            drop(state);
            Ok(found)
        }

        async fn reserve_verification_record(
            &self,
            logical_identifier: &str,
            data: CreateVerification,
        ) -> AuthResult<Option<VerificationView>> {
            let (id, _) = crate::store::verification_reservation_key(logical_identifier);
            let mut state = self.lock();
            let std::collections::hash_map::Entry::Vacant(entry) =
                state.verifications.entry(id.clone())
            else {
                return Ok(None);
            };
            let now = Utc::now();
            let model = VerificationView {
                id,
                identifier: data.identifier,
                value: data.value,
                expires_at: data.expires_at,
                created_at: now,
                updated_at: now,
            };
            entry.insert(model.clone());
            drop(state);
            Ok(Some(model))
        }

        async fn create_verification(
            &self,
            verification: CreateVerification,
        ) -> AuthResult<VerificationView> {
            let now = Utc::now();
            let verification = VerificationView {
                id: uuid::Uuid::new_v4().to_string(),
                identifier: verification.identifier,
                value: verification.value,
                expires_at: verification.expires_at,
                created_at: now,
                updated_at: now,
            };
            self.lock()
                .verifications
                .insert(verification.id.clone(), verification.clone());
            Ok(verification)
        }

        async fn get_verification(
            &self,
            identifier: &str,
            value: &str,
        ) -> AuthResult<Option<VerificationView>> {
            Ok(self
                .lock()
                .verifications
                .values()
                .filter(|verification| {
                    verification.identifier == identifier
                        && verification.value == value
                        && verification.expires_at >= Utc::now()
                })
                .max_by_key(|verification| verification.created_at)
                .cloned())
        }

        async fn get_verification_by_value(
            &self,
            value: &str,
        ) -> AuthResult<Option<VerificationView>> {
            Ok(self
                .lock()
                .verifications
                .values()
                .filter(|verification| {
                    verification.value == value && verification.expires_at >= Utc::now()
                })
                .max_by_key(|verification| verification.created_at)
                .cloned())
        }

        async fn get_verification_by_identifier(
            &self,
            identifier: &str,
        ) -> AuthResult<Option<VerificationView>> {
            Ok(self
                .lock()
                .verifications
                .values()
                .filter(|verification| {
                    verification.identifier == identifier && verification.expires_at >= Utc::now()
                })
                .max_by_key(|verification| verification.created_at)
                .cloned())
        }

        async fn consume_verification(
            &self,
            identifier: &str,
            value: &str,
        ) -> AuthResult<Option<VerificationView>> {
            let mut state = self.lock();
            let found = state
                .verifications
                .values()
                .filter(|verification| verification.identifier == identifier)
                .max_by_key(|verification| verification.created_at)
                .cloned();
            if let Some(verification) = &found {
                if verification.value != value {
                    return Ok(None);
                }
                state
                    .verifications
                    .retain(|_, sibling| sibling.identifier != identifier);
            }
            drop(state);

            Ok(found.filter(|verification| verification.expires_at >= Utc::now()))
        }

        async fn get_latest_verification_by_identifier(
            &self,
            identifier: &str,
        ) -> AuthResult<Option<VerificationView>> {
            Ok(self
                .lock()
                .verifications
                .values()
                .filter(|verification| verification.identifier == identifier)
                .max_by_key(|verification| verification.created_at)
                .cloned())
        }

        async fn consume_verification_by_identifier(
            &self,
            identifier: &str,
        ) -> AuthResult<Option<VerificationView>> {
            let mut state = self.lock();
            let found = state
                .verifications
                .values()
                .filter(|verification| verification.identifier == identifier)
                .max_by_key(|verification| verification.created_at)
                .cloned();
            state
                .verifications
                .retain(|_, sibling| sibling.identifier != identifier);
            drop(state);

            Ok(found.filter(|verification| verification.expires_at >= Utc::now()))
        }

        async fn delete_verifications_by_identifier(&self, identifier: &str) -> AuthResult<()> {
            self.lock()
                .verifications
                .retain(|_, verification| verification.identifier != identifier);
            Ok(())
        }

        async fn compare_and_swap_verification(
            &self,
            id: &str,
            expected_value: &str,
            value: &str,
            expires_at: DateTime<Utc>,
        ) -> AuthResult<bool> {
            let mut state = self.lock();
            let Some(verification) = state.verifications.get_mut(id) else {
                return Ok(false);
            };
            if verification.value != expected_value {
                return Ok(false);
            }
            verification.value = value.to_owned();
            verification.expires_at = expires_at;
            verification.updated_at = Utc::now();
            drop(state);

            Ok(true)
        }

        async fn reserve_verification(&self, verification: CreateVerification) -> AuthResult<bool> {
            let (id, _) = crate::store::verification_reservation_key(&verification.identifier);
            let mut state = self.lock();
            let std::collections::hash_map::Entry::Vacant(entry) =
                state.verifications.entry(id.clone())
            else {
                return Ok(false);
            };

            let now = Utc::now();
            _ = entry.insert(VerificationView {
                id,
                identifier: verification.identifier,
                value: verification.value,
                expires_at: verification.expires_at,
                created_at: now,
                updated_at: now,
            });
            drop(state);
            Ok(true)
        }

        async fn delete_verification(&self, id: &str) -> AuthResult<()> {
            self.lock().verifications.remove(id);
            Ok(())
        }

        async fn delete_expired_verifications(&self) -> AuthResult<usize> {
            let now = Utc::now();
            let mut state = self.lock();
            let before = state.verifications.len();
            state.verifications.retain(|_, verification| {
                verification.expires_at.timestamp_millis() >= now.timestamp_millis()
            });
            Ok(before - state.verifications.len())
        }
    }

    #[async_trait]
    impl OrganizationStore for MemoryStore {
        async fn create_organization(&self, _org: CreateOrganization) -> AuthResult<Organization> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn get_organization_by_id(&self, _id: &str) -> AuthResult<Option<Organization>> {
            Ok(None)
        }
        async fn get_organization_by_slug(&self, _slug: &str) -> AuthResult<Option<Organization>> {
            Ok(None)
        }
        async fn list_organizations_by_ids(
            &self,
            _ids: &[String],
        ) -> AuthResult<Vec<Organization>> {
            Ok(Vec::new())
        }
        async fn update_organization(
            &self,
            _id: &str,
            _update: UpdateOrganization,
        ) -> AuthResult<Organization> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn update_organization_if_present(
            &self,
            _id: &str,
            _update: UpdateOrganization,
        ) -> AuthResult<Option<Organization>> {
            Err(AuthError::NotImplemented(
                "Optional organization updates are not supported by this test store".into(),
            ))
        }
        async fn delete_organization(&self, _id: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn list_user_organizations(&self, _user_id: &str) -> AuthResult<Vec<Organization>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl MemberStore for MemoryStore {
        async fn create_member(&self, _member: CreateMember) -> AuthResult<Member> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn get_member(
            &self,
            _organization_id: &str,
            _user_id: &str,
        ) -> AuthResult<Option<Member>> {
            Ok(None)
        }
        async fn get_member_by_id(&self, _id: &str) -> AuthResult<Option<Member>> {
            Ok(None)
        }
        async fn update_member_role(&self, _member_id: &str, _role: &str) -> AuthResult<Member> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn update_member_role_if_present(
            &self,
            _member_id: &str,
            _role: &str,
        ) -> AuthResult<Option<Member>> {
            Err(AuthError::NotImplemented(
                "Optional member role updates are not supported by this test store".into(),
            ))
        }
        async fn delete_member(&self, _member_id: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn delete_member_with_context(
            &self,
            _member_id: &str,
            _organization_id: &str,
            _user_id: &str,
            _remove_team_members: bool,
        ) -> AuthResult<()> {
            Err(AuthError::NotImplemented(
                "Contextual member deletion is not supported by this test store".into(),
            ))
        }
        async fn list_organization_members_page(
            &self,
            _organization_id: &str,
            _limit: usize,
        ) -> AuthResult<Vec<Member>> {
            Err(AuthError::NotImplemented(
                "Unsorted member pages are not supported by this test store".into(),
            ))
        }
        async fn list_organization_members(&self, _org_id: &str) -> AuthResult<Vec<Member>> {
            Ok(Vec::new())
        }
        async fn query_organization_members(
            &self,
            _params: &ListOrganizationMembersParams,
        ) -> AuthResult<(Vec<Member>, usize)> {
            Ok((Vec::new(), 0))
        }
        async fn count_organization_members(&self, _org_id: &str) -> AuthResult<i64> {
            Ok(0)
        }
        async fn count_organization_owners(&self, _org_id: &str) -> AuthResult<i64> {
            Ok(0)
        }
    }

    #[async_trait]
    impl InvitationStore for MemoryStore {
        async fn create_invitation(&self, _invitation: CreateInvitation) -> AuthResult<Invitation> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn get_invitation_by_id(&self, _id: &str) -> AuthResult<Option<Invitation>> {
            Ok(None)
        }
        async fn get_pending_invitation(
            &self,
            _org_id: &str,
            _email: &str,
        ) -> AuthResult<Option<Invitation>> {
            Ok(None)
        }
        async fn update_invitation_status(
            &self,
            _id: &str,
            _status: InvitationStatus,
        ) -> AuthResult<Invitation> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn list_organization_invitations(
            &self,
            _org_id: &str,
        ) -> AuthResult<Vec<Invitation>> {
            Ok(Vec::new())
        }
        async fn count_pending_organization_invitations(&self, _org_id: &str) -> AuthResult<i64> {
            Ok(0)
        }
        async fn list_user_invitations(&self, _email: &str) -> AuthResult<Vec<Invitation>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl TwoFactorStore for MemoryStore {
        async fn create_two_factor(&self, _two_factor: CreateTwoFactor) -> AuthResult<TwoFactor> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn get_two_factor_by_user_id(&self, _user_id: &str) -> AuthResult<Option<TwoFactor>> {
            Ok(None)
        }
        async fn update_two_factor_backup_codes(
            &self,
            _user_id: &str,
            _backup_codes: &str,
        ) -> AuthResult<TwoFactor> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn delete_two_factor(&self, _user_id: &str) -> AuthResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl ApiKeyStore for MemoryStore {
        async fn consume_api_key_usage_from_snapshot(
            &self,
            _observed: &ApiKey,
            _global_rate_limit_enabled: bool,
        ) -> AuthResult<ConsumeApiKeyResult> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn create_api_key(&self, _input: CreateApiKey) -> AuthResult<ApiKey> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn get_api_key_by_id(&self, _id: &str) -> AuthResult<Option<ApiKey>> {
            Ok(None)
        }
        async fn get_api_key_by_hash(&self, _hash: &str) -> AuthResult<Option<ApiKey>> {
            Ok(None)
        }
        async fn list_api_keys_by_reference(&self, _user_id: &str) -> AuthResult<Vec<ApiKey>> {
            Ok(Vec::new())
        }
        async fn update_api_key(&self, _id: &str, _update: UpdateApiKey) -> AuthResult<ApiKey> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn delete_api_key(&self, _id: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn delete_expired_api_keys(&self) -> AuthResult<usize> {
            Ok(0)
        }
        async fn consume_api_key_usage(
            &self,
            _id: &str,
            _global_rate_limit_enabled: bool,
        ) -> AuthResult<ConsumeApiKeyResult> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
    }

    #[async_trait]
    impl PasskeyStore for MemoryStore {
        async fn create_passkey(&self, _input: CreatePasskey) -> AuthResult<Passkey> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn get_passkey_by_id(&self, _id: &str) -> AuthResult<Option<Passkey>> {
            Ok(None)
        }
        async fn get_passkey_by_credential_id(
            &self,
            _credential_id: &str,
        ) -> AuthResult<Option<Passkey>> {
            Ok(None)
        }
        async fn list_passkeys_by_user(&self, _user_id: &str) -> AuthResult<Vec<Passkey>> {
            Ok(Vec::new())
        }
        async fn update_passkey_authentication(
            &self,
            _id: &str,
            _update: UpdatePasskeyAuthentication,
        ) -> AuthResult<Option<Passkey>> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn update_passkey_name(
            &self,
            _id: &str,
            _name: &crate::utils::json::JsString,
        ) -> AuthResult<Passkey> {
            Err(AuthError::internal("unsupported test-store operation"))
        }
        async fn delete_passkey(&self, _id: &str) -> AuthResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl DeviceCodeStore for MemoryStore {
        async fn create_device_code(&self, input: CreateDeviceCode) -> AuthResult<DeviceCode> {
            let device_code = DeviceCode {
                id: uuid::Uuid::new_v4().to_string(),
                device_code: input.device_code,
                user_code: input.user_code,
                user_id: input.user_id,
                expires_at: input.expires_at,
                status: input.status,
                last_polled_at: input.last_polled_at,
                polling_interval: input.polling_interval,
                client_id: input.client_id,
                scope: input.scope,
            };
            self.lock()
                .device_codes
                .insert(device_code.id.clone(), device_code.clone());
            Ok(device_code)
        }

        async fn get_device_code_by_device_code(
            &self,
            device_code: &str,
        ) -> AuthResult<Option<DeviceCode>> {
            Ok(self
                .lock()
                .device_codes
                .values()
                .find(|value| value.device_code == device_code)
                .cloned())
        }

        async fn get_device_code_by_user_code(
            &self,
            user_code: &str,
        ) -> AuthResult<Option<DeviceCode>> {
            Ok(self
                .lock()
                .device_codes
                .values()
                .find(|value| value.user_code == user_code)
                .cloned())
        }

        async fn update_device_code(
            &self,
            id: &str,
            update: UpdateDeviceCode,
        ) -> AuthResult<DeviceCode> {
            let mut state = self.lock();
            let device_code = state
                .device_codes
                .get_mut(id)
                .ok_or_else(|| AuthError::not_found("Device code not found"))?;

            if let Some(status) = update.status {
                device_code.status = status;
            }
            if let Some(user_id) = update.user_id {
                device_code.user_id = user_id;
            }
            if let Some(last_polled_at) = update.last_polled_at {
                device_code.last_polled_at = last_polled_at;
            }

            let locked_result = Ok(device_code.clone());
            drop(state);
            locked_result
        }

        async fn update_device_code_if_status(
            &self,
            id: &str,
            current_status: &str,
            update: UpdateDeviceCode,
        ) -> AuthResult<bool> {
            let mut state = self.lock();
            let Some(device_code) = state.device_codes.get_mut(id) else {
                return Ok(false);
            };

            if device_code.status != current_status {
                return Ok(false);
            }

            if let Some(status) = update.status {
                device_code.status = status;
            }
            if let Some(user_id) = update.user_id {
                device_code.user_id = user_id;
            }
            if let Some(last_polled_at) = update.last_polled_at {
                device_code.last_polled_at = last_polled_at;
            }
            drop(state);

            Ok(true)
        }

        async fn claim_device_code(&self, id: &str, user_id: &str) -> AuthResult<bool> {
            let mut state = self.lock();
            let Some(device_code) = state.device_codes.get_mut(id) else {
                return Ok(false);
            };

            if device_code.status != "pending" || device_code.user_id.is_some() {
                return Ok(false);
            }

            device_code.user_id = Some(user_id.to_owned());
            drop(state);

            Ok(true)
        }

        async fn delete_device_code(&self, id: &str) -> AuthResult<()> {
            self.lock().device_codes.remove(id);
            Ok(())
        }

        async fn delete_device_code_if_status(&self, id: &str, status: &str) -> AuthResult<bool> {
            let mut state = self.lock();
            let should_delete = state
                .device_codes
                .get(id)
                .is_some_and(|device_code| device_code.status == status);

            if should_delete {
                state.device_codes.remove(id);
            }

            let locked_result = Ok(should_delete);
            drop(state);
            locked_result
        }
    }

    #[async_trait]
    impl TransactionStore<BundledSchema> for MemoryStore {
        async fn transaction_boxed(
            &self,
            work: Box<crate::store::TransactionWork<BundledSchema>>,
        ) -> AuthResult<crate::store::BoxedTransactionValue> {
            let base = self.lock().clone();
            let tx = MemoryTransaction {
                store: MemoryStore {
                    state: Mutex::new(base.clone()),
                },
            };
            let result = work(&tx).await?;
            let changed = tx
                .store
                .state
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut live = self.lock();
            let mut merged = live.clone();
            use crate::store::memory_transaction::merge_rows;
            merged.users = merge_rows(
                live.users.iter().map(|(id, row)| (id, row)),
                base.users.iter().map(|(id, row)| (id, row)),
                changed.users.iter().map(|(id, row)| (id, row)),
            )?;
            merged.sessions = merge_rows(
                live.sessions.iter(),
                base.sessions.iter(),
                changed.sessions.iter(),
            )?
            .into_iter()
            .collect();
            merged.accounts = merge_rows(
                live.accounts.iter(),
                base.accounts.iter(),
                changed.accounts.iter(),
            )?
            .into_iter()
            .collect();
            merged.verifications = merge_rows(
                live.verifications.iter(),
                base.verifications.iter(),
                changed.verifications.iter(),
            )?
            .into_iter()
            .collect();
            merged.device_codes = merge_rows(
                live.device_codes.iter(),
                base.device_codes.iter(),
                changed.device_codes.iter(),
            )?
            .into_iter()
            .collect();
            *live = merged;
            Ok(result)
        }
    }

    pub fn test_config() -> Arc<AuthConfig> {
        Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"))
    }

    pub async fn test_database() -> Arc<dyn AuthStore<BundledSchema>> {
        Arc::new(MemoryStore::new(test_config()))
    }
    // LCOV_EXCL_STOP

    impl crate::store::OAuthClientStore for MemoryStore {}

    impl crate::store::SsoProviderStore for MemoryStore {}

    impl crate::store::ScimManagedStore for MemoryStore {}
}

pub mod types;
#[doc(hidden)]
pub mod user_query;
pub mod user_validation;
pub mod utils;
pub mod verification;
pub mod wire;

#[doc(hidden)]
pub use crate as __private_core;
pub use adapter_record::{AdapterOutput, AdapterRecord};
pub use alibi_macros::{AuthSchema, PluginConfig};
pub use authenticated_user::AuthenticatedUser;
pub use background_tasks::{
    BackgroundTaskCompletion, BackgroundTaskHandler, start_background_task,
};
pub use config::{
    AccountConfig, AccountLinkingConfig, AdvancedConfig, AdvancedDatabaseConfig, AuthConfig,
    AwaitedNotificationErrorPolicy, CookieAttributes, CookieCacheConfig, CookieCacheStrategy,
    CookieOverride, CookieRefreshCache, CrossSubDomainConfig, IpAddressConfig, JwtConfig,
    ManagedSecrets, OAuthStateStrategy, PasswordConfig, SameSite, SessionConfig, UserConfig,
    core_paths, extract_origin,
};
pub use email::{ConsoleEmailProvider, EmailProvider};
pub use entity::{
    AuthAccount, AuthApiKey, AuthInvitation, AuthMember, AuthOrganization, AuthPasskey,
    AuthSession, AuthTwoFactor, AuthUser, AuthVerification, MemberUserView,
};
pub use error::{
    AuthError, AuthResult, DatabaseError, validate_request_body, validation_error_response,
};
pub use hooks::{
    CallbackContext, RequestHookContext, with_request_hook_context, with_request_hook_context_value,
};
pub use middleware::{
    BodyLimitConfig, BodyLimitMiddleware, CacheRateLimitStorage, CorsConfig, CorsMiddleware,
    CsrfConfig, CsrfMiddleware, EndpointRateLimit, MemoryRateLimitStorage, Middleware,
    PluginRateLimit, RateLimitConfig, RateLimitDecision, RateLimitMiddleware, RateLimitResolver,
    RateLimitRule, RateLimitStorage,
};
pub use openapi::{
    OpenApiBuilder, OpenApiEndpoint, OpenApiField, OpenApiInfo, OpenApiModel, OpenApiOperation,
    OpenApiRegistry, OpenApiResponse, OpenApiSpec, PluginOpenApiMetadata,
};
pub use plugin::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRoute, BeforeRequestAction, ContextExtensions,
    HttpEndpointResponse, HttpRequestAction, VerificationEmailOverride,
    VerificationEmailOverrideHandle,
};
pub use schema::AuthSchema;
pub use session::SessionManager;
pub use session::cookie_cache::{
    CacheVersionContext, CacheVersionSource, CookieCacheVersion, CookieCacheVersionResolver,
};
pub use store::{
    AuthStore, AuthTransaction, CacheAdapter, ConsumeApiKeyResult, MemoryCacheAdapter,
    WalletAddressStore, transaction,
};
pub use types::{
    ApiKey, ApiKeyStartText, ApiKeyStartingCharacters, AuthRequest, AuthResponse,
    CodeMessageResponse, CreateAccount, CreateApiKey, CreateDeviceCode, CreateInvitation,
    CreateMember, CreateOrganization, CreatePasskey, CreateSession, CreateTeam, CreateTwoFactor,
    CreateUser, CreateVerification, CreateWalletAddress, DeviceCode, ErrorCodeMessageResponse,
    ErrorMessageResponse, Headers, HealthCheckResponse, HttpMethod, Invitation, InvitationStatus,
    ListUsersParams, Member, OkResponse, Organization, OrganizationPermissions, Passkey,
    RateLimitErrorResponse, RequestMeta, StatusMessageResponse, StatusResponse,
    SuccessMessageResponse, SuccessResponse, Team, TeamMember, TwoFactor, UpdateAccount,
    UpdateApiKey, UpdateDeviceCode, UpdateOrganization, UpdatePasskey, UpdateTeam, UpdateTwoFactor,
    UpdateUser, UpdateUserRequest, UpdateUserResponse, UpdateVerification, UserFilterValue,
    ValidationErrorResponse, WalletAddress,
};
pub use types::{CreateJwk, Jwk};
pub use utils::password::{
    PasswordHashContext, PasswordHashHook, PasswordHasher, ScryptHasher, hash_password,
    verify_password,
};
#[doc(hidden)]
pub use uuid;
pub use wire::{
    AccountView, ApiKeyView, InvitationView, OrganizationView, PasskeyView, SessionView, UserView,
    VerificationView,
};
