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
    AccountStore, ApiKeyStore, AuthStore, AuthTransaction, ConsumeApiKeyResult, DeviceCodeStore,
    InvitationStore, ListOrganizationMembersParams, MemberStore, OrganizationStore, PasskeyStore,
    SessionStore, TransactionStore, TwoFactorStore, UserStore, VerificationStore,
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

#[derive(Default)]
struct State {
    users: HashMap<String, UserView>,
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
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct MemoryTransaction<'a> {
    store: &'a MemoryStore,
}

#[async_trait]
impl AuthTransaction<BundledSchema> for MemoryTransaction<'_> {
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        self.store.get_user_by_id(id).await
    }
    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        self.store.create_passkey(data).await
    }
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<UserView> {
        self.store.create_user(create_user).await
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
}

#[async_trait]
impl UserStore<BundledSchema> for MemoryStore {
    async fn create_user(&self, create_user: CreateUser) -> AuthResult<UserView> {
        let now = Utc::now();
        let id = create_user
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let username = create_user.username.map(|username| username.to_lowercase());
        let user = UserView {
            id: id.clone(),
            name: create_user.name,
            email: create_user.email.map(|email| email.to_lowercase()),
            email_verified: create_user.email_verified.unwrap_or(false),
            image: create_user.image,
            created_at: now,
            updated_at: now,
            username,
            display_username: create_user.display_username,
            two_factor_enabled: create_user.two_factor_enabled,
            role: create_user.role,
            banned: create_user.banned,
            ban_reason: None,
            ban_expires: None,
            metadata: create_user
                .metadata
                .unwrap_or_else(|| serde_json::json!({})),
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
            last_login_method: create_user.last_login_method,
            extension_fields: std::collections::BTreeMap::default(),
        };
        self.lock().users.insert(id, user.clone());
        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        Ok(self.lock().users.get(id).cloned())
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock();
        Ok(ids
            .iter()
            .filter_map(|id| state.users.get(id).cloned())
            .collect())
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let normalized = username.to_lowercase();
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| user.username.as_deref() == Some(&normalized))
            .cloned())
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()
            .users
            .values()
            .find(|user| user.phone_number.as_deref() == Some(phone_number))
            .cloned())
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<UserView> {
        let mut state = self.lock();
        let user = state.users.get_mut(id).ok_or(AuthError::UserNotFound)?;
        if let Some(email) = update.email {
            user.email = Some(email.to_lowercase());
        }
        if let Some(name) = update.name {
            user.name = Some(name);
        }
        if let Some(image) = update.image {
            user.image = Some(image);
        }
        if let Some(email_verified) = update.email_verified {
            user.email_verified = email_verified;
        }
        if let Some(username) = update.username {
            user.username = Some(username.to_lowercase());
        }
        if let Some(display_username) = update.display_username {
            user.display_username = Some(display_username);
        }
        if let Some(role) = update.role {
            user.role = Some(role);
        }
        if let Some(banned) = update.banned {
            user.banned = Some(banned);
            if !banned {
                user.ban_reason = None;
                user.ban_expires = None;
            }
        }
        if let Some(ban_reason) = update.ban_reason {
            user.ban_reason = Some(ban_reason);
        }
        if let Some(ban_expires) = update.ban_expires {
            user.ban_expires = ban_expires;
        }
        if let Some(two_factor_enabled) = update.two_factor_enabled {
            user.two_factor_enabled = Some(two_factor_enabled);
        }
        if let Some(metadata) = update.metadata {
            user.metadata = metadata;
        }
        if let Some(is_anonymous) = update.is_anonymous {
            user.is_anonymous = Some(is_anonymous);
        }
        if let Some(phone_number) = update.phone_number {
            user.phone_number = phone_number;
        }
        if let Some(phone_number_verified) = update.phone_number_verified {
            user.phone_number_verified = Some(phone_number_verified);
        }
        if let Some(last_login_method) = update.last_login_method {
            user.last_login_method = last_login_method;
        }
        user.updated_at = Utc::now();
        let locked_result = Ok(user.clone());
        drop(state);
        locked_result
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.lock().users.remove(id);
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let users: Vec<_> = self.lock().users.values().cloned().collect();
        Ok(crate::user_query::apply_list_users(users, &_params))
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
            drop(
                session
                    .extension_fields
                    .insert(name, value.to_json_value()?),
            );
        }
        session.updated_at = Utc::now();
        let locked_result = Ok(Some(session.clone()));
        drop(data);
        locked_result
    }
    async fn create_session(&self, mut create_session: CreateSession) -> AuthResult<SessionView> {
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
                    crate::utils::json::JsValue::String(value.clone()),
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
                .map(|(name, value)| value.to_json_value().map(|value| (name, value)))
                .collect::<Result<_, _>>()?,
            active: true,
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
        state
            .sessions
            .retain(|_, session| session.expires_at > now && session.active);
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
        provider_account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        Ok(self
            .lock()
            .accounts
            .values()
            .find(|account| {
                account.provider_id == provider && account.account_id == provider_account_id
            })
            .cloned())
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

    async fn get_verification_by_value(&self, value: &str) -> AuthResult<Option<VerificationView>> {
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
        let _ignored_insert = entry.insert(VerificationView {
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
        state
            .verifications
            .retain(|_, verification| verification.expires_at > now);
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
    async fn list_organizations_by_ids(&self, _ids: &[String]) -> AuthResult<Vec<Organization>> {
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
    async fn list_organization_invitations(&self, _org_id: &str) -> AuthResult<Vec<Invitation>> {
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
    ) -> AuthResult<Passkey> {
        Err(AuthError::internal("unsupported test-store operation"))
    }
    async fn update_passkey_name(&self, _id: &str, _name: &str) -> AuthResult<Passkey> {
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
        let tx = MemoryTransaction { store: self };
        work(&tx).await
    }
}

pub fn test_config() -> Arc<AuthConfig> {
    Arc::new(AuthConfig::new("test-secret-min-32-chars-1234567"))
}

pub async fn test_database() -> Arc<dyn AuthStore<BundledSchema>> {
    Arc::new(MemoryStore::new(test_config()))
}
