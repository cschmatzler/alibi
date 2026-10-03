//! Ephemeral no-database identity provisioning and cookie-only sessions.
//!
//! This store has no database connection. The initialized store wrapper keeps
//! ephemeral session records for cookie bypass and instance-local logout.
//! User/account/verification provisioning is instance-local, as in the pinned
//! no-database memory adapter. Native two-factor/passkey/API-key/device-code/JWK/organization records share that
//! instance-local lifetime; other optional records require an application store.
//! Applications can also use cookie-only sessions with durable SQL user storage.
mod api_keys;
mod device_codes;
mod invitations;
mod jwks;
mod members;
mod optional_records;
mod organizations;
mod roles;
mod teams;
mod transaction;

use super::*;
use crate::{AccountView, SessionView, UserView, VerificationView};
use chrono::{DateTime, Utc};

/// Wire schema for deployments that do not configure a database.
pub struct StatelessSchema;
impl AuthSchema for StatelessSchema {
    fn user_from_cookie_cache(user: UserView) -> Option<UserView> {
        Some(user)
    }
    type User = UserView;
    type Session = SessionView;
    type Account = AccountView;
    type Verification = VerificationView;
}

/// Instance-local provisioning without durable persistence. Session ownership
/// comes from trusted issuance; the initialized wrapper retains ephemeral sessions.
pub struct StatelessStore {
    state: std::sync::Mutex<IdentityState>,
    organizations: std::sync::Mutex<OrganizationState>,
    find_many_limit: usize,
}

#[derive(Default)]
struct IdentityState {
    users: indexmap::IndexMap<String, UserView>,
    accounts: indexmap::IndexMap<String, AccountView>,
    verifications: indexmap::IndexMap<String, VerificationView>,
    two_factors: indexmap::IndexMap<String, TwoFactor>,
    passkeys: indexmap::IndexMap<String, Passkey>,
    api_keys: indexmap::IndexMap<String, ApiKey>,
    device_codes: indexmap::IndexMap<String, DeviceCode>,
    jwks: indexmap::IndexMap<String, Jwk>,
}

#[derive(Default, Clone)]
struct OrganizationState {
    organizations: indexmap::IndexMap<String, Organization>,
    members: indexmap::IndexMap<String, Member>,
    invitations: indexmap::IndexMap<String, Invitation>,
    teams: indexmap::IndexMap<String, Team>,
    team_members: indexmap::IndexMap<String, TeamMember>,
    roles: indexmap::IndexMap<String, OrganizationRole>,
}

impl Default for StatelessStore {
    fn default() -> Self {
        Self::with_find_many_limit(100)
    }
}

impl StatelessStore {
    /// Use the configured adapter page bound for native organization rows.
    #[must_use]
    pub fn with_find_many_limit(find_many_limit: usize) -> Self {
        Self {
            state: Default::default(),
            organizations: Default::default(),
            find_many_limit,
        }
    }

    fn organization_state(&self) -> AuthResult<std::sync::MutexGuard<'_, OrganizationState>> {
        self.organizations
            .lock()
            .map_err(|_| AuthError::internal("No-database organization state poisoned"))
    }

    fn lock(&self) -> AuthResult<std::sync::MutexGuard<'_, IdentityState>> {
        self.state
            .lock()
            .map_err(|_| AuthError::internal("No-database identity state poisoned"))
    }
}

impl WalletAddressStore for StatelessStore {}

#[async_trait]
impl SessionStore<StatelessSchema> for StatelessStore {
    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<SessionView> {
        if persist {
            return Err(AuthError::config("StatelessStore cannot persist sessions"));
        }
        SessionStore::<StatelessSchema>::create_session(self, input).await
    }
    async fn complete_secondary_session_creation(&self, _session: &SessionView) -> AuthResult<()> {
        Ok(())
    }
    async fn create_session(&self, mut input: CreateSession) -> AuthResult<SessionView> {
        input
            .additional_fields
            .apply_adapter_transforms_async()
            .await?;
        let now = Utc::now();
        Ok(SessionView {
            id: uuid::Uuid::new_v4().to_string(),
            token: input
                .token
                .unwrap_or_else(crate::utils::sessions::generate_session_token),
            user_id: input.user_id,
            expires_at: input.expires_at,
            created_at: now,
            updated_at: now,
            ip_address: input.ip_address.or_else(|| Some(String::new())),
            user_agent: input.user_agent.or_else(|| Some(String::new())),
            active_organization_id: input.active_organization_id,
            active_team_id: input.active_team_id,
            impersonated_by: input.impersonated_by,
            extension_fields: input
                .additional_fields
                .into_iter()
                .map(|(key, value)| value.to_json_value().map(|value| (key, value)))
                .collect::<Result<_, _>>()?,
            active: true,
            omitted_fields: Default::default(),
        })
    }
    async fn prepare_secondary_session_update(
        &self,
        mut session: SessionView,
        expires_at: Option<DateTime<Utc>>,
        mut fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<(SessionView, crate::field_policy::FieldValues)>> {
        fields.apply_adapter_transforms_async().await?;
        for (key, value) in &fields {
            match key.as_str() {
                "activeOrganizationId" => {
                    session.active_organization_id = value.as_str().map(str::to_owned)
                }
                "activeTeamId" => session.active_team_id = value.as_str().map(str::to_owned),
                "impersonatedBy" => session.impersonated_by = value.as_str().map(str::to_owned),
                _ => {
                    drop(
                        session
                            .extension_fields
                            .insert(key.clone(), value.to_json_value()?),
                    );
                }
            }
        }
        if let Some(expires_at) = expires_at {
            session.expires_at = expires_at;
        }
        session.updated_at = Utc::now();
        Ok(Some((session, fields)))
    }
    async fn complete_secondary_session_update(
        &self,
        session: SessionView,
        _expires_at: Option<DateTime<Utc>>,
        _fields: crate::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<SessionView>> {
        if persist {
            return Err(AuthError::config(
                "No-database store cannot persist sessions",
            ));
        }
        Ok(Some(session))
    }
    async fn get_session(&self, _token: &str) -> AuthResult<Option<SessionView>> {
        Ok(None)
    }
    async fn get_user_sessions(&self, _user: &str) -> AuthResult<Vec<SessionView>> {
        Ok(Vec::new())
    }
    async fn update_session_expiry(
        &self,
        _token: &str,
        _expires: chrono::DateTime<Utc>,
    ) -> AuthResult<()> {
        Err(AuthError::SessionNotFound)
    }
    async fn update_session_active_organization(
        &self,
        _token: &str,
        _id: Option<&str>,
    ) -> AuthResult<SessionView> {
        Err(AuthError::SessionNotFound)
    }
    async fn delete_session(&self, _token: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn delete_user_sessions(&self, _user: &str) -> AuthResult<()> {
        Ok(())
    }
    async fn delete_expired_sessions(&self) -> AuthResult<usize> {
        Ok(0)
    }
}

#[async_trait]
impl UserStore<StatelessSchema> for StatelessStore {
    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<UserView> {
        create_user.email = create_user.email.map(|email| email.to_lowercase());
        UserStore::<StatelessSchema>::create_user_prepared(
            self,
            crate::user_validation::PreparedUserCreation::from_data(create_user),
        )
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
        let id = create_user
            .id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut omitted_fields = std::collections::BTreeSet::new();
        for (name, absent) in [
            ("name", create_user.name.is_none()),
            ("email", create_user.email.is_none()),
            ("image", create_user.image.is_none()),
            ("username", create_user.username.is_none()),
            ("displayUsername", create_user.display_username.is_none()),
        ] {
            if absent && !create_user.additional_fields.contains_key(name) {
                let _ = omitted_fields.insert(name.to_owned());
            }
        }
        let username = create_user.username.map(|username| username.to_lowercase());
        let user = UserView {
            omitted_fields,
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
                .unwrap_or_else(|| serde_json::json!({})),
            is_anonymous: create_user.is_anonymous,
            phone_number: create_user.phone_number,
            phone_number_verified: create_user.phone_number_verified,
            last_login_method: create_user.last_login_method,
            extension_fields: create_user
                .additional_fields
                .into_iter()
                .map(|(key, value)| value.to_json_value().map(|value| (key, value)))
                .collect::<Result<_, _>>()?,
        };
        let mut state = self.lock()?;
        if state.users.contains_key(&id)
            || state
                .users
                .values()
                .any(|existing| user.email.is_some() && existing.email == user.email)
        {
            return Err(AuthError::bad_request("User already exists"));
        }
        drop(state.users.insert(id, user.clone()));
        Ok(user)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        Ok(self.lock()?.users.get(id).cloned())
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<UserView>> {
        let state = self.lock()?;
        Ok(ids
            .iter()
            .filter_map(|id| state.users.get(id).cloned())
            .collect())
    }

    async fn list_users_by_ids_page(
        &self,
        ids: &[String],
        limit: f64,
    ) -> AuthResult<Vec<UserView>> {
        let mut users: Vec<_> = self
            .lock()?
            .users
            .values()
            .filter(|user| ids.contains(&user.id))
            .cloned()
            .collect();
        users.truncate(members::slice_index(limit, users.len()));
        Ok(users)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.email.as_deref() == Some(&email.to_lowercase()))
            .cloned())
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<UserView>> {
        let normalized = username.to_lowercase();
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.username.as_deref() == Some(&normalized))
            .cloned())
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<UserView>> {
        Ok(self
            .lock()?
            .users
            .values()
            .find(|user| user.phone_number.as_deref() == Some(phone_number))
            .cloned())
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<UserView> {
        update
            .additional_fields
            .apply_adapter_transforms_async()
            .await?;
        let mut state = self.lock()?;
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
        for (key, value) in update.additional_fields {
            drop(user.extension_fields.insert(key, value.to_json_value()?));
        }
        for name in ["name", "email", "image", "username", "displayUsername"] {
            let present = match name {
                "name" => user.name.is_some(),
                "email" => user.email.is_some(),
                "image" => user.image.is_some(),
                "username" => user.username.is_some(),
                _ => user.display_username.is_some(),
            };
            if present {
                let _ = user.omitted_fields.remove(name);
            }
        }
        user.updated_at = Utc::now();
        let locked_result = Ok(user.clone());
        drop(state);
        locked_result
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        drop(self.lock()?.users.shift_remove(id));
        Ok(())
    }

    async fn list_users(&self, _params: ListUsersParams) -> AuthResult<(Vec<UserView>, usize)> {
        let users: Vec<_> = self.lock()?.users.values().cloned().collect();
        Ok(crate::user_query::apply_list_users(users, &_params))
    }
}

#[async_trait]
impl AccountStore<StatelessSchema> for StatelessStore {
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
        drop(
            self.lock()?
                .accounts
                .insert(account.id.clone(), account.clone()),
        );
        Ok(account)
    }

    async fn get_account(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> AuthResult<Option<AccountView>> {
        let storage = self.lock()?;
        let mut matches = storage.accounts.values().filter(|account| {
            account.provider_id == provider && account.account_id == provider_account_id
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
            .lock()?
            .accounts
            .values()
            .filter(|account| account.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        let mut state = self.lock()?;
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
        drop(self.lock()?.accounts.shift_remove(id));
        Ok(())
    }
}

#[async_trait]
impl VerificationStore<StatelessSchema> for StatelessStore {
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
            let mut state = self.lock()?;
            if state.verifications.contains_key(&model.id) {
                return Err(AuthError::internal("duplicate verification primary ID"));
            }
            drop(state.verifications.insert(model.id.clone(), model.clone()));
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
        let mut state = self.lock()?;
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
        let mut state = self.lock()?;
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
        let mut state = self.lock()?;
        let indexmap::map::Entry::Vacant(entry) = state.verifications.entry(id.clone()) else {
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
        _ = entry.insert(model.clone());
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
        drop(
            self.lock()?
                .verifications
                .insert(verification.id.clone(), verification.clone()),
        );
        Ok(verification)
    }

    async fn get_verification(
        &self,
        identifier: &str,
        value: &str,
    ) -> AuthResult<Option<VerificationView>> {
        Ok(self
            .lock()?
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
            .lock()?
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
            .lock()?
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
        let mut state = self.lock()?;
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
            .lock()?
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
        let mut state = self.lock()?;
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
        self.lock()?
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
        let mut state = self.lock()?;
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
        let mut state = self.lock()?;
        let indexmap::map::Entry::Vacant(entry) = state.verifications.entry(id.clone()) else {
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
        drop(self.lock()?.verifications.shift_remove(id));
        Ok(())
    }

    async fn delete_expired_verifications(&self) -> AuthResult<usize> {
        let now = Utc::now();
        let mut state = self.lock()?;
        let before = state.verifications.len();
        state.verifications.retain(|_, verification| {
            verification.expires_at.timestamp_millis() >= now.timestamp_millis()
        });
        Ok(before - state.verifications.len())
    }
}
