use crate::field_policy::FieldValues;
use crate::store::memory_transaction::{merge_indexed, merge_rows};
use crate::store::stateless::{StatelessSchema, StatelessStore};
use crate::store::{
    AccountStore, BoxedTransactionValue, MemberStore, PasskeyStore, SessionStore, TeamStore,
    TransactionStore, TransactionWork, UserStore, VerificationStore,
};
use crate::types::AddTeamMemberResult;
use crate::user_validation::PreparedUserCreation;
use crate::{
    AccountView, AuthError, AuthResult, AuthTransaction, CreateAccount, CreateMember,
    CreatePasskey, CreateSession, CreateUser, CreateVerification, Member, Passkey, SessionView,
    Team, UpdateAccount, UserView, VerificationView,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

struct StatelessTransaction {
    snapshot: StatelessStore,
}

#[async_trait]
impl TransactionStore<StatelessSchema> for StatelessStore {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<StatelessSchema>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let (base, organizations) = {
            let state = self.lock()?;
            let organizations = self.organization_state()?;
            (state.clone(), organizations.clone())
        };
        let tx = StatelessTransaction {
            snapshot: Self {
                state: std::sync::Mutex::new(base.clone()),
                organizations: std::sync::Mutex::new(organizations.clone()),
                find_many_limit: self.find_many_limit,
            },
        };
        let result = work(&tx).await?;
        let changed = tx
            .snapshot
            .state
            .into_inner()
            .map_err(|_| AuthError::internal("No-database identity state poisoned"))?;
        let changed_organizations = tx
            .snapshot
            .organizations
            .into_inner()
            .map_err(|_| AuthError::internal("No-database organization state poisoned"))?;
        let mut live = self.lock()?;
        let mut live_organizations = self.organization_state()?;
        let mut merged = live.clone();
        let mut merged_organizations = live_organizations.clone();
        merged.users = merge_rows(
            live.users.iter().map(|(id, row)| (id, row)),
            base.users.iter().map(|(id, row)| (id, row)),
            changed.users.iter().map(|(id, row)| (id, row)),
        )?;
        merge_indexed(&mut merged.accounts, &base.accounts, &changed.accounts)?;
        merge_indexed(
            &mut merged.verifications,
            &base.verifications,
            &changed.verifications,
        )?;
        merge_indexed(
            &mut merged.two_factors,
            &base.two_factors,
            &changed.two_factors,
        )?;
        merge_indexed(&mut merged.passkeys, &base.passkeys, &changed.passkeys)?;
        merge_indexed(&mut merged.api_keys, &base.api_keys, &changed.api_keys)?;
        merge_indexed(
            &mut merged.device_codes,
            &base.device_codes,
            &changed.device_codes,
        )?;
        merge_indexed(
            &mut merged.device_code_fields,
            &base.device_code_fields,
            &changed.device_code_fields,
        )?;
        // No transactional JWK write API exists; preserve the live private keyring.
        merge_indexed(
            &mut merged_organizations.organizations,
            &organizations.organizations,
            &changed_organizations.organizations,
        )?;
        merge_indexed(
            &mut merged_organizations.members,
            &organizations.members,
            &changed_organizations.members,
        )?;
        merge_indexed(
            &mut merged_organizations.invitations,
            &organizations.invitations,
            &changed_organizations.invitations,
        )?;
        merge_indexed(
            &mut merged_organizations.teams,
            &organizations.teams,
            &changed_organizations.teams,
        )?;
        merge_indexed(
            &mut merged_organizations.team_members,
            &organizations.team_members,
            &changed_organizations.team_members,
        )?;
        merge_indexed(
            &mut merged_organizations.roles,
            &organizations.roles,
            &changed_organizations.roles,
        )?;
        *live = merged;
        *live_organizations = merged_organizations;
        Ok(result)
    }
}

#[async_trait]
impl AuthTransaction<StatelessSchema> for StatelessTransaction {
    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<UserView>> {
        UserStore::<StatelessSchema>::get_user_by_id(&self.snapshot, id).await
    }

    async fn get_user_by_email(
        &self,
        email: &crate::utils::json::JsString,
    ) -> AuthResult<Option<UserView>> {
        UserStore::<StatelessSchema>::get_user_by_email(&self.snapshot, email).await
    }

    async fn get_account(
        &self,
        provider: &str,
        id: &crate::utils::json::JsString,
    ) -> AuthResult<Option<AccountView>> {
        AccountStore::<StatelessSchema>::get_account(&self.snapshot, provider, id).await
    }

    async fn create_verification(&self, data: CreateVerification) -> AuthResult<VerificationView> {
        VerificationStore::<StatelessSchema>::create_verification(&self.snapshot, data).await
    }

    async fn create_passkey(&self, data: CreatePasskey) -> AuthResult<Passkey> {
        PasskeyStore::create_passkey(&self.snapshot, data).await
    }

    async fn update_user_prepared(
        &self,
        id: &str,
        update: crate::store::PreparedUserUpdate,
    ) -> AuthResult<UserView> {
        UserStore::<StatelessSchema>::update_user_prepared(&self.snapshot, id, update).await
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

    async fn get_team(&self, org: &str, id: &str) -> AuthResult<Option<Team>> {
        TeamStore::get_team(&self.snapshot, Some(org), id).await
    }
    async fn add_team_member(
        &self,
        team: &str,
        user: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        TeamStore::add_team_member(&self.snapshot, team, user, maximum).await
    }
    async fn create_member(&self, data: CreateMember) -> AuthResult<Member> {
        MemberStore::create_member(&self.snapshot, data).await
    }
    async fn prepare_secondary_session_creation(
        &self,
        input: CreateSession,
        persist: bool,
    ) -> AuthResult<SessionView> {
        SessionStore::<StatelessSchema>::prepare_secondary_session_creation(
            &self.snapshot,
            input,
            persist,
        )
        .await
    }
    async fn prepare_secondary_session_update(
        &self,
        session: SessionView,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
    ) -> AuthResult<Option<(SessionView, FieldValues)>> {
        SessionStore::<StatelessSchema>::prepare_secondary_session_update(
            &self.snapshot,
            session,
            expires_at,
            fields,
        )
        .await
    }
    async fn complete_secondary_session_update(
        &self,
        token: &str,
        session: SessionView,
        expires_at: Option<DateTime<Utc>>,
        fields: FieldValues,
        persist: bool,
    ) -> AuthResult<Option<SessionView>> {
        SessionStore::<StatelessSchema>::complete_secondary_session_update(
            &self.snapshot,
            token,
            session,
            expires_at,
            fields,
            persist,
        )
        .await
    }
    async fn create_user(&self, data: CreateUser) -> AuthResult<UserView> {
        UserStore::<StatelessSchema>::create_user(&self.snapshot, data).await
    }
    async fn get_user_by_username_value(
        &self,
        username: &crate::utils::json::JsValue,
    ) -> AuthResult<Option<UserView>> {
        UserStore::<StatelessSchema>::get_user_by_username_value(&self.snapshot, username).await
    }
    async fn create_user_prepared(&self, data: PreparedUserCreation) -> AuthResult<UserView> {
        UserStore::<StatelessSchema>::create_user_prepared(&self.snapshot, data).await
    }
    async fn create_account(&self, data: CreateAccount) -> AuthResult<AccountView> {
        AccountStore::<StatelessSchema>::create_account(&self.snapshot, data).await
    }
    async fn create_session(&self, data: CreateSession) -> AuthResult<SessionView> {
        SessionStore::<StatelessSchema>::create_session(&self.snapshot, data).await
    }
    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        SessionStore::<StatelessSchema>::delete_user_sessions(&self.snapshot, user_id).await
    }
    async fn update_account(&self, id: &str, update: UpdateAccount) -> AuthResult<AccountView> {
        AccountStore::<StatelessSchema>::update_account(&self.snapshot, id, update).await
    }
    async fn consume_verification_snapshot(
        &self,
        identifier: &str,
    ) -> AuthResult<Option<VerificationView>> {
        VerificationStore::<StatelessSchema>::consume_verification_snapshot(
            &self.snapshot,
            identifier,
        )
        .await
    }
}
