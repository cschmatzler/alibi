use crate::store::stateless::{StatelessSchema, StatelessStore};
use crate::store::{
    AccountStore, BoxedTransactionValue, MemberStore, SessionStore, TeamStore, TransactionStore,
    TransactionWork, UserStore,
};
use crate::types::AddTeamMemberResult;
use crate::user_validation::PreparedUserCreation;
use crate::{
    AccountView, AuthError, AuthResult, AuthTransaction, CreateAccount, CreateMember,
    CreateSession, CreateUser, Member, SessionView, Team, UserView,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Reconcile only transaction-owned changes. Concurrent untouched rows survive;
/// a changed row wins last, as in the published memory adapter. This is not
/// serializable isolation across workflow awaits.
fn merge<T: Clone + PartialEq>(
    live: &mut indexmap::IndexMap<String, T>,
    base: &indexmap::IndexMap<String, T>,
    changed: indexmap::IndexMap<String, T>,
) {
    live.retain(|id, _| !base.contains_key(id) || changed.contains_key(id));
    for (id, row) in changed {
        if base.get(&id) == Some(&row) {
            continue;
        }
        // Published merge walks live rows first, then appends only new IDs.
        // A base row concurrently deleted from live must stay deleted.
        if live.contains_key(&id) || !base.contains_key(&id) {
            _ = live.insert(id, row);
        }
    }
}

struct OrganizationTransaction<'a> {
    live: &'a StatelessStore,
    snapshot: StatelessStore,
}

#[async_trait]
impl TransactionStore<StatelessSchema> for StatelessStore {
    async fn transaction_boxed(
        &self,
        work: Box<TransactionWork<StatelessSchema>>,
    ) -> AuthResult<BoxedTransactionValue> {
        let base = self.organization_state()?.clone();
        let tx = OrganizationTransaction {
            live: self,
            snapshot: Self {
                organizations: std::sync::Mutex::new(base.clone()),
                ..Self::with_find_many_limit(self.find_many_limit)
            },
        };
        let result = work(&tx).await?;
        let changed = tx
            .snapshot
            .organizations
            .into_inner()
            .map_err(|_| AuthError::internal("No-database organization state poisoned"))?;
        let mut live = self.organization_state()?;
        merge(
            &mut live.organizations,
            &base.organizations,
            changed.organizations,
        );
        merge(&mut live.members, &base.members, changed.members);
        merge(
            &mut live.invitations,
            &base.invitations,
            changed.invitations,
        );
        merge(&mut live.teams, &base.teams, changed.teams);
        merge(
            &mut live.team_members,
            &base.team_members,
            changed.team_members,
        );
        merge(&mut live.roles, &base.roles, changed.roles);
        Ok(result)
    }
}

#[async_trait]
impl AuthTransaction<StatelessSchema> for OrganizationTransaction<'_> {
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
            self.live, input, persist,
        )
        .await
    }
    async fn prepare_secondary_session_update(
        &self,
        session: SessionView,
        expires_at: Option<DateTime<Utc>>,
        fields: crate::field_policy::FieldValues,
    ) -> AuthResult<Option<(SessionView, crate::field_policy::FieldValues)>> {
        SessionStore::<StatelessSchema>::prepare_secondary_session_update(
            self.live, session, expires_at, fields,
        )
        .await
    }
    async fn complete_secondary_session_update(
        &self,
        session: SessionView,
        expires_at: Option<DateTime<Utc>>,
        fields: crate::field_policy::FieldValues,
        persist: bool,
    ) -> AuthResult<Option<SessionView>> {
        SessionStore::<StatelessSchema>::complete_secondary_session_update(
            self.live, session, expires_at, fields, persist,
        )
        .await
    }
    // Preserve existing identity provisioning behavior. This scoped transaction
    // stages organization rows only; cookie/secondary sessions belong to the wrapper.
    async fn create_user(&self, data: CreateUser) -> AuthResult<UserView> {
        UserStore::<StatelessSchema>::create_user(self.live, data).await
    }
    async fn create_user_prepared(&self, data: PreparedUserCreation) -> AuthResult<UserView> {
        UserStore::<StatelessSchema>::create_user_prepared(self.live, data).await
    }
    async fn create_account(&self, data: CreateAccount) -> AuthResult<AccountView> {
        AccountStore::<StatelessSchema>::create_account(self.live, data).await
    }
    async fn create_session(&self, data: CreateSession) -> AuthResult<SessionView> {
        SessionStore::<StatelessSchema>::create_session(self.live, data).await
    }
}
