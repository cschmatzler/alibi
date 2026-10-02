use super::entities::{invitation, team, team_member};
use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{TeamStore, team_membership_key};
use better_auth_core::types::{AddTeamMemberResult, CreateTeam, Team, TeamMember, UpdateTeam};
use chrono::Utc;
use sea_orm::ExprTrait;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use uuid::Uuid;

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    pub(super) async fn get_team_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        organization_id: Option<&str>,
        team_id: &str,
    ) -> AuthResult<Option<Team>> {
        let mut query = team::Entity::find_by_id(team_id.to_owned());
        if let Some(org) = organization_id {
            query = query.filter(team::Column::OrganizationId.eq(org));
        }
        query
            .one(connection)
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }

    pub(super) async fn add_team_member_in_tx(
        &self,
        tx: &sea_orm::DatabaseTransaction,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult> {
        let id = S::User::parse_id(user_id)?;
        if <S::User as SeaOrmUserModel>::Entity::find()
            .filter(S::User::id_column().eq(id))
            .lock_shared()
            .one(tx)
            .await
            .map_err(map_db_err)?
            .is_none()
        {
            return Err(AuthError::UserNotFound);
        }
        let room = team::Entity::find_by_id(team_id.to_owned())
            .lock_exclusive()
            .one(tx)
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        let existing = team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .filter(team_member::Column::UserId.eq(user_id))
            .one(tx)
            .await
            .map_err(map_db_err)?;
        if let Some(member) = existing {
            return Ok(AddTeamMemberResult::Existing(member.into()));
        }
        let count = team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .count(tx)
            .await
            .map_err(map_db_err)?;
        if maximum
            .map(u64::try_from)
            .transpose()
            .map_err(|_error| AuthError::internal("Team capacity exceeds u64"))?
            .is_some_and(|max| count >= max)
        {
            return Ok(AddTeamMemberResult::LimitReached);
        }
        let key = team_membership_key(team_id, user_id)?;
        let member = team_member::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            team_id: Set(team_id.to_owned()),
            user_id: Set(user_id.to_owned()),
            membership_key: Set(Some(key)),
            created_at: Set(Utc::now()),
        }
        .insert(tx)
        .await
        .map_err(map_db_err)?;
        let mut active = room.into_active_model();
        active.member_count = Set(i64::try_from(count + 1)
            .map_err(|_error| AuthError::internal("Team membership count overflow"))?);
        drop(active.update(tx).await.map_err(map_db_err)?);
        Ok(AddTeamMemberResult::Added(member.into()))
    }
}

#[async_trait]
impl<S> TeamStore for SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    async fn create_team(&self, data: CreateTeam) -> AuthResult<Team> {
        let now = data.updated_at.unwrap_or_else(Utc::now);
        team::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            name: Set(data.name),
            organization_id: Set(data.organization_id),
            member_count: Set(0),
            created_at: Set(now),
            updated_at: Set(data.updated_at),
        }
        .insert(self.connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
    async fn get_team(
        &self,
        organization_id: Option<&str>,
        team_id: &str,
    ) -> AuthResult<Option<Team>> {
        self.get_team_with_connection(self.connection(), organization_id, team_id)
            .await
    }
    async fn list_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        team::Entity::find()
            .filter(team::Column::OrganizationId.eq(organization_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn update_team(
        &self,
        organization_id: &str,
        team_id: &str,
        update: UpdateTeam,
    ) -> AuthResult<Team> {
        let model = team::Entity::find_by_id(team_id.to_owned())
            .filter(team::Column::OrganizationId.eq(organization_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        let mut active = model.into_active_model();
        if let Some(name) = update.name {
            active.name = Set(name);
        }
        active.updated_at = Set(Some(Utc::now()));
        active
            .update(self.connection())
            .await
            .map(Into::into)
            .map_err(map_db_err)
    }
    async fn delete_team(&self, organization_id: &str, team_id: &str) -> AuthResult<bool> {
        let tx = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let deleted = team::Entity::delete_many()
            .filter(team::Column::Id.eq(team_id))
            .filter(team::Column::OrganizationId.eq(organization_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        if deleted.rows_affected == 0 {
            tx.commit().await.map_err(map_db_err)?;
            return Ok(false);
        }
        let _ignored_map_err = team_member::Entity::delete_many()
            .filter(team_member::Column::TeamId.eq(team_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?;
        let pending = invitation::Entity::find()
            .filter(invitation::Column::OrganizationId.eq(organization_id))
            .filter(invitation::Column::Status.eq("pending"))
            .filter(invitation::Column::ExpiresAt.gt(Utc::now()))
            .all(&tx)
            .await
            .map_err(map_db_err)?;
        for invite in pending {
            let Some(ids) = invite.team_id.as_deref() else {
                continue;
            };
            if !ids.split(',').any(|id| id == team_id) {
                continue;
            }
            let remaining = ids
                .split(',')
                .filter(|id| *id != team_id)
                .collect::<Vec<_>>()
                .join(",");
            let mut active = invite.into_active_model();
            active.team_id = Set((!remaining.is_empty()).then_some(remaining));
            drop(active.update(&tx).await.map_err(map_db_err)?);
        }
        tx.commit().await.map_err(map_db_err)?;
        Ok(true)
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .filter(team_member::Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<usize>,
    ) -> AuthResult<AddTeamMemberResult> {
        let tx = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let result = self
            .add_team_member_in_tx(&tx, team_id, user_id, maximum)
            .await?;
        tx.commit().await.map_err(map_db_err)?;
        Ok(result)
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<usize> {
        let tx = self
            .connection()
            .begin_with_options(TransactionOptions {
                sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        drop(
            team::Entity::find_by_id(team_id.to_owned())
                .lock_exclusive()
                .one(&tx)
                .await
                .map_err(map_db_err)?,
        );
        let removed = team_member::Entity::delete_many()
            .filter(team_member::Column::TeamId.eq(team_id))
            .filter(team_member::Column::UserId.eq(user_id))
            .exec(&tx)
            .await
            .map_err(map_db_err)?
            .rows_affected;
        let count = i64::try_from(removed)
            .map_err(|_error| AuthError::internal("Team membership count overflow"))?;
        if count > 0 {
            let _ignored_map_err_2 = team::Entity::update_many()
                .filter(team::Column::Id.eq(team_id))
                .filter(team::Column::MemberCount.gte(count))
                .col_expr(
                    team::Column::MemberCount,
                    sea_orm::sea_query::Expr::col(team::Column::MemberCount).sub(count),
                )
                .exec(&tx)
                .await
                .map_err(map_db_err)?;
        }
        tx.commit().await.map_err(map_db_err)?;
        usize::try_from(removed)
            .map_err(|_error| AuthError::internal("Team membership count overflow"))
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        team_member::Entity::find()
            .filter(team_member::Column::TeamId.eq(team_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let memberships = team_member::Entity::find()
            .filter(team_member::Column::UserId.eq(user_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
        if memberships.is_empty() {
            return Ok(Vec::new());
        }
        let rooms = team::Entity::find()
            .filter(team::Column::Id.is_in(memberships.iter().map(|row| row.team_id.clone())))
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|row| (row.id.clone(), row))
            .collect::<std::collections::HashMap<_, _>>();
        // The upstream join maps membership rows directly, preserving their
        // adapter order. An IN query's team order must not replace that order.
        Ok(memberships
            .into_iter()
            .filter_map(|membership| rooms.get(&membership.team_id).cloned().map(Into::into))
            .collect())
    }
}

/// Delete owned memberships and release exactly the seats those rows occupied.
pub(super) async fn remove_owned_team_members(
    connection: &sea_orm::DatabaseTransaction,
    user_id: &str,
    organization_id: Option<&str>,
) -> AuthResult<()> {
    use sea_orm_migration::SchemaManager;
    if !SchemaManager::new(connection)
        .has_table("team_member")
        .await
        .map_err(map_db_err)?
    {
        return Ok(());
    }
    let mut teams = team::Entity::find();
    if let Some(org) = organization_id {
        teams = teams.filter(team::Column::OrganizationId.eq(org));
    }
    let rooms = teams
        .order_by_asc(team::Column::Id)
        .lock_exclusive()
        .all(connection)
        .await
        .map_err(map_db_err)?;
    release_owned_team_members(connection, user_id, rooms).await
}

/// Remove memberships from an already selected adapter page and release seats.
pub(super) async fn release_owned_team_members(
    connection: &sea_orm::DatabaseTransaction,
    user_id: &str,
    rooms: Vec<team::Model>,
) -> AuthResult<()> {
    for room in rooms {
        let deleted = team_member::Entity::delete_many()
            .filter(team_member::Column::TeamId.eq(&room.id))
            .filter(team_member::Column::UserId.eq(user_id))
            .exec(connection)
            .await
            .map_err(map_db_err)?;
        if deleted.rows_affected > 0 {
            let count = i64::try_from(deleted.rows_affected)
                .map_err(|_error| AuthError::internal("Team membership count overflow"))?;
            let _ignored_map_err = team::Entity::update_many()
                .filter(team::Column::Id.eq(&room.id))
                .filter(team::Column::MemberCount.gte(count))
                .col_expr(
                    team::Column::MemberCount,
                    sea_orm::sea_query::Expr::col(team::Column::MemberCount).sub(count),
                )
                .exec(connection)
                .await
                .map_err(map_db_err)?;
        }
    }
    Ok(())
}

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{bundled_schema::BundledSchema, migrator::run_migrations};
    use better_auth_core::AuthConfig;
    use better_auth_core::entity::{AuthSession, AuthUser};
    use better_auth_core::store::{
        InvitationStore, MemberStore, OrganizationRoleStore, OrganizationStore, SessionStore,
        UserStore,
    };
    use better_auth_core::types::{
        CreateInvitation, CreateMember, CreateOrganization, CreateOrganizationRole, CreateSession,
        CreateUser, InvitationStatus, OrganizationRoleSelector, UpdateOrganizationRole,
    };
    use chrono::Duration;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection};
    use std::sync::Arc;
    use tokio::{sync::Barrier, task::JoinSet};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    async fn memory_store() -> Result<SeaOrmStore<BundledSchema>, Box<dyn std::error::Error>> {
        let database = Database::connect("sqlite::memory:").await?;
        run_migrations(&database).await?;
        Ok(SeaOrmStore::new(
            AuthConfig::new("organization-storage-local-test-secret-32-chars"),
            database,
        ))
    }

    async fn organization(store: &SeaOrmStore<BundledSchema>, slug: &str) -> AuthResult<String> {
        Ok(store
            .create_organization(CreateOrganization::new(slug, slug))
            .await?
            .id)
    }

    async fn user(store: &SeaOrmStore<BundledSchema>, prefix: &str) -> AuthResult<String> {
        Ok(store
            .create_user(CreateUser::new().with_email(format!("{prefix}@example.com")))
            .await?
            .id()
            .into_owned())
    }

    async fn room(
        store: &SeaOrmStore<BundledSchema>,
        organization_id: &str,
        name: &str,
    ) -> AuthResult<Team> {
        store
            .create_team(CreateTeam {
                name: name.to_owned(),
                organization_id: organization_id.to_owned(),
                updated_at: None,
            })
            .await
    }

    async fn session(store: &SeaOrmStore<BundledSchema>, user_id: &str) -> AuthResult<String> {
        Ok(store
            .create_session(CreateSession {
                additional_fields: better_auth_core::field_policy::FieldValues::default(),
                token: None,
                user_id: user_id.to_owned(),
                expires_at: Utc::now() + Duration::hours(1),
                ip_address: None,
                user_agent: None,
                impersonated_by: None,
                active_organization_id: None,
                active_team_id: None,
            })
            .await?
            .token()
            .to_owned())
    }

    async fn invite(
        store: &SeaOrmStore<BundledSchema>,
        organization_id: &str,
        inviter_id: &str,
        email: &str,
        teams: &[&str],
    ) -> AuthResult<better_auth_core::types::Invitation> {
        let mut data = CreateInvitation::new(
            organization_id,
            email,
            "member",
            inviter_id,
            Utc::now() + Duration::hours(1),
        );
        data.team_id = (!teams.is_empty()).then(|| teams.join(","));
        store.create_invitation(data).await
    }

    async fn stored_count(store: &SeaOrmStore<BundledSchema>, team_id: &str) -> AuthResult<i64> {
        Ok(store
            .get_team(None, team_id)
            .await?
            .ok_or_else(|| AuthError::internal("Team disappeared"))?
            .member_count)
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn configured_query_limit_bounds_public_lists_without_truncating_owned_deletion()
    -> TestResult {
        let store = memory_store().await?;
        let mut config = store.config().as_ref().clone();
        config.advanced.database.default_find_many_limit = 2;
        let limited = SeaOrmStore::<BundledSchema>::new(config, store.connection().clone());
        let org = organization(&store, "configured-query-limit").await?;
        let principal = user(&store, "query-limit-principal").await?;
        let first = room(&store, &org, "First").await?;
        let second = room(&store, &org, "Second").await?;
        let third = room(&store, &org, "Third").await?;
        for team in [&third, &first, &second] {
            drop(store.add_team_member(&team.id, &principal, None).await?);
        }
        for prefix in ["limit-other-one", "limit-other-two"] {
            let member = user(&store, prefix).await?;
            drop(store.add_team_member(&first.id, &member, None).await?);
        }
        for name in ["first-role", "second-role", "third-role"] {
            drop(
                store
                    .create_organization_role(CreateOrganizationRole {
                        organization_id: org.clone(),
                        role: name.to_owned(),
                        permission: better_auth_core::OrganizationPermissions::default(),
                    })
                    .await?,
            );
        }
        assert_eq!(
            limited
                .list_teams(&org)
                .await?
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["First", "Second"]
        );
        assert_eq!(limited.list_team_members(&first.id).await?.len(), 2);
        assert_eq!(
            limited
                .list_user_teams(&principal)
                .await?
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Third", "First"]
        );
        assert_eq!(
            limited
                .list_organization_roles(&org)
                .await?
                .iter()
                .map(|row| row.role.as_str())
                .collect::<Vec<_>>(),
            vec!["first-role", "second-role"]
        );
        assert_eq!(limited.count_organization_roles(&org).await?, 3);
        assert_eq!(stored_count(&limited, &first.id).await?, 3);
        limited.delete_user(&principal).await?;
        for team in [&first, &second, &third] {
            assert!(store.get_team_member(&team.id, &principal).await?.is_none());
        }
        assert_eq!(stored_count(&store, &first.id).await?, 2);
        assert_eq!(stored_count(&store, &second.id).await?, 0);
        assert_eq!(stored_count(&store, &third.id).await?, 0);
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
    async fn invitation_acceptance_is_atomic_for_capacity_identity_and_tenant_failures()
    -> TestResult {
        let store = memory_store().await?;
        let org = organization(&store, "compound-invitation").await?;
        let other_org = organization(&store, "other-organization").await?;
        let inviter = user(&store, "inviter").await?;
        let recipient = user(&store, "invitee").await?;
        let wrong_user = user(&store, "wrong-user").await?;
        let blocker = user(&store, "seat-blocker").await?;
        let first = room(&store, &org, "First").await?;
        let second = room(&store, &org, "Second").await?;
        let foreign = room(&store, &other_org, "Foreign").await?;
        let token = session(&store, &recipient).await?;
        let wrong_token = session(&store, &wrong_user).await?;
        let invitation = invite(
            &store,
            &org,
            &inviter,
            "invitee@example.com",
            &[&first.id, &second.id],
        )
        .await?;
        drop(store.add_team_member(&second.id, &blocker, Some(1)).await?);
        let limits = vec![(first.id.clone(), Some(1)), (second.id.clone(), Some(1))];

        assert!(
            store
                .accept_invitation_with_teams(&invitation.id, &recipient, &token, &limits, None)
                .await
                .is_err()
        );
        assert!(
            store
                .get_team_member(&first.id, &recipient)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&second.id, &recipient)
                .await?
                .is_none()
        );
        assert!(store.get_member(&org, &recipient).await?.is_none());
        assert_eq!(stored_count(&store, &first.id).await?, 0);
        assert_eq!(stored_count(&store, &second.id).await?, 1);
        assert_eq!(
            store
                .get_invitation_by_id(&invitation.id)
                .await?
                .map(|row| row.status),
            Some(InvitationStatus::Pending)
        );
        let unchanged = store
            .get_session(&token)
            .await?
            .ok_or_else(|| std::io::Error::other("Session disappeared"))?;
        assert!(unchanged.active_organization_id().is_none());
        assert!(unchanged.active_team_id().is_none());

        let tenant_invitation = invite(
            &store,
            &org,
            &inviter,
            "invitee@example.com",
            &[&first.id, &foreign.id],
        )
        .await?;
        assert!(
            store
                .accept_invitation_with_teams(&tenant_invitation.id, &recipient, &token, &[], None)
                .await
                .is_err()
        );
        assert!(
            store
                .get_team_member(&first.id, &recipient)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&foreign.id, &recipient)
                .await?
                .is_none()
        );
        assert_eq!(
            store
                .get_invitation_by_id(&tenant_invitation.id)
                .await?
                .map(|row| row.status),
            Some(InvitationStatus::Pending)
        );

        assert_eq!(store.remove_team_member(&second.id, &blocker).await?, 1);
        // Available seats ensure these failures prove ownership and session
        // checks, rather than accidentally succeeding at a later capacity guard.
        assert!(matches!(
            store.accept_invitation_with_teams(&invitation.id, &wrong_user, &wrong_token, &limits, None).await,
            Err(AuthError::Forbidden(message)) if message == "This invitation is not for you"
        ));
        assert!(matches!(
            store
                .accept_invitation_with_teams(
                    &invitation.id,
                    &recipient,
                    &wrong_token,
                    &limits,
                    None
                )
                .await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(store.get_member(&org, &wrong_user).await?.is_none());
        assert!(
            store
                .get_team_member(&first.id, &wrong_user)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&second.id, &wrong_user)
                .await?
                .is_none()
        );
        let wrong_session = store
            .get_session(&wrong_token)
            .await?
            .ok_or_else(|| std::io::Error::other("Wrong-user session disappeared"))?;
        assert!(wrong_session.active_organization_id().is_none());
        assert!(wrong_session.active_team_id().is_none());

        let expired_token = session(&store, &recipient).await?;
        let _ignored_connection = crate::store::entities::session::Entity::update_many()
            .filter(crate::store::entities::session::Column::Token.eq(&expired_token))
            .col_expr(
                crate::store::entities::session::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(Utc::now() - Duration::minutes(1)),
            )
            .exec(store.connection())
            .await?;
        assert!(matches!(
            store
                .accept_invitation_with_teams(
                    &invitation.id,
                    &recipient,
                    &expired_token,
                    &limits,
                    None
                )
                .await,
            Err(AuthError::SessionNotFound)
        ));
        // A persisted, revoked session cannot authorize the compound transition.
        // Capacity is available here so a missing active predicate cannot hide
        // behind the team's capacity rejection.
        let revoked_token = session(&store, &recipient).await?;
        let _ignored_connection_2 = crate::store::entities::session::Entity::update_many()
            .filter(crate::store::entities::session::Column::Token.eq(&revoked_token))
            .col_expr(
                crate::store::entities::session::Column::Active,
                sea_orm::sea_query::Expr::value(false),
            )
            .exec(store.connection())
            .await?;
        assert!(matches!(
            store
                .accept_invitation_with_teams(
                    &invitation.id,
                    &recipient,
                    &revoked_token,
                    &limits,
                    None
                )
                .await,
            Err(AuthError::SessionNotFound)
        ));
        assert!(store.get_member(&org, &recipient).await?.is_none());
        assert!(
            store
                .get_team_member(&first.id, &recipient)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&second.id, &recipient)
                .await?
                .is_none()
        );
        assert_eq!(
            store
                .get_invitation_by_id(&invitation.id)
                .await?
                .map(|row| row.status),
            Some(InvitationStatus::Pending)
        );
        let accepted = store
            .accept_invitation_with_teams(&invitation.id, &recipient, &token, &limits, None)
            .await?
            .ok_or_else(|| std::io::Error::other("Invitation was not accepted"))?;
        assert_eq!(accepted.0.status, InvitationStatus::Accepted);
        assert_eq!(accepted.1.organization_id, org);
        assert_eq!(accepted.1.user_id, recipient);
        assert_eq!(stored_count(&store, &first.id).await?, 1);
        assert_eq!(stored_count(&store, &second.id).await?, 1);
        assert!(
            store
                .get_team_member(&first.id, &recipient)
                .await?
                .is_some()
        );
        assert!(
            store
                .get_team_member(&second.id, &recipient)
                .await?
                .is_some()
        );
        let changed = store
            .get_session(&token)
            .await?
            .ok_or_else(|| std::io::Error::other("Session disappeared"))?;
        assert_eq!(changed.active_organization_id(), Some(org.as_str()));
        assert!(changed.active_team_id().is_none());
        assert!(
            store
                .accept_invitation_with_teams(&invitation.id, &recipient, &token, &limits, None)
                .await?
                .is_none()
        );
        assert_eq!(store.list_organization_members(&org).await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn invitation_expiry_and_membership_limit_preserve_pending_state_and_single_team_updates_session()
    -> TestResult {
        let store = memory_store().await?;
        let org = organization(&store, "single-team-invitation").await?;
        let inviter = user(&store, "single-inviter").await?;
        let recipient = user(&store, "single-invitee").await?;
        let team = room(&store, &org, "Only").await?;
        let token = session(&store, &recipient).await?;
        let expired = store
            .create_invitation(CreateInvitation::new(
                &org,
                "single-invitee@example.com",
                "member",
                &inviter,
                Utc::now() - Duration::minutes(1),
            ))
            .await?;
        assert!(
            store
                .accept_invitation_with_teams(&expired.id, &recipient, &token, &[], None)
                .await?
                .is_none()
        );
        let invitation = invite(
            &store,
            &org,
            &inviter,
            "single-invitee@example.com",
            &[&team.id],
        )
        .await?;
        assert!(
            store
                .accept_invitation_with_teams(&invitation.id, &recipient, &token, &[], Some(0))
                .await
                .is_err()
        );
        assert!(store.list_team_members(&team.id).await?.is_empty());
        assert_eq!(
            store
                .get_invitation_by_id(&invitation.id)
                .await?
                .map(|row| row.status),
            Some(InvitationStatus::Pending)
        );
        drop(
            store
                .accept_invitation_with_teams(&invitation.id, &recipient, &token, &[], Some(1))
                .await?
                .ok_or_else(|| std::io::Error::other("Expected accepted invitation"))?,
        );
        let persisted = store
            .get_session(&token)
            .await?
            .ok_or_else(|| std::io::Error::other("Session disappeared"))?;
        assert_eq!(persisted.active_team_id(), Some(team.id.as_str()));
        assert_eq!(persisted.active_organization_id(), Some(org.as_str()));
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn deleting_team_prunes_only_live_pending_invitation_links() -> TestResult {
        let store = memory_store().await?;
        let org = organization(&store, "team-delete").await?;
        let other_org = organization(&store, "team-delete-other").await?;
        let inviter = user(&store, "delete-inviter").await?;
        let first = room(&store, &org, "First").await?;
        let remaining = room(&store, &org, "Remaining").await?;
        let linked = invite(
            &store,
            &org,
            &inviter,
            "linked@example.com",
            &[&first.id, &remaining.id],
        )
        .await?;
        let only = invite(&store, &org, &inviter, "only@example.com", &[&first.id]).await?;
        let accepted = invite(&store, &org, &inviter, "accepted@example.com", &[&first.id]).await?;
        drop(
            store
                .update_invitation_status(&accepted.id, InvitationStatus::Accepted)
                .await?,
        );
        let mut expired_data = CreateInvitation::new(
            &org,
            "expired@example.com",
            "member",
            &inviter,
            Utc::now() - Duration::minutes(1),
        );
        expired_data.team_id = Some(first.id.clone());
        let expired = store.create_invitation(expired_data).await?;
        drop(store.add_team_member(&first.id, &inviter, None).await?);
        assert!(!store.delete_team(&other_org, &first.id).await?);
        assert!(store.get_team(Some(&org), &first.id).await?.is_some());
        assert!(store.delete_team(&org, &first.id).await?);
        assert!(store.list_team_members(&first.id).await?.is_empty());
        assert_eq!(
            store
                .get_invitation_by_id(&linked.id)
                .await?
                .and_then(|row| row.team_id),
            Some(remaining.id)
        );
        assert_eq!(
            store
                .get_invitation_by_id(&only.id)
                .await?
                .and_then(|row| row.team_id),
            None
        );
        assert_eq!(
            store
                .get_invitation_by_id(&accepted.id)
                .await?
                .and_then(|row| row.team_id),
            Some(first.id.clone())
        );
        assert_eq!(
            store
                .get_invitation_by_id(&expired.id)
                .await?
                .and_then(|row| row.team_id),
            Some(first.id)
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn member_and_user_deletion_clean_team_links_and_release_capacity() -> TestResult {
        let store = memory_store().await?;
        let first_org = organization(&store, "cleanup-first").await?;
        let second_org = organization(&store, "cleanup-second").await?;
        let principal = user(&store, "cleanup-principal").await?;
        let replacement = user(&store, "cleanup-replacement").await?;
        let first_member = store
            .create_member(CreateMember::new(&first_org, &principal, "member"))
            .await?;
        drop(
            store
                .create_member(CreateMember::new(&second_org, &principal, "member"))
                .await?,
        );
        let first = room(&store, &first_org, "First").await?;
        let second = room(&store, &second_org, "Second").await?;
        drop(
            store
                .add_team_member(&second.id, &principal, Some(1))
                .await?,
        );
        drop(
            store
                .add_team_member(&first.id, &principal, Some(1))
                .await?,
        );
        // Joined user-team lists follow membership insertion, even when team
        // creation order differs. Sorting the teams would change this contract.
        assert_eq!(
            store
                .list_user_teams(&principal)
                .await?
                .iter()
                .map(|team| team.id.as_str())
                .collect::<Vec<_>>(),
            vec![second.id.as_str(), first.id.as_str()]
        );
        store.delete_member(&first_member.id).await?;
        assert!(
            store
                .get_team_member(&first.id, &principal)
                .await?
                .is_none()
        );
        assert!(
            store
                .get_team_member(&second.id, &principal)
                .await?
                .is_some()
        );
        assert_eq!(stored_count(&store, &first.id).await?, 0);
        assert_eq!(stored_count(&store, &second.id).await?, 1);
        assert!(matches!(
            store
                .add_team_member(&first.id, &replacement, Some(1))
                .await?,
            AddTeamMemberResult::Added(_)
        ));
        store.delete_user(&principal).await?;
        assert!(store.list_user_teams(&principal).await?.is_empty());
        assert_eq!(stored_count(&store, &second.id).await?, 0);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    async fn dynamic_roles_scope_reads_and_mutations_and_persist_json_permission_values()
    -> TestResult {
        let store = memory_store().await?;
        let org = organization(&store, "role-storage").await?;
        let foreign = organization(&store, "role-storage-foreign").await?;
        let role = store
            .create_organization_role(CreateOrganizationRole {
                organization_id: org.clone(),
                role: "manager".to_owned(),
                permission: [(
                    "team".to_owned(),
                    vec!["create".to_owned(), "update".to_owned()],
                )]
                .into(),
            })
            .await?;
        assert!(role.updated_at.is_none());
        let selector = OrganizationRoleSelector::Id(role.id.clone());
        assert!(
            store
                .get_organization_role(&foreign, &selector)
                .await?
                .is_none()
        );
        assert!(!store.delete_organization_role(&foreign, &selector).await?);
        assert!(
            store
                .update_organization_role(
                    &foreign,
                    &selector,
                    UpdateOrganizationRole {
                        role: Some("renamed".to_owned()),
                        permission: None
                    }
                )
                .await
                .is_err()
        );
        let updated = store
            .update_organization_role(
                &org,
                &selector,
                UpdateOrganizationRole {
                    role: Some("renamed".to_owned()),
                    permission: Some([("member".to_owned(), vec!["update".to_owned()])].into()),
                },
            )
            .await?;
        assert_eq!(updated.role, "renamed");
        assert!(
            updated
                .updated_at
                .is_some_and(|timestamp| timestamp >= role.created_at)
        );
        assert!(
            store
                .get_organization_role(&org, &OrganizationRoleSelector::Name("manager".to_owned()))
                .await?
                .is_none()
        );
        let raw = super::super::entities::organization_role::Entity::find_by_id(role.id.clone())
            .one(store.connection())
            .await?
            .ok_or_else(|| std::io::Error::other("Role disappeared"))?;
        assert_eq!(raw.permission, r#"{"member":["update"]}"#);
        assert!(
            store
                .delete_organization_role(
                    &org,
                    &OrganizationRoleSelector::Name("renamed".to_owned())
                )
                .await?
        );
        assert!(store.list_organization_roles(&org).await?.is_empty());
        Ok(())
    }

    // These requests use independent connection pools. The seat limit and one-use
    // invitation transition must be enforced by SQL across service instances.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions report test failures; Result propagates setup and fixture errors"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn independent_stores_enforce_team_capacity_and_one_invitation_acceptance_winner()
    -> TestResult {
        let directory =
            std::env::temp_dir().join(format!("better-auth-team-race-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory)?;
        let outcome = async {
            let url = format!(
                "sqlite://{}?mode=rwc",
                directory.join("auth.sqlite").display()
            );
            let mut databases: Vec<DatabaseConnection> = Vec::new();
            let mut stores = Vec::new();
            for index in 0..8 {
                let mut options = ConnectOptions::new(url.clone());
                let _ignored_max_connections = options.min_connections(1).max_connections(1);
                let database = Database::connect(options).await?;
                if index == 0 {
                    run_migrations(&database).await?;
                }
                stores.push(Arc::new(SeaOrmStore::<BundledSchema>::new(
                    AuthConfig::new("organization-race-local-test-secret-32-chars"),
                    database.clone(),
                )));
                databases.push(database);
            }
            let primary = stores
                .first()
                .ok_or_else(|| std::io::Error::other("Missing primary store"))?;
            let org = organization(primary, "team-race").await?;
            let team = room(primary, &org, "Capacity").await?;
            let mut user_ids = Vec::new();
            for index in 0..8 {
                user_ids.push(user(primary, &format!("seat-{index}")).await?);
            }
            let barrier = Arc::new(Barrier::new(8));
            let mut tasks = JoinSet::new();
            for (store, user_id) in stores.iter().zip(&user_ids) {
                let store = Arc::clone(store);
                let user_id = user_id.clone();
                let team_id = team.id.clone();
                let barrier = Arc::clone(&barrier);
                drop(tasks.spawn(async move {
                    let _ignored_wait = barrier.wait().await;
                    store.add_team_member(&team_id, &user_id, Some(2)).await
                }));
            }
            let mut admitted = Vec::new();
            let mut rejected = 0;
            while let Some(result) = tasks.join_next().await {
                match result?? {
                    AddTeamMemberResult::Added(row) => admitted.push(row),
                    AddTeamMemberResult::LimitReached => rejected += 1,
                    AddTeamMemberResult::Existing(_) => {
                        return Err(std::io::Error::other("Unexpected existing membership").into());
                    }
                }
            }
            assert_eq!(admitted.len(), 2);
            assert_eq!(rejected, 6);
            assert_eq!(stored_count(primary, &team.id).await?, 2);
            assert_eq!(primary.list_team_members(&team.id).await?.len(), 2);
            assert_eq!(
                admitted
                    .iter()
                    .filter_map(|row| row.membership_key.as_deref())
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                2
            );
            for membership in &admitted {
                let AddTeamMemberResult::Existing(existing) = primary
                    .add_team_member(&team.id, &membership.user_id, Some(2))
                    .await?
                else {
                    return Err(std::io::Error::other(
                        "Repeated admission created a second membership",
                    )
                    .into());
                };
                assert_eq!(existing.id, membership.id);
                assert_eq!(existing.membership_key, membership.membership_key);
            }
            assert_eq!(stored_count(primary, &team.id).await?, 2);
            let first = admitted
                .first()
                .ok_or_else(|| std::io::Error::other("Missing winner"))?;
            assert_eq!(
                primary.remove_team_member(&team.id, &first.user_id).await?,
                1
            );
            assert_eq!(
                primary.remove_team_member(&team.id, &first.user_id).await?,
                0
            );
            assert_eq!(stored_count(primary, &team.id).await?, 1);
            assert!(matches!(
                primary
                    .add_team_member(&team.id, &first.user_id, Some(2))
                    .await?,
                AddTeamMemberResult::Added(_)
            ));
            let invitee = user(primary, "race-invitee").await?;
            let sender = user_ids
                .first()
                .ok_or_else(|| std::io::Error::other("Missing inviter"))?;
            let target = room(primary, &org, "Invitation").await?;
            let invitation = invite(
                primary,
                &org,
                sender,
                "race-invitee@example.com",
                &[&target.id],
            )
            .await?;
            let token = session(primary, &invitee).await?;
            let barrier_2 = Arc::new(Barrier::new(8));
            let mut tasks_2 = JoinSet::new();
            for store in &stores {
                let store = Arc::clone(store);
                let barrier_2_3 = Arc::clone(&barrier_2);
                let invite_id = invitation.id.clone();
                let user_id = invitee.clone();
                let token = token.clone();
                let team_id = target.id.clone();
                drop(tasks_2.spawn(async move {
                    let _ignored_wait_2 = barrier_2_3.wait().await;
                    store
                        .accept_invitation_with_teams(
                            &invite_id,
                            &user_id,
                            &token,
                            &[(team_id, Some(1))],
                            None,
                        )
                        .await
                }));
            }
            let mut winners = 0;
            while let Some(result) = tasks_2.join_next().await {
                if result??.is_some() {
                    winners += 1;
                }
            }
            assert_eq!(winners, 1);
            assert_eq!(primary.list_organization_members(&org).await?.len(), 1);
            assert_eq!(primary.list_team_members(&target.id).await?.len(), 1);
            assert_eq!(stored_count(primary, &target.id).await?, 1);
            assert_eq!(
                primary
                    .get_invitation_by_id(&invitation.id)
                    .await?
                    .map(|row| row.status),
                Some(InvitationStatus::Accepted)
            );
            for database in databases {
                database.close().await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        std::fs::remove_dir_all(directory)?;
        outcome
    }
}
// LCOV_EXCL_STOP
