use super::entities::{invitation, team, team_member};
use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::{TeamStore, team_membership_key};
use alibi_core::types::{AddTeamMemberResult, CreateTeam, Team, TeamMember, UpdateTeam};
use async_trait::async_trait;
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
        tx: &super::ScopedTransaction,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        let id = S::User::parse_id(user_id)?;
        if super::users::user_query::<S::User>(sea_orm::ConnectionTrait::get_database_backend(tx))
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
        // Sync upward exactly as Source does, then let the database compare
        // its durable counter to the raw policy. Do not round/cap query values.
        let reserved_count = std::cmp::max(
            i64::try_from(count)
                .map_err(|_error| AuthError::internal("Team membership count overflow"))?,
            room.member_count,
        );
        let mut active = room.into_active_model();
        active.member_count = Set(reserved_count);
        let room = active.update(tx).await.map_err(map_db_err)?;
        if let Some(maximum) = maximum {
            let predicate = if tx.get_database_backend() == sea_orm::DbBackend::Postgres {
                // Source's text Number parameter is parsed as the physical
                // bigint counter, rather than promoting that counter to float8.
                sea_orm::sea_query::Expr::col(team::Column::MemberCount).lt(
                    sea_orm::sea_query::Expr::cust_with_values(
                        "$1::bigint",
                        [ryu_js::Buffer::new().format(maximum).to_owned()],
                    ),
                )
            } else {
                team::Column::MemberCount.lt(maximum)
            };
            let available = team::Entity::find_by_id(team_id.to_owned())
                .filter(predicate)
                .one(tx)
                .await
                .map_err(map_db_err)?;
            if available.is_none() {
                return Ok(AddTeamMemberResult::LimitReached);
            }
        }
        let key = team_membership_key(team_id, user_id)?;
        let member = team_member::ActiveModel {
            id: Set(self
                .generated_id(tx, "teamMember", "team_member", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            team_id: Set(team_id.to_owned()),
            user_id: Set(user_id.to_owned()),
            membership_key: Set(Some(key)),
            created_at: Set(Utc::now()),
        }
        .insert(tx)
        .await
        .map_err(map_db_err)?;
        let mut active = room.into_active_model();
        active.member_count = Set(reserved_count
            .checked_add(1)
            .ok_or_else(|| AuthError::internal("Team membership count overflow"))?);
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
            id: Set(self
                .generated_id(&self.db, "team", "team", "id")
                .await?
                .unwrap_or_else(|| Uuid::new_v4().to_string())),
            name: Set(data.name),
            organization_id: Set(data.organization_id),
            member_count: Set(0),
            created_at: Set(now),
            updated_at: Set(data.updated_at),
        }
        .insert(self.scoped_connection())
        .await
        .map(Into::into)
        .map_err(map_db_err)
    }
    async fn get_team(
        &self,
        organization_id: Option<&str>,
        team_id: &str,
    ) -> AuthResult<Option<Team>> {
        self.get_team_with_connection(self.scoped_connection(), organization_id, team_id)
            .await
    }
    async fn list_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        team::Entity::find()
            .filter(team::Column::OrganizationId.eq(organization_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.scoped_connection())
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
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        let mut active = model.into_active_model();
        if let Some(name) = update.name {
            active.name = Set(name);
        }
        active.updated_at = Set(Some(Utc::now()));
        active
            .update(self.scoped_connection())
            .await
            .map(Into::into)
            .map_err(map_db_err)
    }
    async fn delete_team(&self, organization_id: &str, team_id: &str) -> AuthResult<bool> {
        let tx = self
            .scoped_connection()
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
            .one(self.scoped_connection())
            .await
            .map(|row| row.map(Into::into))
            .map_err(map_db_err)
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        let tx = self
            .scoped_connection()
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
            .scoped_connection()
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
            .all(self.scoped_connection())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(map_db_err)
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let memberships = team_member::Entity::find()
            .filter(team_member::Column::UserId.eq(user_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        if memberships.is_empty() {
            return Ok(Vec::new());
        }
        let rooms = team::Entity::find()
            .filter(team::Column::Id.is_in(memberships.iter().map(|row| row.team_id.clone())))
            .all(self.scoped_connection())
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
    connection: &super::ScopedTransaction,
    user_id: &str,
    organization_id: Option<&str>,
) -> AuthResult<()> {
    if !connection
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
    connection: &super::ScopedTransaction,
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
