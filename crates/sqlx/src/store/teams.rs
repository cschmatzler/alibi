use super::entities::{team, team_member};
use super::{SqlxStore, lock_exclusive};
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxUserModel};
use crate::sql::Sql;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{TeamStore, team_membership_key};
use better_auth_core::types::{AddTeamMemberResult, CreateTeam, Team, TeamMember, UpdateTeam};
use chrono::Utc;
use uuid::Uuid;

fn team_member_lookup(exec: Exec<'_>, team_id: &str, user_id: &str) -> Sql {
    let mut sql = model::select_model::<team_member::Model>(exec);
    sql.push(" WHERE ");
    sql.compare(team_member::Model::TABLE, "team_id", " = ", team_id);
    sql.push(" AND ");
    sql.compare(team_member::Model::TABLE, "user_id", " = ", user_id);
    model::limit_one(&mut sql);
    sql
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
{
    pub(super) async fn get_team_with_connection(
        &self,
        exec: Exec<'_>,
        organization_id: Option<&str>,
        team_id: &str,
    ) -> AuthResult<Option<Team>> {
        let mut sql = model::by_id::<team::Model>(exec, team_id);
        if let Some(org) = organization_id {
            sql.push(" AND ");
            sql.compare(team::Model::TABLE, "organization_id", " = ", org);
        }
        model::limit_one(&mut sql);
        Ok(exec
            .fetch_optional::<team::Model>(sql)
            .await?
            .map(Into::into))
    }

    pub(super) async fn add_team_member_in_tx(
        &self,
        tx: &SqlxTransaction,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        let exec = Exec::Tx(tx);
        if super::users::find_user_by_id::<S::User>(exec, user_id, super::users::Lock::Shared)
            .await?
            .is_none()
        {
            return Err(AuthError::UserNotFound);
        }
        let mut room = model::by_id::<team::Model>(exec, team_id);
        model::limit_one(&mut room);
        lock_exclusive(&mut room);
        let room = exec
            .fetch_optional::<team::Model>(room)
            .await?
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        if let Some(member) = exec
            .fetch_optional::<team_member::Model>(team_member_lookup(exec, team_id, user_id))
            .await?
        {
            return Ok(AddTeamMemberResult::Existing(member.into()));
        }
        let mut count = Sql::with(exec.engine(), "SELECT COUNT(*) FROM ");
        count.ident(team_member::Model::TABLE);
        count.push(" WHERE ");
        count.compare(team_member::Model::TABLE, "team_id", " = ", team_id);
        let count = u64::try_from(exec.fetch_scalar::<i64>(count).await?.unwrap_or_default())
            .unwrap_or_default();
        // Source only repairs a stale low durable counter before reserving a seat.
        // Preserve high counters, and bind the raw policy to the database's `<`
        // predicate: notably SQLite binds NaN as NULL, which cannot reserve a seat.
        let reserved_count = i64::try_from(count)
            .map_err(|_error| AuthError::internal("Team membership count overflow"))?
            .max(room.member_count);
        let mut active = room.into_active();
        active.set("member_count", reserved_count);
        drop(
            model::update::<team::Model>(exec, &active)
                .await?
                .ok_or_else(record_not_updated)?,
        );
        if let Some(maximum) = maximum {
            let mut seat = Sql::with(exec.engine(), "SELECT COUNT(*) FROM ");
            seat.ident(team::Model::TABLE);
            seat.push(" WHERE ");
            seat.compare(team::Model::TABLE, "id", " = ", team_id);
            seat.push(" AND ");
            if exec.engine() == crate::pool::Engine::Postgres {
                // Source's text Number parameter is parsed as the physical
                // bigint counter, rather than promoting that counter to float8.
                seat.column(team::Model::TABLE, "member_count");
                seat.push(" < ");
                seat.bind(ryu_js::Buffer::new().format(maximum).to_owned());
                seat.push("::bigint");
            } else {
                seat.compare(team::Model::TABLE, "member_count", " < ", maximum);
            }
            if exec.fetch_scalar::<i64>(seat).await?.unwrap_or_default() == 0 {
                return Ok(AddTeamMemberResult::LimitReached);
            }
        }
        let key = team_membership_key(team_id, user_id)?;
        let mut member = ActiveRow::new();
        member.set("id", Uuid::new_v4().to_string());
        member.set("team_id", team_id);
        member.set("user_id", user_id);
        member.set("membership_key", Some(key));
        member.set("created_at", Utc::now());
        let member = model::insert::<team_member::Model>(exec, &member).await?;
        active.set(
            "member_count",
            reserved_count
                .checked_add(1)
                .ok_or_else(|| AuthError::internal("Team membership count overflow"))?,
        );
        drop(
            model::update::<team::Model>(exec, &active)
                .await?
                .ok_or_else(record_not_updated)?,
        );
        Ok(AddTeamMemberResult::Added(member.into()))
    }
}

#[async_trait]
impl<S> TeamStore for SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
{
    async fn create_team(&self, data: CreateTeam) -> AuthResult<Team> {
        self.create_team_with_connection(self.exec(), data).await
    }
    async fn get_team(
        &self,
        organization_id: Option<&str>,
        team_id: &str,
    ) -> AuthResult<Option<Team>> {
        self.get_team_with_connection(self.exec(), organization_id, team_id)
            .await
    }
    async fn list_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        self.list_teams_with_connection(self.exec(), organization_id)
            .await
    }
    async fn update_team(
        &self,
        organization_id: &str,
        team_id: &str,
        update: UpdateTeam,
    ) -> AuthResult<Team> {
        self.update_team_with_connection(self.exec(), organization_id, team_id, update)
            .await
    }
    async fn delete_team(&self, organization_id: &str, team_id: &str) -> AuthResult<bool> {
        self.in_transaction(true, async |tx| {
            self.delete_team_in_tx(tx, organization_id, team_id).await
        })
        .await
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        self.get_team_member_with_connection(self.exec(), team_id, user_id)
            .await
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        let tx = self.pool().begin(true).await?;
        let result = self
            .add_team_member_in_tx(&tx, team_id, user_id, maximum)
            .await?;
        tx.commit().await?;
        Ok(result)
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<usize> {
        self.in_transaction(true, async |tx| {
            self.remove_team_member_in_tx(tx, team_id, user_id).await
        })
        .await
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        self.list_team_members_with_connection(self.exec(), team_id)
            .await
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        self.list_user_teams_with_connection(self.exec(), user_id)
            .await
    }
}

/// `UPDATE team SET member_count = member_count - n WHERE id = ? AND member_count >= n`.
async fn release_seats(exec: Exec<'_>, team_id: &str, count: i64) -> AuthResult<()> {
    let mut sql = Sql::with(exec.engine(), "UPDATE ");
    sql.ident(team::Model::TABLE);
    sql.push(" SET ");
    sql.ident("member_count");
    sql.push(" = ");
    sql.ident("member_count");
    sql.push(" - ");
    sql.bind(count);
    sql.push(" WHERE ");
    sql.compare(team::Model::TABLE, "id", " = ", team_id);
    sql.push(" AND ");
    sql.compare(team::Model::TABLE, "member_count", " >= ", count);
    _ = exec.execute(sql).await?;
    Ok(())
}

/// Delete owned memberships and release exactly the seats those rows occupied.
pub(super) async fn remove_owned_team_members(
    tx: &SqlxTransaction,
    user_id: &str,
    organization_id: Option<&str>,
) -> AuthResult<()> {
    let exec = Exec::Tx(tx);
    if !super::migrator::has_table(exec, "team_member").await? {
        return Ok(());
    }
    let mut teams = model::select_model::<team::Model>(exec);
    if let Some(org) = organization_id {
        teams.push(" WHERE ");
        teams.compare(team::Model::TABLE, "organization_id", " = ", org);
    }
    teams.push(" ORDER BY ");
    teams.column(team::Model::TABLE, "id");
    teams.push(" ASC");
    lock_exclusive(&mut teams);
    let rooms = exec.fetch_all::<team::Model>(teams).await?;
    release_owned_team_members(tx, user_id, rooms).await
}

/// Remove memberships from an already selected adapter page and release seats.
pub(super) async fn release_owned_team_members(
    tx: &SqlxTransaction,
    user_id: &str,
    rooms: Vec<team::Model>,
) -> AuthResult<()> {
    let exec = Exec::Tx(tx);
    for room in rooms {
        let mut delete = Sql::with(exec.engine(), "DELETE FROM ");
        delete.ident(team_member::Model::TABLE);
        delete.push(" WHERE ");
        delete.compare(
            team_member::Model::TABLE,
            "team_id",
            " = ",
            room.id.as_str(),
        );
        delete.push(" AND ");
        delete.compare(team_member::Model::TABLE, "user_id", " = ", user_id);
        let deleted = exec.execute(delete).await?;
        if deleted > 0 {
            let count = i64::try_from(deleted)
                .map_err(|_error| AuthError::internal("Team membership count overflow"))?;
            release_seats(exec, &room.id, count).await?;
        }
    }
    Ok(())
}

impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn create_team_with_connection(
        &self,
        exec: Exec<'_>,
        data: CreateTeam,
    ) -> AuthResult<Team> {
        let now = data.updated_at.unwrap_or_else(Utc::now);
        let mut active = ActiveRow::new();
        active.set("id", Uuid::new_v4().to_string());
        active.set("name", data.name);
        active.set("organization_id", data.organization_id);
        active.set("member_count", 0_i64);
        active.set("created_at", now);
        active.set("updated_at", data.updated_at);
        model::insert::<team::Model>(exec, &active)
            .await
            .map(Into::into)
    }
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
{
    pub(super) async fn list_teams_with_connection(
        &self,
        exec: Exec<'_>,
        organization_id: &str,
    ) -> AuthResult<Vec<Team>> {
        let mut sql = model::select_model::<team::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(
            team::Model::TABLE,
            "organization_id",
            " = ",
            organization_id,
        );
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(self
            .exec()
            .fetch_all::<team::Model>(sql)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    pub(super) async fn update_team_with_connection(
        &self,
        exec: Exec<'_>,
        organization_id: &str,
        team_id: &str,
        update: UpdateTeam,
    ) -> AuthResult<Team> {
        let mut sql = model::by_id::<team::Model>(exec, team_id);
        sql.push(" AND ");
        sql.compare(
            team::Model::TABLE,
            "organization_id",
            " = ",
            organization_id,
        );
        model::limit_one(&mut sql);
        let model = self
            .exec()
            .fetch_optional::<team::Model>(sql)
            .await?
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        let mut active = model.into_active();
        if let Some(name) = update.name {
            active.set("name", name);
        }
        active.set("updated_at", Some(Utc::now()));
        model::update::<team::Model>(exec, &active)
            .await?
            .map(Into::into)
            .ok_or_else(record_not_updated)
    }
    pub(super) async fn get_team_member_with_connection(
        &self,
        exec: Exec<'_>,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        Ok(self
            .exec()
            .fetch_optional::<team_member::Model>(team_member_lookup(exec, team_id, user_id))
            .await?
            .map(Into::into))
    }
    pub(super) async fn list_team_members_with_connection(
        &self,
        exec: Exec<'_>,
        team_id: &str,
    ) -> AuthResult<Vec<TeamMember>> {
        let mut sql = model::select_model::<team_member::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(team_member::Model::TABLE, "team_id", " = ", team_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(self
            .exec()
            .fetch_all::<team_member::Model>(sql)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
    pub(super) async fn list_user_teams_with_connection(
        &self,
        exec: Exec<'_>,
        user_id: &str,
    ) -> AuthResult<Vec<Team>> {
        let mut sql = model::select_model::<team_member::Model>(exec);
        sql.push(" WHERE ");
        sql.compare(team_member::Model::TABLE, "user_id", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let memberships: Vec<team_member::Model> = exec.fetch_all(sql).await?;
        if memberships.is_empty() {
            return Ok(Vec::new());
        }
        let mut rooms = model::select_model::<team::Model>(exec);
        rooms.push(" WHERE ");
        rooms.column(team::Model::TABLE, "id");
        rooms.push(" IN ");
        rooms.bind_list(memberships.iter().map(|row| row.team_id.clone()));
        let rooms = self
            .exec()
            .fetch_all::<team::Model>(rooms)
            .await?
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
    pub(super) async fn delete_team_in_tx(
        &self,
        tx: &SqlxTransaction,
        organization_id: &str,
        team_id: &str,
    ) -> AuthResult<bool> {
        let exec = Exec::Tx(tx);
        let mut delete = Sql::with(exec.engine(), "DELETE FROM ");
        delete.ident(team::Model::TABLE);
        delete.push(" WHERE ");
        delete.compare(team::Model::TABLE, "id", " = ", team_id);
        delete.push(" AND ");
        delete.compare(
            team::Model::TABLE,
            "organization_id",
            " = ",
            organization_id,
        );
        if exec.execute(delete).await? == 0 {
            return Ok(false);
        }
        let mut members = Sql::with(exec.engine(), "DELETE FROM ");
        members.ident(team_member::Model::TABLE);
        members.push(" WHERE ");
        members.compare(team_member::Model::TABLE, "team_id", " = ", team_id);
        _ = exec.execute(members).await?;
        let mut pending = self.organization_models.invitation.select(exec);
        pending.push(" WHERE ");
        self.organization_models.invitation.compare(
            &mut pending,
            "organization_id",
            " = ",
            organization_id,
        )?;
        pending.push(" AND ");
        self.organization_models
            .invitation
            .compare(&mut pending, "status", " = ", "pending")?;
        pending.push(" AND ");
        self.organization_models.invitation.compare(
            &mut pending,
            "expires_at",
            " > ",
            Utc::now(),
        )?;
        for invite in self
            .organization_models
            .invitation
            .fetch_all(exec, pending)
            .await?
        {
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
            let mut active = invite.into_active();
            active.set("team_id", (!remaining.is_empty()).then_some(remaining));
            drop(
                self.organization_models
                    .invitation
                    .update(exec, &active)
                    .await?
                    .ok_or_else(record_not_updated)?,
            );
        }
        Ok(true)
    }
    pub(super) async fn remove_team_member_in_tx(
        &self,
        tx: &SqlxTransaction,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<usize> {
        let exec = Exec::Tx(tx);
        let mut room = model::by_id::<team::Model>(exec, team_id);
        model::limit_one(&mut room);
        lock_exclusive(&mut room);
        drop(exec.fetch_optional::<team::Model>(room).await?);
        let mut delete = Sql::with(exec.engine(), "DELETE FROM ");
        delete.ident(team_member::Model::TABLE);
        delete.push(" WHERE ");
        delete.compare(team_member::Model::TABLE, "team_id", " = ", team_id);
        delete.push(" AND ");
        delete.compare(team_member::Model::TABLE, "user_id", " = ", user_id);
        let removed = exec.execute(delete).await?;
        let count = i64::try_from(removed)
            .map_err(|_error| AuthError::internal("Team membership count overflow"))?;
        if count > 0 {
            release_seats(exec, team_id, count).await?;
        }
        usize::try_from(removed).map_err(|_| AuthError::internal("Team membership count overflow"))
    }
}
