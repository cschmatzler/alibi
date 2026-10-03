use super::entities::invitation::Model;
use super::entities::{member, organization, team};
use super::{SqlxStore, lock_exclusive};
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::Exec;
use crate::schema::{AuthSchema, SqlxSessionModel, SqlxUserModel};
use crate::sql::Sql;
use async_trait::async_trait;
use better_auth_core::entity::AuthUser;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::InvitationStore;
use better_auth_core::{CreateInvitation, Invitation, InvitationStatus};
use chrono::Utc;
use uuid::Uuid;

impl<S: AuthSchema> SqlxStore<S> {
    async fn find_invitation(&self, id: &str) -> AuthResult<Option<Model>> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        self.exec().fetch_optional(sql).await
    }

    async fn count_invitation_rows(&self, sql: Sql) -> AuthResult<i64> {
        Ok(self
            .exec()
            .fetch_scalar::<i64>(sql)
            .await?
            .unwrap_or_default())
    }
}

#[async_trait]
impl<S> InvitationStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SqlxUserModel,
    S::Session: SqlxSessionModel,
{
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation> {
        self.create_invitation_with_options(
            invitation,
            better_auth_core::store::InvitationCreateOptions::default(),
        )
        .await
    }
    async fn create_invitation_with_options(
        &self,
        invitation: CreateInvitation,
        options: better_auth_core::store::InvitationCreateOptions,
    ) -> AuthResult<Invitation> {
        let mut active = ActiveRow::new();
        active.set(
            "id",
            options.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        );
        active.set("organization_id", invitation.organization_id);
        active.set("email", invitation.email);
        active.set("role", invitation.role);
        active.set("team_id", invitation.team_id);
        active.set("status", options.status.unwrap_or_default().to_string());
        active.set("inviter_id", invitation.inviter_id);
        active.set("expires_at", invitation.expires_at);
        active.set("created_at", options.created_at.unwrap_or_else(Utc::now));
        model::insert::<Model>(self.exec(), &active)
            .await
            .map(|model| Invitation::from(&model))
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        Ok(self
            .find_invitation(id)
            .await?
            .map(|model| Invitation::from(&model)))
    }

    async fn update_invitation_team_ids(
        &self,
        id: &str,
        team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        let row = self
            .find_invitation(id)
            .await?
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        let mut active = row.into_active();
        active.set("team_id", team_ids);
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|row_2| Invitation::from(&row_2))
            .ok_or_else(record_not_updated)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep invitation quota checks and insertion together inside their single transaction"
    )]
    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: &str,
        team_limits: &[(String, Option<f64>)],
        membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, better_auth_core::types::Member)>> {
        let transaction = self.pool().begin(true).await?;
        let outcome = async {
            let tx = &transaction;
            let exec = Exec::Tx(tx);
            let mut select = model::by_id::<Model>(exec, invitation_id);
            model::limit_one(&mut select);
            lock_exclusive(&mut select);
            let Some(invitation) = exec.fetch_optional::<Model>(select).await? else {
                return Ok(None);
            };
            if invitation.status != "pending" || invitation.expires_at < Utc::now() {
                return Ok(None);
            }
            let user =
                super::users::find_user_by_id::<S::User>(exec, user_id, super::users::Lock::Shared)
                    .await?
                    .ok_or(AuthError::UserNotFound)?;
            if user
                .email()
                .is_none_or(|email| email.to_lowercase() != invitation.email.to_lowercase())
            {
                return Err(AuthError::forbidden("This invitation is not for you"));
            }
            let session_table = <S::Session as SqlxModel>::TABLE;
            let mut session = model::select_model::<S::Session>(exec);
            session.push(" WHERE ");
            session.compare(
                session_table,
                S::Session::token_column(),
                " = ",
                session_token,
            );
            session.push(" AND ");
            session.compare(
                session_table,
                S::Session::user_id_column(),
                " = ",
                S::Session::parse_user_id(user_id)?,
            );
            session.push(" AND ");
            session.compare(session_table, S::Session::active_column(), " = ", true);
            model::limit_one(&mut session);
            lock_exclusive(&mut session);
            let session = exec
                .fetch_optional::<S::Session>(session)
                .await?
                .ok_or(AuthError::SessionNotFound)?;
            if better_auth_core::AuthSession::expires_at(&session) < Utc::now() {
                return Err(AuthError::SessionNotFound);
            }
            let mut owner =
                model::by_id::<organization::Model>(exec, invitation.organization_id.as_str());
            model::limit_one(&mut owner);
            lock_exclusive(&mut owner);
            drop(
                exec.fetch_optional::<organization::Model>(owner)
                    .await?
                    .ok_or_else(|| AuthError::bad_request("Organization not found"))?,
            );
            if let Some(limit) = membership_limit {
                let mut count = Sql::with(exec.engine(), "SELECT COUNT(*) FROM ");
                count.ident(member::Model::TABLE);
                count.push(" WHERE ");
                count.compare(
                    member::Model::TABLE,
                    "organization_id",
                    " = ",
                    invitation.organization_id.as_str(),
                );
                let members = exec.fetch_scalar::<i64>(count).await?.unwrap_or_default();
                if u64::try_from(members).unwrap_or_default()
                    >= u64::try_from(limit)
                        .map_err(|_error| AuthError::internal("Membership limit exceeds u64"))?
                {
                    return Err(AuthError::bad_request(
                        "Organization membership limit reached",
                    ));
                }
            }
            let requested = invitation
                .team_id
                .as_deref()
                .filter(|ids| !ids.is_empty())
                .map(|ids| ids.split(',').collect::<Vec<_>>())
                .unwrap_or_default();
            for team_id in &requested {
                let mut room = model::by_id::<team::Model>(exec, *team_id);
                room.push(" AND ");
                room.compare(
                    team::Model::TABLE,
                    "organization_id",
                    " = ",
                    invitation.organization_id.as_str(),
                );
                model::limit_one(&mut room);
                if exec.fetch_optional::<team::Model>(room).await?.is_none() {
                    return Err(AuthError::bad_request("Team not found"));
                }
                let maximum = team_limits
                    .iter()
                    .find(|(id, _)| id == team_id)
                    .and_then(|(_, limit)| *limit);
                if matches!(
                    self.add_team_member_in_tx(tx, team_id, user_id, maximum)
                        .await?,
                    better_auth_core::types::AddTeamMemberResult::LimitReached
                ) {
                    return Err(AuthError::Upstream {
                        status: 403,
                        code: "TEAM_MEMBER_LIMIT_REACHED",
                        message: "Team member limit reached",
                    });
                }
            }
            let mut created = ActiveRow::new();
            created.set("id", Uuid::new_v4().to_string());
            created.set("organization_id", invitation.organization_id.clone());
            created.set("user_id", user_id);
            created.set("role", invitation.role.clone());
            created.set("created_at", Utc::now());
            let created = model::insert::<member::Model>(exec, &created).await?;
            let mut active = session.into_active();
            S::Session::set_active_organization_id(
                &mut active,
                Some(invitation.organization_id.clone()),
            );
            if requested.len() == 1 {
                S::Session::set_active_team_id(
                    &mut active,
                    requested.first().map(|id| (*id).to_owned()),
                )?;
            }
            S::Session::set_updated_at(&mut active, Utc::now());
            drop(
                model::update::<S::Session>(exec, &active)
                    .await?
                    .ok_or_else(record_not_updated)?,
            );
            let mut changed = Sql::with(exec.engine(), "UPDATE ");
            changed.ident(Model::TABLE);
            changed.push(" SET ");
            changed.assign("status", "accepted");
            changed.push(" WHERE ");
            changed.compare(Model::TABLE, "id", " = ", invitation_id);
            changed.push(" AND ");
            changed.compare(Model::TABLE, "status", " = ", "pending");
            if exec.execute(changed).await? != 1 {
                return Err(AuthError::bad_request("Invitation not found"));
            }
            let mut invitation = Invitation::from(&invitation);
            invitation.status = InvitationStatus::Accepted;
            Ok(Some((
                invitation,
                better_auth_core::types::Member::from(&created),
            )))
        }
        .await;
        match outcome {
            Ok(value) => {
                transaction.commit().await?;
                Ok(value)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    async fn update_invitation_status_if_status(
        &self,
        id: &str,
        expected: InvitationStatus,
        status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        // Returning the actual changed row is part of this atomic public contract.
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(Model::TABLE);
        sql.push(" SET ");
        sql.assign("status", status.to_string());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "id", " = ", id);
        sql.push(" AND ");
        sql.compare(Model::TABLE, "status", " = ", expected.to_string());
        model::returning::<Model>(&mut sql);
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .first()
            .map(Invitation::from))
    }

    async fn pending_invitation_page(
        &self,
        org_id: &str,
        email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "organization_id", " = ", org_id);
        sql.push(" AND ");
        sql.compare(
            Model::TABLE,
            "status",
            " = ",
            InvitationStatus::Pending.to_string(),
        );
        if let Some(email) = email {
            sql.push(" AND ");
            sql.compare(Model::TABLE, "email", " = ", email.to_lowercase());
        }
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Invitation::from)
            .collect())
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        let model = self
            .find_invitation(id)
            .await?
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        let mut active = model.into_active();
        active.set("expires_at", expires_at);
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model| Invitation::from(&model))
            .ok_or_else(record_not_updated)
    }
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "organization_id", " = ", org_id);
        sql.push(" AND ");
        sql.compare(Model::TABLE, "email", " = ", email.to_lowercase());
        sql.push(" AND ");
        sql.compare(
            Model::TABLE,
            "status",
            " = ",
            InvitationStatus::Pending.to_string(),
        );
        sql.push(" AND ");
        sql.compare(Model::TABLE, "expires_at", " > ", Utc::now());
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| Invitation::from(&model)))
    }

    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let Some(model) = self.find_invitation(id).await? else {
            return Err(AuthError::not_found("Invitation not found"));
        };

        let mut active = model.into_active();
        active.set("status", status.to_string());
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Invitation::from(&model_2))
            .ok_or_else(record_not_updated)
    }

    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "organization_id", " = ", org_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Invitation::from)
            .collect())
    }

    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64> {
        let mut sql = Sql::with(self.exec().engine(), "SELECT COUNT(*) FROM ");
        sql.ident(Model::TABLE);
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "organization_id", " = ", org_id);
        sql.push(" AND ");
        sql.compare(
            Model::TABLE,
            "status",
            " = ",
            InvitationStatus::Pending.to_string(),
        );
        sql.push(" AND ");
        sql.compare(Model::TABLE, "expires_at", " > ", Utc::now());
        self.count_invitation_rows(sql).await
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "email", " = ", email.to_lowercase());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Invitation::from)
            .collect())
    }
}
