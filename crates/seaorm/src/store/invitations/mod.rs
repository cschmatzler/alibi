#[cfg(test)]
mod tests;

use async_trait::async_trait;

use chrono::Utc;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
};

use uuid::Uuid;

use better_auth_core::store::InvitationStore;

use better_auth_core::error::{AuthError, AuthResult};

use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};

use better_auth_core::{CreateInvitation, Invitation, InvitationStatus};

use better_auth_core::entity::AuthUser;

use super::entities::invitation::{ActiveModel, Column, Entity};

use super::{SeaOrmStore, map_db_err};

#[async_trait]
impl<S> InvitationStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
    S::Session: SeaOrmSessionModel,
{
    async fn create_invitation(&self, invitation: CreateInvitation) -> AuthResult<Invitation> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(invitation.organization_id),
            email: Set(invitation.email),
            role: Set(invitation.role),
            team_id: Set(invitation.team_id),
            status: Set(InvitationStatus::Pending.to_string()),
            inviter_id: Set(invitation.inviter_id),
            expires_at: Set(invitation.expires_at),
            created_at: Set(Utc::now()),
        }
        .insert(self.connection())
        .await
        .map(|model| Invitation::from(&model))
        .map_err(map_db_err)
    }

    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Invitation::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_invitation_team_ids(
        &self,
        id: &str,
        team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        let row = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        let mut active = row.into_active_model();
        active.team_id = Set(team_ids);
        active
            .update(self.connection())
            .await
            .map(|row_2| Invitation::from(&row_2))
            .map_err(map_db_err)
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
        team_limits: &[(String, Option<usize>)],
        membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, better_auth_core::types::Member)>> {
        use super::entities::{member, organization};
        use better_auth_core::error::AuthError;
        let transaction = self
            .connection()
            .begin_with_options(sea_orm::TransactionOptions {
                sqlite_transaction_mode: Some(sea_orm::SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        let outcome = async {
            let Some(invitation) = Entity::find_by_id(invitation_id.to_owned())
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(map_db_err)?
            else {
                return Ok(None);
            };
            if invitation.status != "pending" || invitation.expires_at < Utc::now() {
                return Ok(None);
            }
            let typed_id = S::User::parse_id(user_id)?;
            let user = <S::User as SeaOrmUserModel>::Entity::find()
                .filter(S::User::id_column().eq(typed_id))
                .lock_shared()
                .one(&transaction)
                .await
                .map_err(map_db_err)?
                .ok_or(AuthError::UserNotFound)?;
            if user
                .email()
                .is_none_or(|email| email.to_lowercase() != invitation.email.to_lowercase())
            {
                return Err(AuthError::forbidden("This invitation is not for you"));
            }
            let session = <S::Session as SeaOrmSessionModel>::Entity::find()
                .filter(S::Session::token_column().eq(session_token))
                .filter(S::Session::user_id_column().eq(S::Session::parse_user_id(user_id)?))
                .filter(S::Session::active_column().eq(true))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(map_db_err)?
                .ok_or(AuthError::SessionNotFound)?;
            if better_auth_core::AuthSession::expires_at(&session) < Utc::now() {
                return Err(AuthError::SessionNotFound);
            }
            drop(
                organization::Entity::find_by_id(invitation.organization_id.clone())
                    .lock_exclusive()
                    .one(&transaction)
                    .await
                    .map_err(map_db_err)?
                    .ok_or_else(|| AuthError::bad_request("Organization not found"))?,
            );
            if let Some(limit) = membership_limit
                && member::Entity::find()
                    .filter(member::Column::OrganizationId.eq(&invitation.organization_id))
                    .count(&transaction)
                    .await
                    .map_err(map_db_err)?
                    >= u64::try_from(limit)
                        .map_err(|_error| AuthError::internal("Membership limit exceeds u64"))?
            {
                return Err(AuthError::bad_request(
                    "Organization membership limit reached",
                ));
            }
            let requested = invitation
                .team_id
                .as_deref()
                .filter(|ids| !ids.is_empty())
                .map(|ids| ids.split(',').collect::<Vec<_>>())
                .unwrap_or_default();
            for team_id in &requested {
                let room = super::entities::team::Entity::find_by_id((*team_id).to_owned())
                    .filter(
                        super::entities::team::Column::OrganizationId
                            .eq(&invitation.organization_id),
                    )
                    .one(&transaction)
                    .await
                    .map_err(map_db_err)?;
                if room.is_none() {
                    return Err(AuthError::bad_request("Team not found"));
                }
                let maximum = team_limits
                    .iter()
                    .find(|(id, _)| id == team_id)
                    .and_then(|(_, limit)| *limit);
                if matches!(
                    self.add_team_member_in_tx(&transaction, team_id, user_id, maximum)
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
            let created = member::ActiveModel {
                id: Set(Uuid::new_v4().to_string()),
                organization_id: Set(invitation.organization_id.clone()),
                user_id: Set(user_id.to_owned()),
                role: Set(invitation.role.clone()),
                created_at: Set(Utc::now()),
            }
            .insert(&transaction)
            .await
            .map_err(map_db_err)?;
            let mut active = session.into_active_model();
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
            drop(active.update(&transaction).await.map_err(map_db_err)?);
            let changed = Entity::update_many()
                .filter(Column::Id.eq(invitation_id))
                .filter(Column::Status.eq("pending"))
                .col_expr(Column::Status, sea_orm::sea_query::Expr::value("accepted"))
                .exec(&transaction)
                .await
                .map_err(map_db_err)?;
            if changed.rows_affected != 1 {
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
                transaction.commit().await.map_err(map_db_err)?;
                Ok(value)
            }
            Err(error) => {
                transaction.rollback().await.map_err(map_db_err)?;
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
        // Fail before mutation on a backend without supported RETURNING semantics.
        if !matches!(
            self.connection().get_database_backend(),
            sea_orm::DbBackend::Sqlite | sea_orm::DbBackend::Postgres
        ) {
            return Err(crate::error::AuthError::NotImplemented(
                "Conditional invitation updates require RETURNING support".into(),
            ));
        }
        Entity::update_many()
            .filter(Column::Id.eq(id))
            .filter(Column::Status.eq(expected.to_string()))
            .col_expr(
                Column::Status,
                sea_orm::sea_query::Expr::value(status.to_string()),
            )
            .exec_with_returning(self.connection())
            .await
            .map(|rows| rows.first().map(Invitation::from))
            .map_err(map_db_err)
    }

    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(org_id))
            .filter(Column::Email.eq(email.to_lowercase()))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Invitation::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Invitation not found"));
        };

        let mut active = model.into_active_model();
        active.status = Set(status.to_string());
        active
            .update(self.connection())
            .await
            .map(|model_2| Invitation::from(&model_2))
            .map_err(map_db_err)
    }

    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(org_id))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }

    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(org_id))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .count(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|count| {
                i64::try_from(count)
                    .map_err(|_error| AuthError::internal("Invitation count exceeds i64"))
            })
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::Email.eq(email.to_lowercase()))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }
}
