use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
};
use uuid::Uuid;

use better_auth_core::store::InvitationStore;

use crate::error::AuthResult;
use crate::schema::{AuthSchema, SeaOrmSessionModel, SeaOrmUserModel};
use crate::types_org::{CreateInvitation, Invitation, InvitationStatus};
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
            .ok_or_else(|| crate::error::AuthError::not_found("Invitation not found"))?;
        let mut active = row.into_active_model();
        active.team_id = Set(team_ids);
        active
            .update(self.connection())
            .await
            .map(|row| Invitation::from(&row))
            .map_err(map_db_err)
    }

    async fn accept_invitation_with_teams(
        &self,
        invitation_id: &str,
        user_id: &str,
        session_token: &str,
        team_limits: &[(String, Option<usize>)],
        membership_limit: Option<usize>,
    ) -> AuthResult<Option<(Invitation, better_auth_core::types::Member)>> {
        use super::entities::{member, organization};
        use crate::error::AuthError;
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
            if !user
                .email()
                .is_some_and(|email| email.to_lowercase() == invitation.email.to_lowercase())
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
            let _ = organization::Entity::find_by_id(invitation.organization_id.clone())
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(map_db_err)?
                .ok_or_else(|| AuthError::bad_request("Organization not found"))?;
            if let Some(limit) = membership_limit
                && member::Entity::find()
                    .filter(member::Column::OrganizationId.eq(&invitation.organization_id))
                    .count(&transaction)
                    .await
                    .map_err(map_db_err)?
                    >= limit as u64
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
            let _ = active.update(&transaction).await.map_err(map_db_err)?;
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

    async fn get_pending_invitation(
        &self,
        organization_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
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
            return Err(crate::error::AuthError::not_found("Invitation not found"));
        };

        let mut active = model.into_active_model();
        active.status = Set(status.to_string());
        active
            .update(self.connection())
            .await
            .map(|model| Invitation::from(&model))
            .map_err(map_db_err)
    }

    async fn list_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }

    async fn count_pending_organization_invitations(
        &self,
        organization_id: &str,
    ) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .count(self.connection())
            .await
            .map(|count| count as i64)
            .map_err(map_db_err)
    }

    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        Entity::find()
            .filter(Column::Email.eq(email.to_lowercase()))
            .filter(Column::Status.eq(InvitationStatus::Pending.to_string()))
            .filter(Column::ExpiresAt.gt(Utc::now()))
            .order_by_desc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Invitation::from).collect())
            .map_err(map_db_err)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use better_auth_core::config::AuthConfig;
    use better_auth_core::store::{InvitationStore, OrganizationStore, UserStore};
    use chrono::{Duration, Utc};

    use crate::Database;
    use crate::store::__private_test_support::bundled_schema::BundledSchema;
    use crate::store::__private_test_support::migrator::run_migrations;
    use crate::types::CreateUser;
    use crate::types_org::{CreateInvitation, CreateOrganization, InvitationStatus};

    use super::SeaOrmStore;

    async fn test_store() -> SeaOrmStore<BundledSchema> {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("sqlite test database should connect");
        run_migrations(&database)
            .await
            .expect("sqlite test migrations should run");
        SeaOrmStore::new(
            Arc::new(AuthConfig::new("test-secret-key-at-least-32-chars-long")),
            database,
        )
    }

    #[tokio::test]
    async fn pending_invitation_count_excludes_expired_and_non_pending_rows() {
        let store = test_store().await;
        let org_id = "org-1";
        let _organization = store
            .create_organization(CreateOrganization {
                id: Some(org_id.to_string()),
                name: "Org".to_string(),
                slug: "org".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        let _inviter = store
            .create_user(CreateUser {
                id: Some("inviter-1".to_string()),
                email: Some("inviter@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("inviter should be created");

        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "first@example.com",
                "member",
                "inviter-1",
                Utc::now() + Duration::hours(1),
            ))
            .await
            .expect("pending invitation should be created");
        let canceled = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "second@example.com",
                "member",
                "inviter-1",
                Utc::now() + Duration::hours(1),
            ))
            .await
            .expect("cancelable invitation should be created");
        let _ = store
            .update_invitation_status(&canceled.id, InvitationStatus::Canceled)
            .await
            .expect("invitation should be canceled");
        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await
            .expect("expired invitation should be created");

        let count = store
            .count_pending_organization_invitations(org_id)
            .await
            .expect("pending invitation count should succeed");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn get_pending_invitation_ignores_expired_rows() {
        let store = test_store().await;
        let org_id = "org-1";
        let _organization = store
            .create_organization(CreateOrganization {
                id: Some(org_id.to_string()),
                name: "Org".to_string(),
                slug: "org-second".to_string(),
                logo: None,
                metadata: None,
            })
            .await
            .expect("organization should be created");
        let _inviter = store
            .create_user(CreateUser {
                id: Some("inviter-1".to_string()),
                email: Some("inviter@example.com".to_string()),
                ..CreateUser::default()
            })
            .await
            .expect("inviter should be created");

        let _ = store
            .create_invitation(CreateInvitation::new(
                org_id,
                "expired@example.com",
                "member",
                "inviter-1",
                Utc::now() - Duration::hours(1),
            ))
            .await
            .expect("expired invitation should be created");

        let invitation = store
            .get_pending_invitation(org_id, "expired@example.com")
            .await
            .expect("lookup should succeed");

        assert!(invitation.is_none());
    }
}
