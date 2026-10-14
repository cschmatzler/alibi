//! Atomic canonical User insertion, identity subject fencing, and tombstone consumption.
use super::{
    SeaOrmStore,
    entities::{scim_identity_tombstone as tombstone, scim_subject as subject, scim_user as user},
    map_db_err,
};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{CreateScimUser, ScimProjectionPreparedUser, ScimUserRecord},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, sea_query::Expr,
};
fn conflict(detail: &str) -> AuthError {
    AuthError::Api {
        status: 409,
        code: Some("uniqueness".into()),
        message: detail.into(),
    }
}
fn identity_conflict() -> AuthError {
    AuthError::internal("The SCIM identity changed concurrently; retry the request")
}
impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn assert_scim_user_keys_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        connection: &str,
        name_key: &str,
        external_key: Option<&str>,
        connection_user_key: Option<&str>,
        exclude: Option<&str>,
    ) -> AuthResult<()> {
        for (field, value, detail) in [
            (
                user::Column::UserNameKey,
                Some(name_key),
                "SCIM User userName already exists",
            ),
            (
                user::Column::ExternalIdKey,
                external_key,
                "SCIM User externalId already exists",
            ),
            (
                user::Column::ConnectionUserKey,
                connection_user_key,
                "This connection already provisions the resolved Better Auth User",
            ),
        ] {
            if let Some(value) = value
                && user::Entity::find()
                    .filter(user::Column::ConnectionId.eq(connection))
                    .filter(field.eq(value))
                    .one(db)
                    .await
                    .map_err(map_db_err)?
                    .is_some_and(|row| Some(row.id.as_str()) != exclude)
            {
                return Err(conflict(detail));
            }
        }
        Ok(())
    }

    pub(super) async fn acquire_scim_subject_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        required: bool,
    ) -> AuthResult<subject::Model> {
        let current = if let Some(current) = subject::Entity::find()
            .filter(subject::Column::UserId.eq(user_id))
            .one(db)
            .await
            .map_err(map_db_err)?
        {
            let revision = current
                .revision
                .checked_add(1)
                .ok_or_else(identity_conflict)?;
            if subject::Entity::update_many()
                .col_expr(subject::Column::Revision, Expr::value(revision))
                .col_expr(subject::Column::UpdatedAt, Expr::value(now))
                .filter(subject::Column::Id.eq(&current.id))
                .filter(subject::Column::Revision.eq(current.revision))
                .exec(db)
                .await
                .map_err(map_db_err)?
                .rows_affected
                == 0
            {
                return Err(identity_conflict());
            }
            subject::Model {
                revision,
                ..current
            }
        } else {
            if required {
                return Err(AuthError::Api {
                    status: 500,
                    code: None,
                    message: "The SCIM User subject is missing".into(),
                });
            }
            subject::ActiveModel {
                id: Set(self
                    .generated_id(db, "scimSubject", "scimSubject", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())),
                user_id: Set(user_id.to_owned()),
                profile_source_id: Set(None),
                revision: Set(1),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(db)
            .await
            .map_err(map_db_err)?
        };
        Ok(current)
    }

    pub(super) async fn create_scim_user_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        data: CreateScimUser,
        roles: bool,
    ) -> AuthResult<(ScimUserRecord, Vec<ScimProjectionPreparedUser>)> {
        self.assert_scim_user_keys_with_connection(
            db,
            &data.connection_id,
            &data.attributes.user_name_key,
            data.attributes.external_id_key.as_deref(),
            Some(&data.connection_user_key),
            None,
        )
        .await?;
        let current = self
            .acquire_scim_subject_with_connection(db, &data.user_id, data.created_at, false)
            .await?;
        let id = self
            .generated_id(db, "scimUser", "scimUser", "id")
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let stored = user::ActiveModel {
            id: Set(id.clone()),
            connection_id: Set(data.connection_id.clone()),
            provisioning_domain_id: Set(data.provisioning_domain_id.clone()),
            user_id: Set(data.user_id.clone()),
            connection_user_key: Set(data.connection_user_key.clone()),
            user_name: Set(data.attributes.user_name.clone()),
            user_name_key: Set(data.attributes.user_name_key.clone()),
            primary_email: Set(data.attributes.primary_email.clone()),
            work_email_value_index: Set(data.attributes.work_email_value_index.clone()),
            email_value_index: Set(data.attributes.email_value_index.clone()),
            display_name: Set(data.attributes.display_name.clone()),
            formatted_name: Set(data.attributes.formatted_name.clone()),
            given_name: Set(data.attributes.given_name.clone()),
            family_name: Set(data.attributes.family_name.clone()),
            serialized_emails: Set(data.attributes.serialized_emails.clone()),
            serialized_attributes: Set(data.attributes.serialized_attributes.clone()),
            external_id: Set(data.attributes.external_id.clone()),
            external_id_key: Set(data.attributes.external_id_key.clone()),
            active: Set(data.attributes.active),
            order_key: Set(data.order_key.clone()),
            created_at: Set(data.created_at),
            updated_at: Set(data.created_at),
        }
        .insert(db)
        .await
        .map_err(map_db_err)?;
        if data.manage_profile {
            if current
                .profile_source_id
                .as_ref()
                .is_some_and(|value| !value.is_empty() && value != &id)
            {
                return Err(conflict(
                    "Another SCIM source already manages this User profile",
                ));
            }
            let revision = current
                .revision
                .checked_add(1)
                .ok_or_else(identity_conflict)?;
            if subject::Entity::update_many()
                .col_expr(subject::Column::Revision, Expr::value(revision))
                .col_expr(subject::Column::ProfileSourceId, Expr::value(id))
                .col_expr(subject::Column::UpdatedAt, Expr::value(data.created_at))
                .filter(subject::Column::Id.eq(&current.id))
                .filter(subject::Column::Revision.eq(current.revision))
                .filter(subject::Column::ProfileSourceId.is_null())
                .exec(db)
                .await
                .map_err(map_db_err)?
                .rows_affected
                == 0
            {
                return Err(identity_conflict());
            }
        }
        if let Some(id) = data.tombstone_id {
            _ = tombstone::Entity::delete_many()
                .filter(tombstone::Column::Id.eq(id))
                .exec(db)
                .await
                .map_err(map_db_err)?;
        }
        let states = self
            .prepare_scim_projection_for_users_with_connection(
                db,
                &data.provisioning_domain_id,
                vec![data.user_id],
                roles,
            )
            .await?;
        Ok((
            ScimUserRecord {
                id: stored.id,
                connection_id: stored.connection_id,
                provisioning_domain_id: stored.provisioning_domain_id,
                user_name: stored.user_name,
                primary_email: stored.primary_email,
                display_name: stored.display_name,
                active: stored.active,
                external_id: stored.external_id,
                formatted_name: stored.formatted_name,
                given_name: stored.given_name,
                family_name: stored.family_name,
                serialized_emails: stored.serialized_emails,
                serialized_attributes: stored.serialized_attributes,
                created_at: stored.created_at,
                updated_at: stored.updated_at,
            },
            states,
        ))
    }
}
