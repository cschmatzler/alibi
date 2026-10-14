//! Canonical User replacement over a fenced identity subject.
use super::{SeaOrmStore, map_db_err};
use alibi_core::{
    AuthResult, AuthSchema,
    store::{ReplaceScimUser, ScimProjectionPreparedUser, ScimUserMutationContext, ScimUserRecord},
};
use sea_orm::{ActiveModelTrait, ConnectionTrait, IntoActiveModel, Set};
impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn lock_scim_user_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        connection: &str,
        domain: &str,
        attributes: &alibi_core::store::ScimUserAttributes,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<ScimUserMutationContext> {
        let source = self
            .scim_user_owned_with_connection(db, id, connection, domain)
            .await?;
        let subject = self
            .acquire_scim_subject_with_connection(db, &source.user_id, now)
            .await?;
        self.assert_scim_user_keys_with_connection(
            db,
            connection,
            &attributes.user_name_key,
            attributes.external_id_key.as_deref(),
            None,
            Some(id),
        )
        .await?;
        Ok(ScimUserMutationContext {
            user_id: source.user_id,
            manage_profile: subject.profile_source_id.as_deref() == Some(id),
        })
    }
    pub(super) async fn replace_scim_user_with_connection<C: ConnectionTrait>(
        &self,
        db: &C,
        id: &str,
        data: ReplaceScimUser,
        roles: bool,
    ) -> AuthResult<(ScimUserRecord, Vec<ScimProjectionPreparedUser>)> {
        let current = self
            .scim_user_owned_with_connection(
                db,
                id,
                &data.connection_id,
                &data.provisioning_domain_id,
            )
            .await?;
        self.assert_scim_user_keys_with_connection(
            db,
            &data.connection_id,
            &data.attributes.user_name_key,
            data.attributes.external_id_key.as_deref(),
            None,
            Some(id),
        )
        .await?;
        let user_id = current.user_id.clone();
        let mut row = current.into_active_model();
        row.user_name = Set(data.attributes.user_name.clone());
        row.user_name_key = Set(data.attributes.user_name_key.clone());
        row.primary_email = Set(data.attributes.primary_email.clone());
        row.work_email_value_index = Set(data.attributes.work_email_value_index.clone());
        row.email_value_index = Set(data.attributes.email_value_index.clone());
        row.display_name = Set(data.attributes.display_name.clone());
        row.formatted_name = Set(data.attributes.formatted_name.clone());
        row.given_name = Set(data.attributes.given_name.clone());
        row.family_name = Set(data.attributes.family_name.clone());
        row.serialized_emails = Set(data.attributes.serialized_emails.clone());
        row.serialized_attributes = Set(data.attributes.serialized_attributes.clone());
        row.external_id = Set(data.attributes.external_id.clone());
        row.external_id_key = Set(data.attributes.external_id_key.clone());
        row.active = Set(data.attributes.active);
        row.updated_at = Set(data.updated_at);
        let stored = row.update(db).await.map_err(map_db_err)?;
        let states = self
            .prepare_scim_projection_for_users_with_connection(
                db,
                &data.provisioning_domain_id,
                vec![user_id],
                roles,
            )
            .await?;
        Ok((
            ScimUserRecord {
                id: stored.id,
                connection_id: stored.connection_id,
                provisioning_domain_id: stored.provisioning_domain_id,
                user_name: stored.user_name,
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
