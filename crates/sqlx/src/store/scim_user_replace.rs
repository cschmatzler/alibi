//! Canonical User replacement over a fenced identity subject.
use super::{SqlxStore, entities::scim_user as user};
use crate::{
    model::{self, ActiveRow},
    pool::Exec,
};
use alibi_core::{
    AuthResult, AuthSchema,
    store::{ReplaceScimUser, ScimProjectionPreparedUser, ScimUserMutationContext, ScimUserRecord},
};
impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn lock_scim_user_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        connection: &str,
        domain: &str,
        attributes: Option<&alibi_core::store::ScimUserAttributes>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<ScimUserMutationContext> {
        let mut source = self
            .scim_user_owned_with_exec(exec, id, connection, domain)
            .await?;
        let subject = self
            .acquire_scim_subject_with_exec(exec, &source.user_id, now, attributes.is_none())
            .await?;
        if let Some(attributes) = attributes {
            self.assert_scim_user_keys_with_exec(
                exec,
                connection,
                &attributes.user_name_key,
                attributes.external_id_key.as_deref(),
                None,
                Some(id),
            )
            .await?;
        } else {
            let after = self
                .scim_user_owned_with_exec(exec, id, connection, domain)
                .await?;
            if after.user_id != source.user_id {
                return Err(alibi_core::AuthError::Api {
                    status: 409,
                    code: None,
                    message: "The SCIM User identity changed concurrently".into(),
                });
            }
            source = after;
        }
        Ok(ScimUserMutationContext {
            user_id: source.user_id.clone(),
            source: source.into(),
            manage_profile: subject.profile_source_id.as_deref() == Some(id),
        })
    }
    pub(super) async fn replace_scim_user_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
        data: ReplaceScimUser,
        roles: bool,
    ) -> AuthResult<(ScimUserRecord, Vec<ScimProjectionPreparedUser>)> {
        let current = self
            .scim_user_owned_with_exec(exec, id, &data.connection_id, &data.provisioning_domain_id)
            .await?;
        self.assert_scim_user_keys_with_exec(
            exec,
            &data.connection_id,
            &data.attributes.user_name_key,
            data.attributes.external_id_key.as_deref(),
            None,
            Some(id),
        )
        .await?;
        let mut row = ActiveRow::new();
        row.set("id", id);
        row.set("userName", data.attributes.user_name.clone());
        row.set("userNameKey", data.attributes.user_name_key.clone());
        row.set("primaryEmail", data.attributes.primary_email.clone());
        row.set(
            "workEmailValueIndex",
            data.attributes.work_email_value_index.clone(),
        );
        row.set("emailValueIndex", data.attributes.email_value_index.clone());
        row.set("displayName", data.attributes.display_name.clone());
        row.set("formattedName", data.attributes.formatted_name.clone());
        row.set("givenName", data.attributes.given_name.clone());
        row.set("familyName", data.attributes.family_name.clone());
        row.set(
            "serializedEmails",
            data.attributes.serialized_emails.clone(),
        );
        row.set(
            "serializedAttributes",
            data.attributes.serialized_attributes.clone(),
        );
        row.set("externalId", data.attributes.external_id.clone());
        row.set("externalIdKey", data.attributes.external_id_key.clone());
        row.set("active", data.attributes.active);
        row.set("updatedAt", data.updated_at);
        let stored = model::update::<user::Model>(exec, &row)
            .await?
            .ok_or_else(|| alibi_core::AuthError::Api {
                status: 404,
                code: None,
                message: "SCIM User not found".into(),
            })?;
        let states = self
            .prepare_scim_projection_for_users_with_exec(
                exec,
                &data.provisioning_domain_id,
                vec![current.user_id],
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

impl From<user::Model> for ScimUserRecord {
    fn from(row: user::Model) -> Self {
        Self {
            id: row.id,
            connection_id: row.connection_id,
            provisioning_domain_id: row.provisioning_domain_id,
            user_name: row.user_name,
            primary_email: row.primary_email,
            display_name: row.display_name,
            active: row.active,
            external_id: row.external_id,
            formatted_name: row.formatted_name,
            given_name: row.given_name,
            family_name: row.family_name,
            serialized_emails: row.serialized_emails,
            serialized_attributes: row.serialized_attributes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
