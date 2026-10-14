//! Atomic canonical User insertion, identity subject fencing, and tombstone consumption.
use super::{
    SqlxStore,
    entities::{scim_subject as subject, scim_user as user},
};
use crate::{
    model::{self, ActiveRow},
    pool::Exec,
    sql::Sql,
};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{CreateScimUser, ScimProjectionPreparedUser, ScimUserRecord},
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
impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn assert_scim_user_keys_with_exec(
        &self,
        exec: Exec<'_>,
        connection: &str,
        name_key: &str,
        external_key: Option<&str>,
        connection_user_key: Option<&str>,
        exclude: Option<&str>,
    ) -> AuthResult<()> {
        for (field, value, detail) in [
            (
                "userNameKey",
                Some(name_key),
                "SCIM User userName already exists",
            ),
            (
                "externalIdKey",
                external_key,
                "SCIM User externalId already exists",
            ),
            (
                "connectionUserKey",
                connection_user_key,
                "This connection already provisions the resolved Better Auth User",
            ),
        ] {
            if let Some(value) = value {
                let mut sql = model::select_model::<user::Model>(exec);
                sql.push(" WHERE ");
                sql.compare("scimUser", "connectionId", " = ", connection.to_owned());
                sql.push(" AND ");
                sql.compare("scimUser", field, " = ", value);
                model::limit_one(&mut sql);
                if exec
                    .fetch_optional::<user::Model>(sql)
                    .await?
                    .is_some_and(|row| Some(row.id.as_str()) != exclude)
                {
                    return Err(conflict(detail));
                }
            }
        }
        Ok(())
    }

    pub(super) async fn acquire_scim_subject_with_exec(
        &self,
        exec: Exec<'_>,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> AuthResult<subject::Model> {
        let mut sql = model::select_model::<subject::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimSubject", "userId", " = ", user_id.to_owned());
        model::limit_one(&mut sql);
        let current = if let Some(current) = exec.fetch_optional::<subject::Model>(sql).await? {
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimSubject");
            sql.push(" SET ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1, ");
            sql.ident("updatedAt");
            sql.push(" = ");
            sql.bind(now);
            sql.push(" WHERE ");
            sql.compare("scimSubject", "id", " = ", current.id);
            sql.push(" AND ");
            sql.compare("scimSubject", "revision", " = ", current.revision);
            model::returning::<subject::Model>(&mut sql);
            exec.fetch_optional::<subject::Model>(sql)
                .await?
                .ok_or_else(identity_conflict)?
        } else {
            let mut row = ActiveRow::new();
            row.set(
                "id",
                self.generated_id(exec, "scimSubject", "scimSubject", "id")
                    .await?
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            );
            row.set("userId", user_id.to_owned());
            row.set("revision", 1i64);
            row.set("createdAt", now);
            row.set("updatedAt", now);
            model::insert::<subject::Model>(exec, &row).await?
        };
        Ok(current)
    }

    pub(super) async fn create_scim_user_with_exec(
        &self,
        exec: Exec<'_>,
        data: CreateScimUser,
        roles: bool,
    ) -> AuthResult<(ScimUserRecord, Vec<ScimProjectionPreparedUser>)> {
        self.assert_scim_user_keys_with_exec(
            exec,
            &data.connection_id,
            &data.attributes.user_name_key,
            data.attributes.external_id_key.as_deref(),
            Some(&data.connection_user_key),
            None,
        )
        .await?;
        let current = self
            .acquire_scim_subject_with_exec(exec, &data.user_id, data.created_at)
            .await?;
        let id = self
            .generated_id(exec, "scimUser", "scimUser", "id")
            .await?
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut row = ActiveRow::new();
        row.set("id", id.clone());
        row.set("connectionId", data.connection_id.clone());
        row.set("provisioningDomainId", data.provisioning_domain_id.clone());
        row.set("userId", data.user_id.clone());
        row.set("connectionUserKey", data.connection_user_key.clone());
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
        row.set("orderKey", data.order_key.clone());
        row.set("active", data.attributes.active);
        row.set("createdAt", data.created_at);
        row.set("updatedAt", data.created_at);
        let stored = model::insert::<user::Model>(exec, &row).await?;
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
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimSubject");
            sql.push(" SET ");
            sql.ident("profileSourceId");
            sql.push(" = ");
            sql.bind(id);
            sql.push(", ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1, ");
            sql.ident("updatedAt");
            sql.push(" = ");
            sql.bind(data.created_at);
            sql.push(" WHERE ");
            sql.compare("scimSubject", "id", " = ", current.id);
            sql.push(" AND ");
            sql.compare("scimSubject", "revision", " = ", current.revision);
            sql.push(" AND ");
            sql.column("scimSubject", "profileSourceId");
            sql.push(" IS NULL");
            if exec.execute(sql).await? == 0 {
                return Err(identity_conflict());
            }
        }
        if let Some(id) = data.tombstone_id {
            let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
            sql.ident("scimIdentityTombstone");
            sql.push(" WHERE ");
            sql.compare("scimIdentityTombstone", "id", " = ", id);
            _ = exec.execute(sql).await?;
        }
        let states = self
            .prepare_scim_projection_for_users_with_exec(
                exec,
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
