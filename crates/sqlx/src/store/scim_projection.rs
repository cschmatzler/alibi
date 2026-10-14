use super::{
    SqlxStore,
    entities::{
        scim_connection_binding as binding, scim_projection_grant as grant,
        scim_subject as subject, scim_user as user,
    },
};
use crate::{model, pool::Exec, sql::Sql};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{ScimIdentitySource, ScimProjectedUserState, ScimProjectionPreparedUser},
};
use chrono::SubsecRound;
impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn prepare_scim_projection_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        ids: &[String],
    ) -> AuthResult<Vec<ScimProjectionPreparedUser>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut sql = model::select_model::<user::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimUser", "provisioningDomainId", " = ", domain);
        sql.push(" AND ");
        sql.column("scimUser", "id");
        sql.push(" IN ");
        sql.bind_list(ids.iter().cloned());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let requested = exec.fetch_all::<user::Model>(sql).await?;
        let mut user_ids = Vec::new();
        for id in ids {
            if let Some(user) = requested.iter().find(|user| user.id == *id)
                && !user_ids.contains(&user.user_id)
            {
                user_ids.push(user.user_id.clone());
            }
        }
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut sorted = user_ids.clone();
        sorted.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        let mut sql = model::select_model::<subject::Model>(exec);
        sql.push(" WHERE ");
        sql.column("scimSubject", "userId");
        sql.push(" IN ");
        sql.bind_list(sorted.iter().cloned());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let subjects = exec.fetch_all::<subject::Model>(sql).await?;
        if subjects.len() != sorted.len() {
            return Err(AuthError::internal(
                "A SCIM User selected for projection has no subject aggregate.",
            ));
        }
        let updated_at = chrono::Utc::now().trunc_subsecs(3);
        for user_id in sorted {
            let subject = subjects
                .iter()
                .find(|subject| subject.user_id == user_id)
                .ok_or_else(|| {
                    AuthError::internal(
                        "A SCIM User selected for projection has no subject aggregate.",
                    )
                })?;
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimSubject");
            sql.push(" SET ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1, ");
            sql.ident("updatedAt");
            sql.push(" = ");
            sql.bind(updated_at);
            sql.push(" WHERE ");
            sql.compare("scimSubject", "id", " = ", subject.id.clone());
            sql.push(" AND ");
            sql.compare("scimSubject", "revision", " = ", subject.revision);
            if exec.execute(sql).await? == 0 {
                return Err(AuthError::internal(
                    "The SCIM projection subject changed concurrently; retry the request.",
                ));
            }
        }
        let mut sql = model::select_model::<user::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimUser", "provisioningDomainId", " = ", domain);
        sql.push(" AND ");
        sql.column("scimUser", "userId");
        sql.push(" IN ");
        sql.bind_list(user_ids.iter().cloned());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let users = exec.fetch_all::<user::Model>(sql).await?;
        let connections = users
            .iter()
            .map(|user| user.connection_id.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut sql = model::select_model::<binding::Model>(exec);
        sql.push(" WHERE ");
        sql.column("scimConnectionBinding", "connectionId");
        sql.push(" IN ");
        sql.bind_list(connections);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let retired = exec
            .fetch_all::<binding::Model>(sql)
            .await?
            .into_iter()
            .filter(|binding| binding.decommission_status != "active")
            .map(|binding| binding.connection_id)
            .collect::<std::collections::HashSet<_>>();
        let mut sql = model::select_model::<grant::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimProjectionGrant", "provisioningDomainId", " = ", domain);
        sql.push(" AND ");
        sql.column("scimProjectionGrant", "userId");
        sql.push(" IN ");
        sql.bind_list(user_ids.iter().cloned());
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let grants = exec.fetch_all::<grant::Model>(sql).await?;
        Ok(user_ids
            .into_iter()
            .map(|user_id| {
                let mut sources = users
                    .iter()
                    .filter(|user| {
                        user.user_id == user_id && !retired.contains(&user.connection_id)
                    })
                    .map(|user| ScimIdentitySource {
                        id: user.id.clone(),
                        connection_id: user.connection_id.clone(),
                        provisioning_domain_id: user.provisioning_domain_id.clone(),
                        active: user.active,
                    })
                    .collect::<Vec<_>>();
                sources.sort_by(|left, right| left.id.cmp(&right.id));
                let removed_grant_ids = grants
                    .iter()
                    .filter(|grant| grant.user_id == user_id)
                    .map(|grant| grant.id.clone())
                    .collect();
                ScimProjectionPreparedUser {
                    state: ScimProjectedUserState {
                        provisioning_domain_id: domain.into(),
                        user_id,
                        active: sources.iter().any(|source| source.active),
                        sources,
                        grants: Vec::new(),
                    },
                    removed_grant_ids,
                }
            })
            .collect())
    }
    pub(super) async fn remove_scim_projection_grants_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        user_id: &str,
        ids: &[String],
    ) -> AuthResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident("scimProjectionGrant");
        sql.push(" WHERE ");
        sql.compare("scimProjectionGrant", "provisioningDomainId", " = ", domain);
        sql.push(" AND ");
        sql.compare("scimProjectionGrant", "userId", " = ", user_id);
        sql.push(" AND ");
        sql.column("scimProjectionGrant", "id");
        sql.push(" IN ");
        sql.bind_list(ids.iter().cloned());
        _ = exec.execute(sql).await?;
        Ok(())
    }
}
