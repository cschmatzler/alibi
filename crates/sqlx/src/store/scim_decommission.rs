use super::{
    SqlxStore,
    entities::{scim_connection_binding as binding, scim_subject as subject, scim_user as user},
};
use crate::{model, pool::Exec, sql::Sql};
use alibi_core::{
    AuthError, AuthResult, AuthSchema,
    store::{ScimConnectionBinding, ScimProjectionCandidate},
};
use chrono::SubsecRound;
impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn get_scim_connection_binding_with_exec(
        &self,
        exec: Exec<'_>,
        id: &str,
    ) -> AuthResult<Option<ScimConnectionBinding>> {
        let mut sql = model::select_model::<binding::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimConnectionBinding", "id", " = ", id);
        model::limit_one(&mut sql);
        Ok(exec
            .fetch_optional::<binding::Model>(sql)
            .await?
            .map(Into::into))
    }
    pub(super) async fn scim_projection_candidates_with_exec(
        &self,
        exec: Exec<'_>,
        domain: &str,
        cursor: Option<&str>,
    ) -> AuthResult<Vec<ScimProjectionCandidate>> {
        let mut sql = model::select_model::<user::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimUser", "provisioningDomainId", " = ", domain);
        if let Some(cursor) = cursor {
            sql.push(" AND ");
            sql.compare("scimUser", "userId", " > ", cursor);
        }
        sql.push(" ORDER BY ");
        sql.ident("userId");
        sql.push(" ASC LIMIT 51");
        Ok(exec
            .fetch_all::<user::Model>(sql)
            .await?
            .into_iter()
            .map(|user| ScimProjectionCandidate {
                id: user.id,
                user_id: user.user_id,
            })
            .collect())
    }
    pub(super) async fn renew_scim_decommission_lease_with_exec(
        &self,
        exec: Exec<'_>,
        binding: &ScimConnectionBinding,
        lease: &str,
    ) -> AuthResult<bool> {
        let mut sql = Sql::with(exec.engine(), "UPDATE ");
        sql.ident("scimConnectionBinding");
        sql.push(" SET ");
        sql.ident("decommissionLeaseExpiresAt");
        sql.push(" = ");
        sql.bind(chrono::Utc::now().trunc_subsecs(3) + chrono::Duration::minutes(5));
        sql.push(" WHERE ");
        sql.compare("scimConnectionBinding", "id", " = ", binding.id.clone());
        sql.push(" AND ");
        sql.compare(
            "scimConnectionBinding",
            "decommissionRevision",
            " = ",
            binding.decommission_revision,
        );
        sql.push(" AND ");
        sql.compare(
            "scimConnectionBinding",
            "decommissionStatus",
            " = ",
            "reconciling",
        );
        sql.push(" AND ");
        sql.compare("scimConnectionBinding", "decommissionLeaseId", " = ", lease);
        Ok(exec.execute(sql).await? > 0)
    }
    pub(super) async fn advance_scim_decommission_with_exec(
        &self,
        exec: Exec<'_>,
        binding: &ScimConnectionBinding,
        lease: &str,
        cursor: Option<&str>,
        count: usize,
        more: bool,
    ) -> AuthResult<Option<ScimConnectionBinding>> {
        let now = chrono::Utc::now().trunc_subsecs(3);
        let mut sql = Sql::with(exec.engine(), "UPDATE ");
        sql.ident("scimConnectionBinding");
        sql.push(" SET ");
        sql.ident("decommissionRevision");
        sql.push(" = ");
        sql.ident("decommissionRevision");
        sql.push(" + 1");
        if let Some(cursor) = cursor {
            sql.push(", ");
            sql.ident("decommissionCursorUserId");
            sql.push(" = ");
            sql.bind(cursor);
            sql.push(", ");
            sql.ident("decommissionReconciledUserCount");
            sql.push(" = ");
            sql.ident("decommissionReconciledUserCount");
            sql.push(" + ");
            sql.bind(i64::try_from(count).map_err(|error| AuthError::internal(error.to_string()))?);
            sql.push(", ");
            sql.ident("decommissionBatchCount");
            sql.push(" = ");
            sql.ident("decommissionBatchCount");
            sql.push(" + 1");
        }
        if more {
            sql.push(", ");
            sql.ident("decommissionLeaseExpiresAt");
            sql.push(" = ");
            sql.bind(now + chrono::Duration::minutes(5));
        } else {
            sql.push(", ");
            sql.ident("decommissionStatus");
            sql.push(" = ");
            sql.bind("complete");
            sql.push(", ");
            sql.ident("decommissionCompletedAt");
            sql.push(" = ");
            sql.bind(now);
            sql.push(", ");
            sql.ident("decommissionLeaseId");
            sql.push(" = NULL, ");
            sql.ident("decommissionLeaseExpiresAt");
            sql.push(" = NULL");
        }
        sql.push(" WHERE ");
        sql.compare("scimConnectionBinding", "id", " = ", binding.id.clone());
        sql.push(" AND ");
        sql.compare(
            "scimConnectionBinding",
            "decommissionRevision",
            " = ",
            binding.decommission_revision,
        );
        sql.push(" AND ");
        sql.compare("scimConnectionBinding", "decommissionLeaseId", " = ", lease);
        if exec.execute(sql).await? == 0 {
            return Ok(None);
        }
        self.get_scim_connection_binding_with_exec(exec, &binding.id)
            .await
    }
    pub(super) async fn reconcile_scim_identity_with_exec(
        &self,
        exec: Exec<'_>,
        user_id: &str,
    ) -> AuthResult<bool> {
        let mut sql = model::select_model::<user::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimUser", "userId", " = ", user_id);
        sql.push(" LIMIT ");
        sql.bind(self.find_many_limit());
        let users = exec.fetch_all::<user::Model>(sql).await?;
        let connections = users
            .iter()
            .map(|user| user.connection_id.clone())
            .collect::<std::collections::HashSet<_>>();
        let retired = if connections.is_empty() {
            std::collections::HashSet::new()
        } else {
            let mut sql = model::select_model::<binding::Model>(exec);
            sql.push(" WHERE ");
            sql.column("scimConnectionBinding", "connectionId");
            sql.push(" IN ");
            sql.bind_list(connections);
            sql.push(" LIMIT ");
            sql.bind(self.find_many_limit());
            exec.fetch_all::<binding::Model>(sql)
                .await?
                .into_iter()
                .filter(|binding| binding.decommission_status != "active")
                .map(|binding| binding.connection_id)
                .collect()
        };
        let participating = users
            .iter()
            .filter(|user| !retired.contains(&user.connection_id))
            .collect::<Vec<_>>();
        let mut sql = model::select_model::<subject::Model>(exec);
        sql.push(" WHERE ");
        sql.compare("scimSubject", "userId", " = ", user_id);
        model::limit_one(&mut sql);
        if let Some(subject) = exec.fetch_optional::<subject::Model>(sql).await?
            && let Some(profile) = &subject.profile_source_id
            && !participating.iter().any(|source| source.id == *profile)
        {
            let mut sql = Sql::with(exec.engine(), "UPDATE ");
            sql.ident("scimSubject");
            sql.push(" SET ");
            sql.ident("profileSourceId");
            sql.push(" = NULL, ");
            sql.ident("revision");
            sql.push(" = ");
            sql.ident("revision");
            sql.push(" + 1, ");
            sql.ident("updatedAt");
            sql.push(" = ");
            sql.bind(chrono::Utc::now().trunc_subsecs(3));
            sql.push(" WHERE ");
            sql.compare("scimSubject", "id", " = ", subject.id);
            sql.push(" AND ");
            sql.compare("scimSubject", "revision", " = ", subject.revision);
            sql.push(" AND ");
            sql.compare("scimSubject", "profileSourceId", " = ", profile.clone());
            if exec.execute(sql).await? == 0 {
                return Err(AuthError::internal(
                    "The SCIM User identity changed concurrently; retry the request.",
                ));
            }
        }
        Ok(participating.iter().any(|source| source.active))
    }
}
