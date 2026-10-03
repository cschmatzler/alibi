use super::SqlxStore;
use super::entities::member;
use super::entities::organization_role::Model;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::schema::AuthSchema;
use crate::sql::Sql;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::OrganizationRoleStore;
use better_auth_core::types::{
    CreateOrganizationRole, OrganizationRole, OrganizationRoleSelector, UpdateOrganizationRole,
};
use chrono::Utc;
use uuid::Uuid;

/// Append the organization scope and role selector.
fn scope(sql: &mut Sql, organization_id: &str, selector: &OrganizationRoleSelector) {
    sql.push(" WHERE ")
        .column(Model::TABLE, "organization_id")
        .push(" = ")
        .bind(organization_id)
        .push(" AND ");
    match selector {
        OrganizationRoleSelector::Id(id) => {
            sql.column(Model::TABLE, "id").push(" = ").bind(id.as_str());
        }
        OrganizationRoleSelector::Name(name) => {
            sql.column(Model::TABLE, "role")
                .push(" = ")
                .bind(name.as_str());
        }
    }
}

#[async_trait]
impl<S: AuthSchema> OrganizationRoleStore for SqlxStore<S> {
    async fn create_organization_role(
        &self,
        data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut active = ActiveRow::new();
        active.set("id", Uuid::new_v4().to_string());
        active.set("organization_id", data.organization_id);
        active.set("role", data.role);
        active.set("permission", serde_json::to_string(&data.permission)?);
        active.set("created_at", Utc::now());
        active.set("updated_at", None::<chrono::DateTime<Utc>>);
        model::insert::<Model>(self.exec(), &active)
            .await?
            .try_into()
    }
    async fn get_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>> {
        let mut sql = model::select_model::<Model>(self.exec());
        scope(&mut sql, organization_id, selector);
        model::limit_one(&mut sql);
        self.exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(TryInto::try_into)
            .transpose()
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ")
            .column(Model::TABLE, "organization_id")
            .push(" = ")
            .bind(organization_id)
            .push(" LIMIT ")
            .bind(self.find_many_limit());
        self.exec()
            .fetch_all::<Model>(sql)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<usize> {
        let mut sql = Sql::with(self.exec().backend(), "SELECT COUNT(*) FROM ");
        sql.ident(Model::TABLE)
            .push(" WHERE ")
            .column(Model::TABLE, "organization_id")
            .push(" = ")
            .bind(organization_id);
        let count = self
            .exec()
            .fetch_scalar::<i64>(sql)
            .await?
            .unwrap_or_default();
        usize::try_from(count)
            .map_err(|_error| AuthError::internal("Organization role count overflow"))
    }
    async fn has_organization_role_members(
        &self,
        organization_id: &str,
        role: &str,
    ) -> AuthResult<bool> {
        let mut sql = model::select_model::<member::Model>(self.exec());
        sql.push(" WHERE ")
            .column(member::Model::TABLE, "organization_id")
            .push(" = ")
            .bind(organization_id)
            .push(" AND ")
            .column(member::Model::TABLE, "role")
            .push(" LIKE ")
            .bind(format!("%{role}%"))
            .push(" LIMIT ")
            .bind(self.find_many_limit());
        let members: Vec<member::Model> = self.exec().fetch_all(sql).await?;
        Ok(members.iter().any(|member| {
            member
                .role
                .split(',')
                .map(str::trim)
                .any(|name| name == role)
        }))
    }
    async fn update_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let mut select = model::select_model::<Model>(self.exec());
        scope(&mut select, organization_id, selector);
        model::limit_one(&mut select);
        let mut row = self
            .exec()
            .fetch_optional::<Model>(select)
            .await?
            .ok_or_else(|| AuthError::bad_request("Role not found"))?;
        let updated_at = Utc::now();
        let mut sql = Sql::with(self.exec().backend(), "UPDATE ");
        sql.ident(Model::TABLE)
            .push(" SET ")
            .ident("updated_at")
            .push(" = ")
            .bind(Some(updated_at));
        if let Some(role) = update.role {
            sql.push(", ").ident("role").push(" = ").bind(role.clone());
            row.role = role;
        }
        if let Some(permission) = update.permission {
            let permission = serde_json::to_string(&permission)?;
            sql.push(", ")
                .ident("permission")
                .push(" = ")
                .bind(permission.clone());
            row.permission = permission;
        }
        scope(&mut sql, organization_id, selector);
        self.exec().execute(sql).await?;
        row.updated_at = Some(updated_at);
        row.try_into()
    }
    async fn delete_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        let mut sql = Sql::with(self.exec().backend(), "DELETE FROM ");
        sql.ident(Model::TABLE);
        scope(&mut sql, organization_id, selector);
        Ok(self.exec().execute(sql).await? > 0)
    }
}
