use super::entities::member;
use super::entities::organization_role::{self, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::error::{AuthError, AuthResult};
use crate::schema::AuthSchema;
use async_trait::async_trait;
use better_auth_core::store::OrganizationRoleStore;
use better_auth_core::types::{
    CreateOrganizationRole, OrganizationRole, OrganizationRoleSelector, UpdateOrganizationRole,
};
use chrono::Utc;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
use uuid::Uuid;

fn scope(organization_id: &str, selector: &OrganizationRoleSelector) -> Condition {
    let predicate = Condition::all().add(Column::OrganizationId.eq(organization_id));
    match selector {
        OrganizationRoleSelector::Id(id) => predicate.add(Column::Id.eq(id)),
        OrganizationRoleSelector::Name(name) => predicate.add(Column::Role.eq(name)),
    }
}

fn scoped(organization_id: &str, selector: &OrganizationRoleSelector) -> sea_orm::Select<Entity> {
    Entity::find().filter(scope(organization_id, selector))
}

#[async_trait]
impl<S: AuthSchema> OrganizationRoleStore for SeaOrmStore<S> {
    async fn create_organization_role(
        &self,
        data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        organization_role::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(data.organization_id),
            role: Set(data.role),
            permission: Set(serde_json::to_string(&data.permission)?),
            created_at: Set(Utc::now()),
            updated_at: Set(None),
        }
        .insert(self.connection())
        .await
        .map_err(map_db_err)?
        .try_into()
    }
    async fn get_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>> {
        scoped(organization_id, selector)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .map(TryInto::try_into)
            .transpose()
    }
    async fn list_organization_roles(
        &self,
        organization_id: &str,
    ) -> AuthResult<Vec<OrganizationRole>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }
    async fn count_organization_roles(&self, organization_id: &str) -> AuthResult<usize> {
        let count = Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .count(self.connection())
            .await
            .map_err(map_db_err)?;
        usize::try_from(count).map_err(|_| AuthError::internal("Organization role count overflow"))
    }
    async fn has_organization_role_members(
        &self,
        organization_id: &str,
        role: &str,
    ) -> AuthResult<bool> {
        let members = member::Entity::find()
            .filter(member::Column::OrganizationId.eq(organization_id))
            .filter(member::Column::Role.contains(role))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;
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
        let mut row = scoped(organization_id, selector)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::bad_request("Role not found"))?;
        let updated_at = Utc::now();
        let mut query = Entity::update_many()
            .filter(scope(organization_id, selector))
            .col_expr(Column::UpdatedAt, Expr::value(Some(updated_at)));
        if let Some(role) = update.role {
            query = query.col_expr(Column::Role, Expr::value(role.clone()));
            row.role = role;
        }
        if let Some(permission) = update.permission {
            let permission = serde_json::to_string(&permission)?;
            query = query.col_expr(Column::Permission, Expr::value(permission.clone()));
            row.permission = permission;
        }
        let _ = query.exec(self.connection()).await.map_err(map_db_err)?;
        row.updated_at = Some(updated_at);
        row.try_into()
    }
    async fn delete_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        Entity::delete_many()
            .filter(scope(organization_id, selector))
            .exec(self.connection())
            .await
            .map(|r| r.rows_affected > 0)
            .map_err(map_db_err)
    }
}
