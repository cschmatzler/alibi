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
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
use uuid::Uuid;

fn scoped(organization_id: &str, selector: &OrganizationRoleSelector) -> sea_orm::Select<Entity> {
    let query = Entity::find().filter(Column::OrganizationId.eq(organization_id));
    match selector {
        OrganizationRoleSelector::Id(id) => query.filter(Column::Id.eq(id)),
        OrganizationRoleSelector::Name(name) => query.filter(Column::Role.eq(name)),
    }
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
    async fn update_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let row = scoped(organization_id, selector)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::bad_request("Role not found"))?;
        let mut active = row.into_active_model();
        if let Some(role) = update.role {
            active.role = Set(role);
        }
        if let Some(permission) = update.permission {
            active.permission = Set(serde_json::to_string(&permission)?);
        }
        active.updated_at = Set(Some(Utc::now()));
        active
            .update(self.connection())
            .await
            .map_err(map_db_err)?
            .try_into()
    }
    async fn delete_organization_role(
        &self,
        organization_id: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        let Some(role) = scoped(organization_id, selector)
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(false);
        };
        Entity::delete_many()
            .filter(Column::Id.eq(role.id))
            .filter(Column::OrganizationId.eq(organization_id))
            .exec(self.connection())
            .await
            .map(|r| r.rows_affected > 0)
            .map_err(map_db_err)
    }
}
