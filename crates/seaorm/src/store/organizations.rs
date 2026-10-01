use async_trait::async_trait;

use chrono::Utc;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbBackend, DbErr, EntityTrait, IntoActiveModel, QueryFilter,
    QuerySelect, Set, TransactionTrait,
};

use std::collections::HashMap;

use uuid::Uuid;

use better_auth_core::store::OrganizationStore;

use crate::schema::AuthSchema;

use super::entities;

use super::entities::organization::{ActiveModel, Column, Entity, JsonMetadata, Model};

use super::{SeaOrmStore, map_db_err};

use better_auth_core::error::AuthResult;

use better_auth_core::{CreateOrganization, Organization, UpdateOrganization};

#[async_trait]
impl<S> OrganizationStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_organization(&self, org: CreateOrganization) -> AuthResult<Organization> {
        let now = Utc::now();
        let metadata = org
            .metadata
            .map(|metadata| {
                JsonMetadata::for_backend(
                    better_auth_core::utils::json::to_value(&metadata)?,
                    self.connection().get_database_backend(),
                )
            })
            .transpose()?;
        ActiveModel {
            id: Set(org.id.unwrap_or_else(|| Uuid::new_v4().to_string())),
            name: Set(org.name),
            slug: Set(org.slug),
            logo: Set(org.logo),
            metadata: Set(metadata),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(self.connection())
        .await
        .map(|model| Organization::from(&model))
        .map_err(map_db_err)
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Organization::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        Entity::find()
            .filter(Column::Slug.eq(slug))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Organization::from(&model)))
            .map_err(map_db_err)
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        Entity::find()
            .filter(Column::Id.is_in(ids.iter().cloned()))
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Organization::from).collect())
            .map_err(map_db_err)
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(better_auth_core::error::AuthError::not_found(
                "Organization not found",
            ));
        };

        let active =
            apply_organization_update(model, update, self.connection().get_database_backend())?;

        active
            .update(self.connection())
            .await
            .map(|model_2| Organization::from(&model_2))
            .map_err(map_db_err)
    }

    async fn update_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let Some(model) = Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let active =
            apply_organization_update(model, update, self.connection().get_database_backend())?;
        match active.update(self.connection()).await {
            Ok(model_2) => Ok(Some(Organization::from(&model_2))),
            Err(DbErr::RecordNotUpdated) => Ok(None),
            Err(error) => Err(map_db_err(error)),
        }
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let transaction = self.connection().begin().await.map_err(map_db_err)?;
        let _ignored_map_err = entities::member::Entity::delete_many()
            .filter(entities::member::Column::OrganizationId.eq(id))
            .exec(&transaction)
            .await
            .map_err(map_db_err)?;
        let _ignored_map_err_2 = entities::invitation::Entity::delete_many()
            .filter(entities::invitation::Column::OrganizationId.eq(id))
            .exec(&transaction)
            .await
            .map_err(map_db_err)?;
        let _ignored_map_err_3 = Entity::delete_by_id(id.to_owned())
            .exec(&transaction)
            .await
            .map_err(map_db_err)?;
        transaction.commit().await.map_err(map_db_err)
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let member_models = entities::member::Entity::find()
            .filter(entities::member::Column::UserId.eq(user_id))
            .limit(self.config().advanced.database.default_find_many_limit as u64)
            .all(self.connection())
            .await
            .map_err(map_db_err)?;

        if member_models.is_empty() {
            return Ok(Vec::new());
        }

        let organization_ids: Vec<String> = member_models
            .iter()
            .map(|member| member.organization_id.clone())
            .collect();

        let organizations: HashMap<String, Organization> = Entity::find()
            .filter(Column::Id.is_in(organization_ids))
            .all(self.connection())
            .await
            .map_err(map_db_err)?
            .into_iter()
            .map(|model| (model.id.clone(), Organization::from(&model)))
            .collect();
        // The source maps the member page's joined organizations. Repeated
        // memberships repeat the organization; organization creation order
        // cannot reorder this page. Missing joins retain the existing store's
        // omission behavior, rather than inventing a nullable public result.
        Ok(member_models
            .into_iter()
            .filter_map(|member| organizations.get(&member.organization_id).cloned())
            .collect())
    }
}

fn apply_organization_update(
    model: Model,
    update: UpdateOrganization,
    backend: DbBackend,
) -> AuthResult<ActiveModel> {
    let mut active = model.into_active_model();
    if let Some(name) = update.name {
        active.name = Set(name);
    }
    if let Some(slug) = update.slug {
        active.slug = Set(slug);
    }
    if let Some(logo) = update.logo {
        active.logo = Set(logo);
    }
    if let Some(metadata) = update.metadata {
        active.metadata = Set(Some(JsonMetadata::for_backend(
            better_auth_core::utils::json::to_value(&metadata)?,
            backend,
        )?));
    }
    active.updated_at = Set(Utc::now());

    Ok(active)
}
