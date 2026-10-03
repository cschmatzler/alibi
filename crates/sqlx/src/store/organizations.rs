use super::SqlxStore;
use super::entities::member;
use super::entities::organization::{JsonMetadata, Model};
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::{Engine, Exec};
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlxValue;
use async_trait::async_trait;
use better_auth_core::error::AuthResult;
use better_auth_core::store::OrganizationStore;
use better_auth_core::{CreateOrganization, Organization, UpdateOrganization};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

#[async_trait]
impl<S> OrganizationStore for SqlxStore<S>
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
                    self.exec().engine(),
                )
            })
            .transpose()?;
        let mut active = ActiveRow::new();
        active.set("id", org.id.unwrap_or_else(|| Uuid::new_v4().to_string()));
        active.set("name", org.name);
        active.set("slug", org.slug);
        active.set("logo", org.logo);
        active.set("metadata", metadata.into_sql_value());
        active.set("created_at", now);
        active.set("updated_at", now);
        model::insert::<Model>(self.exec(), &active)
            .await
            .map(|model| Organization::from(&model))
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| Organization::from(&model)))
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.compare(Model::TABLE, "slug", " = ", slug);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| Organization::from(&model)))
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.column(Model::TABLE, "id");
        sql.push(" IN ");
        sql.bind_list(ids.iter().cloned());
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Organization::from)
            .collect())
    }

    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        let Some(model) = self.exec().fetch_optional::<Model>(sql).await? else {
            return Err(better_auth_core::error::AuthError::not_found(
                "Organization not found",
            ));
        };
        let active = apply_organization_update(model, update, self.exec().engine())?;
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Organization::from(&model_2))
            .ok_or_else(record_not_updated)
    }

    async fn patch_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let backend = self.exec().engine();
        let mut assignments: Vec<(&str, crate::SqlValue)> = Vec::new();
        if let Some(name) = update.name {
            assignments.push(("name", name.into()));
        }
        if let Some(slug) = update.slug {
            assignments.push(("slug", slug.into()));
        }
        if let Some(logo) = update.logo {
            assignments.push(("logo", logo.into()));
        }
        if let Some(metadata) = update.metadata {
            let metadata = JsonMetadata::for_backend(
                better_auth_core::utils::json::to_value(&metadata)?,
                backend,
            )?;
            assignments.push(("metadata", metadata.into_sql_value()));
        }
        // An empty patch is sent to the database unchanged, which rejects it.
        let mut sql = Sql::with(backend, "UPDATE ");
        sql.ident(Model::TABLE);
        sql.push(" SET ");
        for (index, (column, value)) in assignments.into_iter().enumerate() {
            if index > 0 {
                sql.push(", ");
            }
            sql.assign(column, value);
        }
        sql.push(" WHERE ");
        sql.assign("id", id);
        model::returning::<Model>(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .as_ref()
            .map(Organization::from))
    }

    async fn update_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        let Some(model) = self.exec().fetch_optional::<Model>(sql).await? else {
            return Ok(None);
        };
        let active = apply_organization_update(model, update, self.exec().engine())?;
        Ok(model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Organization::from(&model_2)))
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let id = id.to_owned();
        self.in_transaction(false, async move |tx| {
            let exec = Exec::Tx(tx);
            for table in ["member", "invitation"] {
                let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
                sql.ident(table);
                sql.push(" WHERE ");
                sql.compare(table, "organization_id", " = ", id.as_str());
                _ = exec.execute(sql).await?;
            }
            _ = exec.execute(model::delete_by_id::<Model>(exec, id)).await?;
            Ok(())
        })
        .await
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let mut members = model::select_model::<member::Model>(self.exec());
        members.push(" WHERE ");
        members.compare(member::Model::TABLE, "user_id", " = ", user_id);
        members.push(" LIMIT ");
        members.bind(self.find_many_limit());
        let member_models: Vec<member::Model> = self.exec().fetch_all(members).await?;

        if member_models.is_empty() {
            return Ok(Vec::new());
        }

        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ");
        sql.column(Model::TABLE, "id");
        sql.push(" IN ");
        sql.bind_list(
            member_models
                .iter()
                .map(|member| member.organization_id.clone()),
        );
        let organizations: HashMap<String, Organization> = self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
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
    backend: Engine,
) -> AuthResult<ActiveRow> {
    let mut active = model.into_active();
    if let Some(name) = update.name {
        active.set("name", name);
    }
    if let Some(slug) = update.slug {
        active.set("slug", slug);
    }
    if let Some(logo) = update.logo {
        active.set("logo", logo);
    }
    if let Some(metadata) = update.metadata {
        active.set(
            "metadata",
            Some(JsonMetadata::for_backend(
                better_auth_core::utils::json::to_value(&metadata)?,
                backend,
            )?)
            .into_sql_value(),
        );
    }
    active.set("updated_at", Utc::now());

    Ok(active)
}
