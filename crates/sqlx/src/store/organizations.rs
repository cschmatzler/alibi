use super::SqlxStore;
use super::entities::organization::{JsonMetadata, Model};
use crate::SqlValue;
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow};
use crate::organization_models::Row;
use crate::pool::{Engine, Exec};
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlxValue;
use alibi_core::error::AuthResult;
use alibi_core::store::OrganizationStore;
use alibi_core::{CreateOrganization, Organization, UpdateOrganization};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;

#[async_trait]
impl<S> OrganizationStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_organization(&self, mut org: CreateOrganization) -> AuthResult<Organization> {
        let now = Utc::now();
        let metadata = org
            .metadata
            .map(|metadata| {
                JsonMetadata::for_backend(
                    alibi_core::utils::json::to_value(&metadata)?,
                    self.exec().engine(),
                )
            })
            .transpose()?;
        let mut active = ActiveRow::new();
        active.set(
            "id",
            match org.id {
                Some(id) => id,
                None => self
                    .generated_id(
                        self.exec(),
                        "organization",
                        self.organization_models.organization.table(),
                        self.organization_models
                            .organization
                            .physical("id")
                            .ok_or_else(|| {
                                alibi_core::AuthError::config("Organization model has no ID column")
                            })?,
                    )
                    .await?
                    .unwrap_or_else(|| self.organization_models.organization.new_id()),
            },
        );
        active.set("name", org.name);
        active.set("slug", org.slug);
        active.set("logo", org.logo);
        active.set("metadata", metadata.into_sql_value());
        active.set("created_at", now);
        active.set("updated_at", now);
        self.organization_models
            .organization
            .set_fields(self.exec(), &mut active, &mut org.additional_fields)
            .await?;
        self.organization_models
            .organization
            .insert(self.exec(), &active)
            .await
            .map(|model| Organization::from(&model))
    }

    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        let mut sql = self
            .organization_models
            .organization
            .by_id(self.exec(), id)?;
        model::limit_one(&mut sql);
        Ok(self
            .organization_models
            .organization
            .fetch_optional(self.exec(), sql)
            .await?
            .map(|model| Organization::from(&model)))
    }

    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        let mut sql = self.organization_models.organization.select(self.exec());
        sql.push(" WHERE ");
        self.organization_models
            .organization
            .compare(&mut sql, "slug", " = ", slug)?;
        model::limit_one(&mut sql);
        Ok(self
            .organization_models
            .organization
            .fetch_optional(self.exec(), sql)
            .await?
            .map(|model| Organization::from(&model)))
    }

    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut sql = self.organization_models.organization.select(self.exec());
        sql.push(" WHERE ");
        self.organization_models
            .organization
            .column(&mut sql, "id")?;
        sql.push(" IN ");
        self.organization_models
            .organization
            .bind_list(&mut sql, "id", ids.iter().cloned())?;
        Ok(self
            .organization_models
            .organization
            .fetch_all(self.exec(), sql)
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
        let mut sql = self
            .organization_models
            .organization
            .by_id(self.exec(), id)?;
        model::limit_one(&mut sql);
        let Some(model) = self
            .organization_models
            .organization
            .fetch_optional(self.exec(), sql)
            .await?
        else {
            return Err(alibi_core::error::AuthError::not_found(
                "Organization not found",
            ));
        };
        let mut fields = update.additional_fields.clone();
        let mut active = apply_organization_update(model, update, self.exec().engine())?;
        self.organization_models
            .organization
            .set_fields(self.exec(), &mut active, &mut fields)
            .await?;
        self.organization_models
            .organization
            .update(self.exec(), &active)
            .await?
            .map(|model_2| Organization::from(&model_2))
            .ok_or_else(record_not_updated)
    }

    async fn patch_organization_if_present(
        &self,
        id: &str,
        mut update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let backend = self.exec().engine();
        let mut assignments: Vec<(&str, SqlValue)> = Vec::new();
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
            let metadata =
                JsonMetadata::for_backend(alibi_core::utils::json::to_value(&metadata)?, backend)?;
            assignments.push(("metadata", metadata.into_sql_value()));
        }
        let mut additional = ActiveRow::new();
        self.organization_models
            .organization
            .set_fields(self.exec(), &mut additional, &mut update.additional_fields)
            .await?;
        assignments.extend(
            additional
                .changed()
                .map(|(name, value)| (name, value.clone())),
        );
        // An empty patch is sent to the database unchanged, which rejects it.
        let mut sql = Sql::with(backend, "UPDATE ");
        sql.ident(self.organization_models.organization.table());
        sql.push(" SET ");
        for (index, (column, value)) in assignments.into_iter().enumerate() {
            if index > 0 {
                sql.push(", ");
            }
            self.organization_models
                .organization
                .assign(&mut sql, column, value)?;
        }
        sql.push(" WHERE ");
        self.organization_models
            .organization
            .assign(&mut sql, "id", id)?;
        self.organization_models.organization.returning(&mut sql);
        Ok(self
            .organization_models
            .organization
            .fetch_optional(self.exec(), sql)
            .await?
            .as_ref()
            .map(Organization::from))
    }

    async fn update_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let mut sql = self
            .organization_models
            .organization
            .by_id(self.exec(), id)?;
        model::limit_one(&mut sql);
        let Some(model) = self
            .organization_models
            .organization
            .fetch_optional(self.exec(), sql)
            .await?
        else {
            return Ok(None);
        };
        let mut fields = update.additional_fields.clone();
        let mut active = apply_organization_update(model, update, self.exec().engine())?;
        self.organization_models
            .organization
            .set_fields(self.exec(), &mut active, &mut fields)
            .await?;
        Ok(self
            .organization_models
            .organization
            .update(self.exec(), &active)
            .await?
            .map(|model_2| Organization::from(&model_2)))
    }

    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let id = id.to_owned();
        self.in_transaction(false, async move |tx| {
            let exec = Exec::tx(tx);
            for query in [
                self.organization_models
                    .member
                    .delete_for_organization(exec, &id)?,
                self.organization_models
                    .invitation
                    .delete_for_organization(exec, &id)?,
            ] {
                _ = exec.execute(query).await?;
            }
            _ = exec
                .execute(
                    self.organization_models
                        .organization
                        .delete_by_id(exec, id)?,
                )
                .await?;
            Ok(())
        })
        .await
    }

    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let mut members = self.organization_models.member.select(self.exec());
        members.push(" WHERE ");
        self.organization_models
            .member
            .compare(&mut members, "user_id", " = ", user_id)?;
        members.push(" LIMIT ");
        members.bind(self.find_many_limit());
        let member_models = self
            .organization_models
            .member
            .fetch_all(self.exec(), members)
            .await?;

        if member_models.is_empty() {
            return Ok(Vec::new());
        }

        let mut sql = self.organization_models.organization.select(self.exec());
        sql.push(" WHERE ");
        self.organization_models
            .organization
            .column(&mut sql, "id")?;
        sql.push(" IN ");
        self.organization_models.organization.bind_list(
            &mut sql,
            "id",
            member_models
                .iter()
                .map(|member| member.organization_id.clone()),
        )?;
        let organizations: HashMap<String, Organization> = self
            .organization_models
            .organization
            .fetch_all(self.exec(), sql)
            .await?
            .into_iter()
            .map(|model| (model.id.clone(), Organization::from(&model)))
            .collect();
        // Source maps the member page's joined organizations: repeated
        // memberships repeat the organization, and missing joins are omitted.
        Ok(member_models
            .into_iter()
            .filter_map(|member| organizations.get(&member.organization_id).cloned())
            .collect())
    }
}

fn apply_organization_update(
    model: Row<Model>,
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
                alibi_core::utils::json::to_value(&metadata)?,
                backend,
            )?)
            .into_sql_value(),
        );
    }
    active.set("updated_at", Utc::now());

    Ok(active)
}
