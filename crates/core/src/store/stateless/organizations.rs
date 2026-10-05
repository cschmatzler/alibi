use super::*;

fn patch(row: &mut Organization, update: UpdateOrganization) {
    if let Some(name) = update.name {
        row.name = name;
    }
    if let Some(slug) = update.slug {
        row.slug = slug;
    }
    if let Some(logo) = update.logo {
        row.logo = logo;
    }
    if let Some(metadata) = update.metadata {
        row.metadata = Some(metadata);
    }
}

#[async_trait]
impl OrganizationStore for StatelessStore {
    async fn create_organization(&self, data: CreateOrganization) -> AuthResult<Organization> {
        let now = Utc::now();
        let row = Organization {
            additional_fields: Default::default(),
            id: data.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            name: data.name,
            slug: data.slug,
            logo: data.logo,
            metadata: data.metadata,
            created_at: now,
            updated_at: now,
        };
        drop(
            self.organization_state()?
                .organizations
                .insert(row.id.clone(), row.clone()),
        );
        Ok(row)
    }
    async fn get_organization_by_id(&self, id: &str) -> AuthResult<Option<Organization>> {
        Ok(self.organization_state()?.organizations.get(id).cloned())
    }
    async fn get_organization_by_slug(&self, slug: &str) -> AuthResult<Option<Organization>> {
        Ok(self
            .organization_state()?
            .organizations
            .values()
            .find(|row| row.slug == slug)
            .cloned())
    }
    async fn list_organizations_by_ids(&self, ids: &[String]) -> AuthResult<Vec<Organization>> {
        Ok(self
            .organization_state()?
            .organizations
            .values()
            .filter(|row| ids.contains(&row.id))
            .cloned()
            .collect())
    }
    async fn update_organization(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Organization> {
        self.update_organization_if_present(id, update)
            .await?
            .ok_or_else(|| AuthError::not_found("Organization not found"))
    }
    async fn patch_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let mut state = self.organization_state()?;
        let Some(row) = state.organizations.get_mut(id) else {
            return Ok(None);
        };
        // Memory adapter Object.assign accepts an empty patch. No synthesized timestamp.
        patch(row, update);
        Ok(Some(row.clone()))
    }
    async fn update_organization_if_present(
        &self,
        id: &str,
        update: UpdateOrganization,
    ) -> AuthResult<Option<Organization>> {
        let mut state = self.organization_state()?;
        let Some(row) = state.organizations.get_mut(id) else {
            return Ok(None);
        };
        patch(row, update);
        row.updated_at = Utc::now();
        Ok(Some(row.clone()))
    }
    async fn delete_organization(&self, id: &str) -> AuthResult<()> {
        let mut state = self.organization_state()?;
        state.members.retain(|_, row| row.organization_id != id);
        state.invitations.retain(|_, row| row.organization_id != id);
        drop(state.organizations.shift_remove(id));
        Ok(())
    }
    async fn list_user_organizations(&self, user_id: &str) -> AuthResult<Vec<Organization>> {
        let state = self.organization_state()?;
        Ok(state
            .members
            .values()
            .filter(|row| row.user_id == user_id)
            .take(self.find_many_limit)
            .filter_map(|row| state.organizations.get(&row.organization_id).cloned())
            .collect())
    }
}
