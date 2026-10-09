use super::*;

fn selected(
    row: &OrganizationRole,
    organization_id: &str,
    selector: &OrganizationRoleSelector,
) -> bool {
    row.organization_id == organization_id
        && match selector {
            OrganizationRoleSelector::Id(id) => row.id == *id,
            OrganizationRoleSelector::Name(name) => row.role == *name,
        }
}
#[async_trait]
impl OrganizationRoleStore for StatelessStore {
    async fn create_organization_role(
        &self,
        data: CreateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let row = OrganizationRole {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: data.organization_id,
            role: data.role,
            permission: serde_json::to_string(&data.permission)?.into(),
            created_at: Utc::now(),
            updated_at: None,
        };
        _ = self
            .organization_state()?
            .roles
            .insert(row.id.clone(), row.clone());
        Ok(row)
    }
    async fn get_organization_role(
        &self,
        org: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<Option<OrganizationRole>> {
        Ok(self
            .organization_state()?
            .roles
            .values()
            .find(|row| selected(row, org, selector))
            .cloned())
    }
    async fn list_organization_roles(&self, org: &str) -> AuthResult<Vec<OrganizationRole>> {
        Ok(self
            .organization_state()?
            .roles
            .values()
            .filter(|row| row.organization_id == org)
            .take(self.find_many_limit)
            .cloned()
            .collect())
    }
    async fn count_organization_roles(&self, org: &str) -> AuthResult<usize> {
        Ok(self
            .organization_state()?
            .roles
            .values()
            .filter(|row| row.organization_id == org)
            .count())
    }
    async fn has_organization_role_members(&self, org: &str, role: &str) -> AuthResult<bool> {
        Ok(self
            .organization_state()?
            .members
            .values()
            .filter(|row| row.organization_id == org && row.role.contains(role))
            .take(self.find_many_limit)
            .any(|row| row.role.split(',').map(str::trim).any(|part| part == role)))
    }
    async fn update_organization_role(
        &self,
        org: &str,
        selector: &OrganizationRoleSelector,
        update: UpdateOrganizationRole,
    ) -> AuthResult<OrganizationRole> {
        let permission = update
            .permission
            .map(|p| serde_json::to_string(&p))
            .transpose()?;
        let mut state = self.organization_state()?;
        let mut first = None;
        let now = Utc::now();
        // Source update applies the literal patch to every selector match,
        // returning the first row. Names need not be unique in a memory adapter.
        for row in state
            .roles
            .values_mut()
            .filter(|row| selected(row, org, selector))
        {
            if let Some(role) = &update.role {
                row.role.clone_from(role);
            }
            if let Some(permission) = &permission {
                row.permission = permission.clone().into();
            }
            row.updated_at = Some(now);
            if first.is_none() {
                first = Some(row.clone());
            }
        }
        first.ok_or_else(|| AuthError::bad_request("Role not found"))
    }
    async fn delete_organization_role(
        &self,
        org: &str,
        selector: &OrganizationRoleSelector,
    ) -> AuthResult<bool> {
        let mut state = self.organization_state()?;
        let before = state.roles.len();
        state.roles.retain(|_, row| !selected(row, org, selector));
        Ok(before != state.roles.len())
    }
}
