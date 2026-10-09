use super::*;

#[async_trait]
impl InvitationStore for StatelessStore {
    async fn create_invitation(&self, data: CreateInvitation) -> AuthResult<Invitation> {
        self.create_invitation_with_options(data, InvitationCreateOptions::default())
            .await
    }
    async fn create_invitation_with_options(
        &self,
        data: CreateInvitation,
        options: InvitationCreateOptions,
    ) -> AuthResult<Invitation> {
        let row = Invitation {
            id: options
                .id
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            organization_id: data.organization_id,
            email: data.email,
            role: Some(data.role),
            team_id: data.team_id,
            status: options.status.unwrap_or_default(),
            inviter_id: data.inviter_id,
            expires_at: data.expires_at,
            created_at: options.created_at.unwrap_or_else(Utc::now),
        };
        _ = self
            .organization_state()?
            .invitations
            .insert(row.id.clone(), row.clone());
        Ok(row)
    }
    async fn get_invitation_by_id(&self, id: &str) -> AuthResult<Option<Invitation>> {
        Ok(self.organization_state()?.invitations.get(id).cloned())
    }
    async fn get_pending_invitation(
        &self,
        org_id: &str,
        email: &str,
    ) -> AuthResult<Option<Invitation>> {
        Ok(self
            .organization_state()?
            .invitations
            .values()
            .find(|row| {
                row.organization_id == org_id
                    && row.email == email.to_lowercase()
                    && row.status == InvitationStatus::Pending
                    && row.expires_at > Utc::now()
            })
            .cloned())
    }
    async fn pending_invitation_page(
        &self,
        org_id: &str,
        email: Option<&str>,
    ) -> AuthResult<Vec<Invitation>> {
        let email = email.map(str::to_lowercase);
        Ok(self
            .organization_state()?
            .invitations
            .values()
            .filter(|row| {
                row.organization_id == org_id
                    && row.status == InvitationStatus::Pending
                    && email.as_ref().is_none_or(|email| row.email == *email)
            })
            .take(self.find_many_limit)
            .cloned()
            .collect())
    }
    async fn update_invitation_expiry(
        &self,
        id: &str,
        expires_at: DateTime<Utc>,
    ) -> AuthResult<Invitation> {
        let mut state = self.organization_state()?;
        let row = state
            .invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        row.expires_at = expires_at;
        Ok(row.clone())
    }
    async fn update_invitation_team_ids(
        &self,
        id: &str,
        team_ids: Option<String>,
    ) -> AuthResult<Invitation> {
        let mut state = self.organization_state()?;
        let row = state
            .invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        row.team_id = team_ids;
        Ok(row.clone())
    }
    async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> AuthResult<Invitation> {
        let mut state = self.organization_state()?;
        let row = state
            .invitations
            .get_mut(id)
            .ok_or_else(|| AuthError::not_found("Invitation not found"))?;
        row.status = status;
        Ok(row.clone())
    }
    async fn update_invitation_status_if_status(
        &self,
        id: &str,
        expected: InvitationStatus,
        status: InvitationStatus,
    ) -> AuthResult<Option<Invitation>> {
        let mut state = self.organization_state()?;
        let Some(row) = state
            .invitations
            .get_mut(id)
            .filter(|row| row.status == expected)
        else {
            return Ok(None);
        };
        row.status = status;
        Ok(Some(row.clone()))
    }
    async fn list_organization_invitations(&self, org_id: &str) -> AuthResult<Vec<Invitation>> {
        Ok(self
            .organization_state()?
            .invitations
            .values()
            .filter(|row| row.organization_id == org_id)
            .take(self.find_many_limit)
            .cloned()
            .collect())
    }
    async fn count_pending_organization_invitations(&self, org_id: &str) -> AuthResult<i64> {
        i64::try_from(
            self.organization_state()?
                .invitations
                .values()
                .filter(|row| {
                    row.organization_id == org_id
                        && row.status == InvitationStatus::Pending
                        && row.expires_at > Utc::now()
                })
                .count(),
        )
        .map_err(|_| AuthError::internal("Invitation count overflow"))
    }
    async fn list_user_invitations(&self, email: &str) -> AuthResult<Vec<Invitation>> {
        let email = email.to_lowercase();
        Ok(self
            .organization_state()?
            .invitations
            .values()
            .filter(|row| row.email == email)
            .take(self.find_many_limit)
            .cloned()
            .collect())
    }
    // The legacy combined acceptance API requires a physical session and is
    // intentionally unsupported. HTTP acceptance uses the status CAS and the
    // transaction interface, whose initialized wrapper owns ephemeral sessions.
}
