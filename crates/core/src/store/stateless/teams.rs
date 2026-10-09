use crate::store::stateless::{OrganizationState, StatelessStore};
use crate::store::{TeamStore, team_membership_key};
use crate::types::AddTeamMemberResult;
use crate::utils::javascript::number_from_i64;
use crate::{AuthError, AuthResult, CreateTeam, InvitationStatus, Team, TeamMember, UpdateTeam};
use async_trait::async_trait;
use chrono::Utc;

impl OrganizationState {
    pub(super) fn remove_team_members(&mut self, team_id: &str, user_id: &str) -> usize {
        let before = self.team_members.len();
        self.team_members
            .retain(|_, row| row.team_id != team_id || row.user_id != user_id);
        let removed = before - self.team_members.len();
        if let (Some(team), Ok(removed)) = (self.teams.get_mut(team_id), i64::try_from(removed))
            && team.member_count >= removed
        {
            team.member_count -= removed;
        }
        removed
    }
}
#[async_trait]
impl TeamStore for StatelessStore {
    async fn create_team(&self, data: CreateTeam) -> AuthResult<Team> {
        let row = Team {
            id: uuid::Uuid::new_v4().to_string(),
            name: data.name,
            organization_id: data.organization_id,
            created_at: data.updated_at.unwrap_or_else(Utc::now),
            updated_at: data.updated_at,
            member_count: 0,
        };
        _ = self
            .organization_state()?
            .teams
            .insert(row.id.clone(), row.clone());
        Ok(row)
    }
    async fn get_team(&self, organization_id: Option<&str>, id: &str) -> AuthResult<Option<Team>> {
        Ok(self
            .organization_state()?
            .teams
            .get(id)
            .filter(|row| organization_id.is_none_or(|org| org == row.organization_id))
            .cloned())
    }
    async fn list_teams(&self, organization_id: &str) -> AuthResult<Vec<Team>> {
        Ok(self
            .organization_state()?
            .teams
            .values()
            .filter(|row| row.organization_id == organization_id)
            .take(self.find_many_limit)
            .cloned()
            .collect())
    }
    async fn update_team(
        &self,
        organization_id: &str,
        id: &str,
        update: UpdateTeam,
    ) -> AuthResult<Team> {
        let mut state = self.organization_state()?;
        let row = state
            .teams
            .get_mut(id)
            .filter(|row| row.organization_id == organization_id)
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        if let Some(name) = update.name {
            row.name = name;
        }
        row.updated_at = Some(Utc::now());
        Ok(row.clone())
    }
    async fn delete_team(&self, organization_id: &str, id: &str) -> AuthResult<bool> {
        let mut state = self.organization_state()?;
        if state
            .teams
            .get(id)
            .is_none_or(|row| row.organization_id != organization_id)
        {
            return Ok(false);
        }
        _ = state.teams.shift_remove(id);
        state.team_members.retain(|_, row| row.team_id != id);
        for invite in state
            .invitations
            .values_mut()
            .filter(|row| {
                row.organization_id == organization_id && row.status == InvitationStatus::Pending
            })
            .take(self.find_many_limit)
        {
            if invite.expires_at <= Utc::now() {
                continue;
            }
            if let Some(ids) = invite
                .team_id
                .as_deref()
                .filter(|ids| ids.split(',').any(|part| part == id))
            {
                let remaining = ids
                    .split(',')
                    .filter(|part| *part != id)
                    .collect::<Vec<_>>()
                    .join(",");
                invite.team_id = (!remaining.is_empty()).then_some(remaining);
            }
        }
        Ok(true)
    }
    async fn get_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> AuthResult<Option<TeamMember>> {
        Ok(self
            .organization_state()?
            .team_members
            .values()
            .find(|row| row.team_id == team_id && row.user_id == user_id)
            .cloned())
    }
    async fn add_team_member(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: Option<f64>,
    ) -> AuthResult<AddTeamMemberResult> {
        let key = team_membership_key(team_id, user_id)?;
        let mut state = self.organization_state()?;
        if let Some(row) = state
            .team_members
            .values()
            .find(|row| row.team_id == team_id && row.user_id == user_id)
        {
            return Ok(AddTeamMemberResult::Existing(row.clone()));
        }
        let count = i64::try_from(
            state
                .team_members
                .values()
                .filter(|row| row.team_id == team_id)
                .count(),
        )
        .map_err(|_| AuthError::internal("Team membership count overflow"))?;
        let team = state
            .teams
            .get_mut(team_id)
            .ok_or_else(|| AuthError::bad_request("Team not found"))?;
        team.member_count = team.member_count.max(count);
        // Keep the raw Number predicate, including fractions, NaN and infinities.
        if maximum.is_some_and(|maximum| {
            number_from_i64(team.member_count).partial_cmp(&maximum)
                != Some(std::cmp::Ordering::Less)
        }) {
            return Ok(AddTeamMemberResult::LimitReached);
        }
        team.member_count = team
            .member_count
            .checked_add(1)
            .ok_or_else(|| AuthError::internal("Team membership count overflow"))?;
        let row = TeamMember {
            id: uuid::Uuid::new_v4().to_string(),
            team_id: team_id.into(),
            user_id: user_id.into(),
            created_at: Utc::now(),
            membership_key: Some(key),
        };
        _ = state.team_members.insert(row.id.clone(), row.clone());
        Ok(AddTeamMemberResult::Added(row))
    }
    async fn remove_team_member(&self, team_id: &str, user_id: &str) -> AuthResult<usize> {
        Ok(self
            .organization_state()?
            .remove_team_members(team_id, user_id))
    }
    async fn list_team_members(&self, team_id: &str) -> AuthResult<Vec<TeamMember>> {
        Ok(self
            .organization_state()?
            .team_members
            .values()
            .filter(|row| row.team_id == team_id)
            .take(self.find_many_limit)
            .cloned()
            .collect())
    }
    async fn list_user_teams(&self, user_id: &str) -> AuthResult<Vec<Team>> {
        let state = self.organization_state()?;
        Ok(state
            .team_members
            .values()
            .filter(|row| row.user_id == user_id)
            .take(self.find_many_limit)
            .filter_map(|row| state.teams.get(&row.team_id).cloned())
            .collect())
    }
}
