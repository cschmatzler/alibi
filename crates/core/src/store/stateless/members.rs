use crate::store::stateless::StatelessStore;
use crate::store::{ListOrganizationMembersParams, MemberPageQuery, MemberStore};
use crate::{AuthError, AuthResult, CreateMember, Member};
use async_trait::async_trait;
use chrono::Utc;
use std::cmp::Ordering;

fn field<'a>(row: &'a Member, name: &str) -> Option<&'a str> {
    match name {
        "id" => Some(&row.id),
        "organizationId" => Some(&row.organization_id),
        "userId" => Some(&row.user_id),
        "role" => Some(&row.role),
        _ => None,
    }
}
fn comparison(order: Ordering, operator: &str) -> bool {
    match operator {
        "ne" => order != Ordering::Equal,
        "gt" => order == Ordering::Greater,
        "gte" => order != Ordering::Less,
        "lt" => order == Ordering::Less,
        "lte" => order != Ordering::Greater,
        _ => order == Ordering::Equal,
    }
}
fn matches(row: &Member, query: &MemberPageQuery) -> bool {
    let (Some(name), Some(value)) = (query.filter_field.as_deref(), query.filter_value.as_deref())
    else {
        return true;
    };
    let operator = query.filter_operator.as_deref().unwrap_or("eq");
    if name == "createdAt" {
        return chrono::DateTime::parse_from_rfc3339(value).is_ok_and(|value| {
            comparison(row.created_at.cmp(&value.with_timezone(&Utc)), operator)
        });
    }
    field(row, name).is_some_and(|stored| {
        if operator == "contains" {
            stored.contains(value)
        } else {
            comparison(stored.encode_utf16().cmp(value.encode_utf16()), operator)
        }
    })
}
// Array.slice applies ToIntegerOrInfinity, supports negative indices, and treats NaN as zero.
pub(super) fn slice_index(value: f64, length: usize) -> usize {
    if value.is_nan() {
        return 0;
    }
    let value = value.trunc();
    if value < 0.0 {
        (length as f64 + value.trunc()).max(0.0) as usize
    } else {
        value.min(length as f64) as usize
    }
}

#[async_trait]
impl MemberStore for StatelessStore {
    async fn create_member(&self, data: CreateMember) -> AuthResult<Member> {
        let row = Member {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: data.organization_id,
            user_id: data.user_id,
            role: data.role,
            created_at: Utc::now(),
        };
        _ = self
            .organization_state()?
            .members
            .insert(row.id.clone(), row.clone());
        Ok(row)
    }
    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        Ok(self
            .organization_state()?
            .members
            .values()
            .find(|row| row.organization_id == organization_id && row.user_id == user_id)
            .cloned())
    }
    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Ok(self.organization_state()?.members.get(id).cloned())
    }
    async fn update_member_role(&self, id: &str, role: &str) -> AuthResult<Member> {
        self.update_member_role_if_present(id, role)
            .await?
            .ok_or_else(|| AuthError::not_found("Member not found"))
    }
    async fn update_member_role_if_present(
        &self,
        id: &str,
        role: &str,
    ) -> AuthResult<Option<Member>> {
        let mut state = self.organization_state()?;
        let Some(row) = state.members.get_mut(id) else {
            return Ok(None);
        };
        row.role = role.to_owned();
        Ok(Some(row.clone()))
    }
    async fn delete_member(&self, id: &str) -> AuthResult<()> {
        _ = self.organization_state()?.members.shift_remove(id);
        Ok(())
    }
    async fn delete_member_with_context(
        &self,
        id: &str,
        organization_id: &str,
        user_id: &str,
        remove_team_members: bool,
    ) -> AuthResult<()> {
        let mut state = self.organization_state()?;
        _ = state.members.shift_remove(id);
        if remove_team_members {
            let teams: Vec<_> = state
                .teams
                .values()
                .filter(|row| row.organization_id == organization_id)
                .take(self.find_many_limit)
                .map(|row| row.id.clone())
                .collect();
            for team in teams {
                _ = state.remove_team_members(&team, user_id);
            }
        }
        Ok(())
    }
    async fn list_organization_members_page(
        &self,
        organization_id: &str,
        limit: usize,
    ) -> AuthResult<Vec<Member>> {
        Ok(self
            .organization_state()?
            .members
            .values()
            .filter(|row| row.organization_id == organization_id)
            .take(limit)
            .cloned()
            .collect())
    }
    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>> {
        let mut rows = self
            .list_organization_members_page(org_id, usize::MAX)
            .await?;
        rows.sort_by_key(|row| row.created_at);
        Ok(rows)
    }
    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        self.query_organization_members_page(&MemberPageQuery {
            organization_id: params.organization_id.clone(),
            limit: params.limit.map(|v| v as f64),
            offset: params.offset.map(|v| v as f64),
            sort_by: Some(params.sort_by.clone().unwrap_or_else(|| "createdAt".into())),
            sort_direction: Some(
                params
                    .sort_direction
                    .clone()
                    .unwrap_or_else(|| "asc".into()),
            ),
            filter_field: params.filter_field.clone(),
            filter_value: params.filter_value.clone(),
            filter_operator: params.filter_operator.clone(),
        })
        .await
    }
    async fn query_organization_members_page(
        &self,
        query: &MemberPageQuery,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let mut rows: Vec<_> = self
            .organization_state()?
            .members
            .values()
            .filter(|row| row.organization_id == query.organization_id && matches(row, query))
            .cloned()
            .collect();
        let total = rows.len();
        if let Some(name) = query.sort_by.as_deref() {
            rows.sort_by(|a, b| {
                let order = if name == "createdAt" {
                    a.created_at.cmp(&b.created_at)
                } else {
                    field(a, name).cmp(&field(b, name))
                };
                if query.sort_direction.as_deref() == Some("desc") {
                    order.reverse()
                } else {
                    order
                }
            });
        }
        let start = query
            .offset
            .map_or(0, |value| slice_index(value, rows.len()));
        _ = rows.drain(..start);
        rows.truncate(slice_index(
            query.limit.unwrap_or(self.find_many_limit as f64),
            rows.len(),
        ));
        Ok((rows, total))
    }
    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64> {
        i64::try_from(
            self.organization_state()?
                .members
                .values()
                .filter(|row| row.organization_id == org_id)
                .count(),
        )
        .map_err(|_| AuthError::internal("Member count overflow"))
    }
    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64> {
        i64::try_from(
            self.organization_state()?
                .members
                .values()
                .filter(|row| row.organization_id == org_id && row.role == "owner")
                .count(),
        )
        .map_err(|_| AuthError::internal("Owner count overflow"))
    }
}
