use super::entities::member::Model;
use super::entities::team;
use super::{SqlxStore, lock_exclusive};
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::Exec;
use crate::schema::AuthSchema;
use crate::sql::Sql;
use crate::value::SqlValue;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{ListOrganizationMembersParams, MemberPageQuery, MemberStore};
use better_auth_core::{CreateMember, Member};
use chrono::Utc;
use uuid::Uuid;

impl<S: AuthSchema> SqlxStore<S> {
    pub(super) async fn create_member_with_connection(
        &self,
        exec: Exec<'_>,
        member: CreateMember,
    ) -> AuthResult<Member> {
        let mut active = ActiveRow::new();
        active.set("id", Uuid::new_v4().to_string());
        active.set("organization_id", member.organization_id);
        active.set("user_id", member.user_id);
        active.set("role", member.role);
        active.set("created_at", Utc::now());
        model::insert::<Model>(exec, &active)
            .await
            .map(|model| Member::from(&model))
    }

    async fn find_member_by_id(&self, id: &str) -> AuthResult<Option<Model>> {
        let mut sql = model::by_id::<Model>(self.exec(), id);
        model::limit_one(&mut sql);
        self.exec().fetch_optional(sql).await
    }
}

/// A member predicate: one column comparison.
struct Filter {
    column: &'static str,
    operator: &'static str,
    value: SqlValue,
}

fn member_column(field: &str) -> Option<&'static str> {
    match field {
        "id" => Some("id"),
        "organizationId" => Some("organization_id"),
        "userId" => Some("user_id"),
        "role" => Some("role"),
        "createdAt" => Some("created_at"),
        _ => None,
    }
}

fn member_filter(params: &ListOrganizationMembersParams) -> Option<Filter> {
    let field = params.filter_field.as_deref()?;
    let value = params.filter_value.as_deref()?;
    let operator = params.filter_operator.as_deref().unwrap_or("eq");
    match member_column(field)? {
        "created_at" => {
            let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) else {
                return Some(Filter {
                    column: "id",
                    operator: " = ",
                    value: "__better_auth_never_matches__".into(),
                });
            };
            let parsed = parsed.with_timezone(&Utc);
            let operator = match operator {
                "eq" => " = ",
                "ne" => " <> ",
                "gt" => " > ",
                "gte" => " >= ",
                "lt" => " < ",
                "lte" => " <= ",
                _ => return None,
            };
            Some(Filter {
                column: "created_at",
                operator,
                value: parsed.into(),
            })
        }
        column => {
            let (operator, value) = match operator {
                "eq" => (" = ", value.to_owned()),
                "ne" => (" <> ", value.to_owned()),
                "contains" => (" LIKE ", format!("%{value}%")),
                "gt" => (" > ", value.to_owned()),
                "gte" => (" >= ", value.to_owned()),
                "lt" => (" < ", value.to_owned()),
                "lte" => (" <= ", value.to_owned()),
                _ => return None,
            };
            Some(Filter {
                column,
                operator,
                value: value.into(),
            })
        }
    }
}

fn member_where(sql: &mut Sql, organization_id: &str, filter: Option<&Filter>) {
    sql.push(" WHERE ")
        .column(Model::TABLE, "organization_id")
        .push(" = ")
        .bind(organization_id);
    if let Some(filter) = filter {
        sql.push(" AND ")
            .column(Model::TABLE, filter.column)
            .push(filter.operator)
            .bind(filter.value.clone());
    }
}

fn member_sort(sql: &mut Sql, params: &ListOrganizationMembersParams) {
    let column = params
        .sort_by
        .as_deref()
        .and_then(member_column)
        .unwrap_or("created_at");
    let descending = params.sort_by.as_deref().and_then(member_column).is_some()
        && matches!(params.sort_direction.as_deref(), Some("desc"));
    sql.push(" ORDER BY ")
        .column(Model::TABLE, column)
        .push(if descending { " DESC" } else { " ASC" });
}

impl<S: AuthSchema> SqlxStore<S> {
    async fn count_members(
        &self,
        organization_id: &str,
        filter: Option<&Filter>,
    ) -> AuthResult<i64> {
        let mut sql = Sql::with(self.exec().backend(), "SELECT COUNT(*) FROM ");
        sql.ident(Model::TABLE);
        member_where(&mut sql, organization_id, filter);
        Ok(self
            .exec()
            .fetch_scalar::<i64>(sql)
            .await?
            .unwrap_or_default())
    }
}

#[async_trait]
impl<S> MemberStore for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.create_member_with_connection(self.exec(), member)
            .await
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        let mut sql = model::select_model::<Model>(self.exec());
        sql.push(" WHERE ")
            .column(Model::TABLE, "organization_id")
            .push(" = ")
            .bind(organization_id)
            .push(" AND ")
            .column(Model::TABLE, "user_id")
            .push(" = ")
            .bind(user_id);
        model::limit_one(&mut sql);
        Ok(self
            .exec()
            .fetch_optional::<Model>(sql)
            .await?
            .map(|model| Member::from(&model)))
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Ok(self
            .find_member_by_id(id)
            .await?
            .map(|model| Member::from(&model)))
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        let Some(model) = self.find_member_by_id(member_id).await? else {
            return Err(AuthError::not_found("Member not found"));
        };
        let mut active = model.into_active();
        active.set("role", role);
        model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Member::from(&model_2))
            .ok_or_else(crate::error::record_not_updated)
    }

    async fn update_member_role_if_present(
        &self,
        member_id: &str,
        role: &str,
    ) -> AuthResult<Option<Member>> {
        let Some(model) = self.find_member_by_id(member_id).await? else {
            return Ok(None);
        };
        let mut active = model.into_active();
        active.set("role", role);
        Ok(model::update::<Model>(self.exec(), &active)
            .await?
            .map(|model_2| Member::from(&model_2)))
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        let member_id = member_id.to_owned();
        self.in_transaction(true, move |tx| {
            Box::pin(async move {
                let exec = Exec::Tx(tx);
                let mut select = model::by_id::<Model>(exec, member_id.as_str());
                model::limit_one(&mut select);
                lock_exclusive(&mut select);
                if let Some(member) = exec.fetch_optional::<Model>(select).await? {
                    super::teams::remove_owned_team_members(
                        tx,
                        &member.user_id,
                        Some(&member.organization_id),
                    )
                    .await?;
                    exec.execute(model::delete_by_id::<Model>(exec, member_id))
                        .await?;
                }
                Ok(())
            })
        })
        .await
    }

    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>> {
        let mut sql = model::select_model::<Model>(self.exec());
        member_where(&mut sql, org_id, None);
        sql.push(" ORDER BY ")
            .column(Model::TABLE, "created_at")
            .push(" ASC");
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Member::from)
            .collect())
    }

    async fn delete_member_with_context(
        &self,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
        remove_team_members: bool,
    ) -> AuthResult<()> {
        let limit = i64::try_from(self.config().advanced.database.default_find_many_limit)
            .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?;
        let (member_id, organization_id, user_id) = (
            member_id.to_owned(),
            organization_id.to_owned(),
            user_id.to_owned(),
        );
        self.in_transaction(true, move |tx| {
            Box::pin(async move {
                let exec = Exec::Tx(tx);
                exec.execute(model::delete_by_id::<Model>(exec, member_id))
                    .await?;
                if remove_team_members {
                    let mut rooms = model::select_model::<team::Model>(exec);
                    rooms
                        .push(" WHERE ")
                        .column(team::Model::TABLE, "organization_id")
                        .push(" = ")
                        .bind(organization_id)
                        .push(" LIMIT ")
                        .bind(limit);
                    lock_exclusive(&mut rooms);
                    let rooms = exec.fetch_all::<team::Model>(rooms).await?;
                    super::teams::release_owned_team_members(tx, &user_id, rooms).await?;
                }
                Ok(())
            })
        })
        .await
    }

    async fn list_organization_members_page(
        &self,
        organization_id: &str,
        limit: usize,
    ) -> AuthResult<Vec<Member>> {
        let limit = i64::try_from(limit)
            .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?;
        let mut sql = model::select_model::<Model>(self.exec());
        member_where(&mut sql, organization_id, None);
        sql.push(" LIMIT ").bind(limit);
        Ok(self
            .exec()
            .fetch_all::<Model>(sql)
            .await?
            .iter()
            .map(Member::from)
            .collect())
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let filter = member_filter(params);
        let total = usize::try_from(
            self.count_members(&params.organization_id, filter.as_ref())
                .await?,
        )
        .map_err(|_error| AuthError::internal("Member count exceeds usize"))?;

        let mut sql = model::select_model::<Model>(self.exec());
        member_where(&mut sql, &params.organization_id, filter.as_ref());
        member_sort(&mut sql, params);
        if let Some(limit) = params.limit {
            sql.push(" LIMIT ").bind(
                i64::try_from(limit)
                    .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?,
            );
        }
        if let Some(offset) = params.offset {
            sql.push(" OFFSET ").bind(
                i64::try_from(offset)
                    .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?,
            );
        }
        Ok((
            self.exec()
                .fetch_all::<Model>(sql)
                .await?
                .iter()
                .map(Member::from)
                .collect(),
            total,
        ))
    }

    async fn query_organization_members_page(
        &self,
        params: &MemberPageQuery,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let legacy_filter = ListOrganizationMembersParams {
            organization_id: params.organization_id.clone(),
            sort_by: params.sort_by.clone(),
            sort_direction: params.sort_direction.clone(),
            filter_field: params.filter_field.clone(),
            filter_value: params.filter_value.clone(),
            filter_operator: params.filter_operator.clone(),
            ..Default::default()
        };
        let filter = member_filter(&legacy_filter);
        let total = usize::try_from(
            self.count_members(&params.organization_id, filter.as_ref())
                .await?,
        )
        .map_err(|error| AuthError::Internal(error.to_string()))?;
        let mut sql = model::select_model::<Model>(self.exec());
        member_where(&mut sql, &params.organization_id, filter.as_ref());
        if params.sort_by.as_deref().and_then(member_column).is_some() {
            member_sort(&mut sql, &legacy_filter);
        }
        super::numeric_page::bind_page(&mut sql, params.limit, params.offset);
        Ok((
            self.exec()
                .fetch_all::<Model>(sql)
                .await?
                .iter()
                .map(Member::from)
                .collect(),
            total,
        ))
    }

    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64> {
        self.count_members(org_id, None).await
    }

    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64> {
        let filter = Filter {
            column: "role",
            operator: " = ",
            value: "owner".into(),
        };
        self.count_members(org_id, Some(&filter)).await
    }
}
