use super::entities::member::{ActiveModel, Column, Entity};
use super::{SeaOrmStore, map_db_err};
use crate::schema::AuthSchema;
use async_trait::async_trait;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{ListOrganizationMembersParams, MemberPageQuery, MemberStore};
use better_auth_core::{CreateMember, Member};
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, Select, Set, TransactionTrait,
};
use uuid::Uuid;

impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn create_member_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        member: CreateMember,
    ) -> AuthResult<Member> {
        ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            organization_id: Set(member.organization_id),
            user_id: Set(member.user_id),
            role: Set(member.role),
            created_at: Set(Utc::now()),
        }
        .insert(connection)
        .await
        .map(|model| Member::from(&model))
        .map_err(map_db_err)
    }
}

#[async_trait]
impl<S> MemberStore for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
{
    async fn create_member(&self, member: CreateMember) -> AuthResult<Member> {
        self.create_member_with_connection(self.connection(), member)
            .await
    }

    async fn get_member(&self, organization_id: &str, user_id: &str) -> AuthResult<Option<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .filter(Column::UserId.eq(user_id))
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Member::from(&model)))
            .map_err(map_db_err)
    }

    async fn get_member_by_id(&self, id: &str) -> AuthResult<Option<Member>> {
        Entity::find_by_id(id.to_owned())
            .one(self.connection())
            .await
            .map(|model| model.map(|model| Member::from(&model)))
            .map_err(map_db_err)
    }

    async fn update_member_role(&self, member_id: &str, role: &str) -> AuthResult<Member> {
        self.update_member_role_with_connection(self.connection(), member_id, role)
            .await
    }

    async fn update_member_role_if_present(
        &self,
        member_id: &str,
        role: &str,
    ) -> AuthResult<Option<Member>> {
        let Some(model) = Entity::find_by_id(member_id.to_owned())
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        let mut active = model.into_active_model();
        active.role = Set(role.to_owned());
        match active.update(self.connection()).await {
            Ok(model_2) => Ok(Some(Member::from(&model_2))),
            Err(DbErr::RecordNotUpdated) => Ok(None),
            Err(error) => Err(map_db_err(error)),
        }
    }

    async fn delete_member(&self, member_id: &str) -> AuthResult<()> {
        let transaction = self
            .connection()
            .begin_with_options(sea_orm::TransactionOptions {
                sqlite_transaction_mode: Some(sea_orm::SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        if let Some(member) = Entity::find_by_id(member_id.to_owned())
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(map_db_err)?
        {
            super::teams::remove_owned_team_members(
                &transaction,
                &member.user_id,
                Some(&member.organization_id),
            )
            .await?;
            let _ignored_map_err = Entity::delete_by_id(member_id.to_owned())
                .exec(&transaction)
                .await
                .map_err(map_db_err)?;
        }
        transaction.commit().await.map_err(map_db_err)
    }

    async fn list_organization_members(&self, org_id: &str) -> AuthResult<Vec<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(org_id))
            .order_by_asc(Column::CreatedAt)
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Member::from).collect())
            .map_err(map_db_err)
    }

    async fn delete_member_with_context(
        &self,
        member_id: &str,
        organization_id: &str,
        user_id: &str,
        remove_team_members: bool,
    ) -> AuthResult<()> {
        let transaction = self
            .connection()
            .begin_with_options(sea_orm::TransactionOptions {
                sqlite_transaction_mode: Some(sea_orm::SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        _ = Entity::delete_by_id(member_id.to_owned())
            .exec(&transaction)
            .await
            .map_err(map_db_err)?;
        if remove_team_members {
            use super::entities::team;
            let rooms = team::Entity::find()
                .filter(team::Column::OrganizationId.eq(organization_id))
                .limit(
                    u64::try_from(self.config().advanced.database.default_find_many_limit)
                        .map_err(|_error| {
                            AuthError::internal("Member page parameter exceeds u64")
                        })?,
                )
                .lock_exclusive()
                .all(&transaction)
                .await
                .map_err(map_db_err)?;
            super::teams::release_owned_team_members(&transaction, user_id, rooms).await?;
        }
        transaction.commit().await.map_err(map_db_err)
    }

    async fn list_organization_members_page(
        &self,
        organization_id: &str,
        limit: usize,
    ) -> AuthResult<Vec<Member>> {
        Entity::find()
            .filter(Column::OrganizationId.eq(organization_id))
            .limit(
                u64::try_from(limit)
                    .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?,
            )
            .all(self.connection())
            .await
            .map(|models| models.iter().map(Member::from).collect())
            .map_err(map_db_err)
    }

    async fn query_organization_members(
        &self,
        params: &ListOrganizationMembersParams,
    ) -> AuthResult<(Vec<Member>, usize)> {
        let base_query = Entity::find().filter(Column::OrganizationId.eq(&params.organization_id));
        let filtered_query = apply_member_filter(base_query, params);
        let total = usize::try_from(
            filtered_query
                .clone()
                .count(self.connection())
                .await
                .map_err(map_db_err)?,
        )
        .map_err(|_error| AuthError::internal("Member count exceeds usize"))?;

        let mut query = apply_member_sort(filtered_query, params);
        if let Some(offset) = params.offset {
            query = query.offset(
                u64::try_from(offset)
                    .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?,
            );
        }
        if let Some(limit) = params.limit {
            query = query.limit(
                u64::try_from(limit)
                    .map_err(|_error| AuthError::internal("Member page parameter exceeds u64"))?,
            );
        }

        query
            .all(self.connection())
            .await
            .map(|models| (models.iter().map(Member::from).collect(), total))
            .map_err(map_db_err)
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
        let base = Entity::find().filter(Column::OrganizationId.eq(&params.organization_id));
        let mut query = apply_member_filter(base, &legacy_filter);
        let total = usize::try_from(
            query
                .clone()
                .count(self.connection())
                .await
                .map_err(map_db_err)?,
        )
        .map_err(|error| AuthError::Internal(error.to_string()))?;
        if params.sort_by.as_deref().and_then(member_column).is_some() {
            query = apply_member_sort(query, &legacy_filter);
        }
        let backend = self.connection().get_database_backend();
        let statement = super::bind_page(query.build(backend), params.limit, params.offset)?;
        Entity::find()
            .from_raw_sql(statement)
            .all(self.connection())
            .await
            .map(|models| (models.iter().map(Member::from).collect(), total))
            .map_err(map_db_err)
    }

    async fn count_organization_members(&self, org_id: &str) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(org_id))
            .count(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|count| {
                i64::try_from(count)
                    .map_err(|_error| AuthError::internal("Member count exceeds i64"))
            })
    }

    async fn count_organization_owners(&self, org_id: &str) -> AuthResult<i64> {
        Entity::find()
            .filter(Column::OrganizationId.eq(org_id))
            .filter(Column::Role.eq("owner"))
            .count(self.connection())
            .await
            .map_err(map_db_err)
            .and_then(|count| {
                i64::try_from(count)
                    .map_err(|_error| AuthError::internal("Member count exceeds i64"))
            })
    }
}

fn member_column(field: &str) -> Option<Column> {
    match field {
        "id" => Some(Column::Id),
        "organizationId" => Some(Column::OrganizationId),
        "userId" => Some(Column::UserId),
        "role" => Some(Column::Role),
        "createdAt" => Some(Column::CreatedAt),
        _ => None,
    }
}

fn apply_member_filter(
    mut query: Select<Entity>,
    params: &ListOrganizationMembersParams,
) -> Select<Entity> {
    let Some(field) = params.filter_field.as_deref() else {
        return query;
    };
    let Some(value) = params.filter_value.as_deref() else {
        return query;
    };
    let operator = params.filter_operator.as_deref().unwrap_or("eq");

    match member_column(field) {
        Some(Column::CreatedAt) => {
            let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) else {
                return query.filter(Column::Id.eq("__better_auth_never_matches__"));
            };
            let parsed = parsed.with_timezone(&Utc);
            query = match operator {
                "eq" => query.filter(Column::CreatedAt.eq(parsed)),
                "ne" => query.filter(Column::CreatedAt.ne(parsed)),
                "gt" => query.filter(Column::CreatedAt.gt(parsed)),
                "gte" => query.filter(Column::CreatedAt.gte(parsed)),
                "lt" => query.filter(Column::CreatedAt.lt(parsed)),
                "lte" => query.filter(Column::CreatedAt.lte(parsed)),
                _ => query,
            };
        }
        Some(column) => {
            query = match operator {
                "eq" => query.filter(column.eq(value)),
                "ne" => query.filter(column.ne(value)),
                "contains" => query.filter(column.contains(value)),
                "gt" => query.filter(column.gt(value)),
                "gte" => query.filter(column.gte(value)),
                "lt" => query.filter(column.lt(value)),
                "lte" => query.filter(column.lte(value)),
                _ => query,
            };
        }
        None => {}
    }

    query
}

fn apply_member_sort(
    query: Select<Entity>,
    params: &ListOrganizationMembersParams,
) -> Select<Entity> {
    let Some(sort_by) = params.sort_by.as_deref() else {
        return query.order_by_asc(Column::CreatedAt);
    };
    let descending = matches!(params.sort_direction.as_deref(), Some("desc"));

    match member_column(sort_by) {
        Some(column) if descending => query.order_by_desc(column),
        Some(column) => query.order_by_asc(column),
        None => query.order_by_asc(Column::CreatedAt),
    }
}

impl<S: AuthSchema> SeaOrmStore<S> {
    pub(super) async fn update_member_role_with_connection<C: sea_orm::ConnectionTrait>(
        &self,
        connection: &C,
        member_id: &str,
        role: &str,
    ) -> AuthResult<Member> {
        let Some(model) = Entity::find_by_id(member_id.to_owned())
            .one(connection)
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::not_found("Member not found"));
        };

        let mut active = model.into_active_model();
        active.role = Set(role.to_owned());
        active
            .update(connection)
            .await
            .map(|model_2| Member::from(&model_2))
            .map_err(map_db_err)
    }
}
