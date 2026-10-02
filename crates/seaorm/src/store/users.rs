use super::{SeaOrmStore, cancelled_by_hook, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use async_trait::async_trait;
use better_auth_core::AuthUser;
use better_auth_core::error::{AuthError, AuthResult};
use better_auth_core::store::{NumericTextInput, UserStore};
use better_auth_core::types::{CreateUser, ListUsersParams, UpdateUser};
use chrono::Utc;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait,
    IntoActiveModel, QueryFilter, QuerySelect, QueryTrait, TransactionTrait,
};

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    async fn create_user_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&DatabaseTransaction>,
        mut create_user: CreateUser,
        defaults: better_auth_core::store::UserCreationDefaults,
    ) -> AuthResult<S::User>
    where
        C: ConnectionTrait,
    {
        let hook_context = self.hook_context(tx);
        for hook in self.hooks() {
            if hook
                .before_create_user(&mut create_user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(AuthError::UserCreationCancelled);
            }
        }
        let mut create_user = defaults.apply(create_user)?;
        if let Some(username) = create_user.username.as_mut() {
            *username = username.to_lowercase();
        }
        let now = Utc::now();
        let user_id = create_user
            .id
            .as_deref()
            .map(S::User::parse_id)
            .transpose()?;
        let mut fields = std::mem::take(&mut create_user.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        let mut model = S::User::new_active(user_id, create_user, now);
        let backend = db.get_database_backend();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value = crate::session_fields::prepare_value(db, &column, value).await?;
            S::User::set_additional_field(&mut model, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut model, db.get_database_backend())?;

        let user = model.insert(db).await.map_err(map_db_err)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_user(&user, &hook_context).await?;
            }
        }
        Ok(user)
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: &DatabaseTransaction,
        mut create_user: CreateUser,
    ) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(
            tx,
            Some(tx),
            create_user,
            better_auth_core::store::UserCreationDefaults::default(),
        )
        .await
    }

    pub(crate) async fn create_user_prepared_in_tx(
        &self,
        tx: &DatabaseTransaction,
        prepared: better_auth_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let (data, defaults) = prepared.into_parts();
        self.create_user_with_connection(tx, Some(tx), data, defaults)
            .await
    }
}

#[async_trait]
impl<S> UserStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SeaOrmUserModel,
{
    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(
            self.connection(),
            None,
            create_user,
            better_auth_core::store::UserCreationDefaults::default(),
        )
        .await
    }

    async fn create_user_prepared(
        &self,
        prepared: better_auth_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let (data, defaults) = prepared.into_parts();
        self.create_user_with_connection(self.connection(), None, data, defaults)
            .await
    }

    async fn coerce_user_text_number(&self, input: NumericTextInput) -> AuthResult<String> {
        use sea_orm::{DbBackend, Statement};
        let value: sea_orm::Value = match input {
            NumericTextInput::Integer(value) => value.into(),
            NumericTextInput::Real(value) if !value.is_nan() => value.into(),
            NumericTextInput::Real(_) => {
                return Err(AuthError::bad_request("Numeric text input must not be NaN"));
            }
        };
        let backend = self.connection().get_database_backend();
        let sql = match backend {
            DbBackend::Postgres => "SELECT CAST($1 AS TEXT) AS value",
            DbBackend::Sqlite => "SELECT CAST(? AS TEXT) AS value",
            DbBackend::MySql => "SELECT CAST(? AS CHAR) AS value",
            _ => {
                return Err(AuthError::NotImplemented(
                    "Numeric text coercion is not supported by this backend".into(),
                ));
            }
        };
        let row = self
            .connection()
            .query_one_raw(Statement::from_sql_and_values(backend, sql, [value]))
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::internal("Numeric text coercion returned no value"))?;
        let actual: String = row.try_get("", "value").map_err(map_db_err)?;
        // Older SQLite builds serialize REAL bindings with only 15 significant
        // digits. Match the pinned Bun adapter's SQLite 3.53 conversion after
        // executing the actual bound numeric CAST; errors still come from the
        // configured backend. Other adapters retain their own CAST result.
        match (backend, input) {
            (DbBackend::Sqlite, NumericTextInput::Real(value_2)) if value_2.is_finite() => {
                Ok(super::sqlite_real_text(value_2))
            }
            _ => Ok(actual),
        }
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        let user_id = S::User::parse_id(id)?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let user_ids = ids
            .iter()
            .map(|id| S::User::parse_id(id))
            .collect::<AuthResult<Vec<_>>>()?;

        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids))
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn list_users_by_ids_page(&self, ids: &[String], limit: f64) -> AuthResult<Vec<S::User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let user_ids = ids
            .iter()
            .map(|id| S::User::parse_id(id))
            .collect::<AuthResult<Vec<_>>>()?;
        let query = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids));
        let backend = self.connection().get_database_backend();
        let statement = super::numeric_page::bind_page(query.build(backend), Some(limit), None)?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .from_raw_sql(statement)
            .all(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        let email = normalize_user_email(email);
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::email_column().eq(email))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        let Some(col) = <S::User as SeaOrmUserModel>::username_column() else {
            return Ok(None);
        };
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(col.eq(username))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::internal("the user schema has no phone-number field"))?;
        <S::User as SeaOrmUserModel>::Entity::find()
            .filter(column.eq(phone_number))
            .one(self.connection())
            .await
            .map_err(map_db_err)
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<S::User> {
        update.email = update.email.map(|email| normalize_user_email(&email));
        let user_id = S::User::parse_id(id)?;
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_update_user(id, &mut update, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user update"));
            }
        }
        if let Some(username) = update.username.as_mut() {
            *username = username.to_lowercase();
        }
        let Some(model) = <S::User as SeaOrmUserModel>::Entity::find()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(self.connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active_model();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        S::User::apply_update(&mut active, update, Utc::now());
        let backend = self.connection().get_database_backend();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value =
                crate::session_fields::prepare_value(self.connection(), &column, value).await?;
            S::User::set_additional_field(&mut active, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut active, self.connection().get_database_backend())?;

        let user = active.update(self.connection()).await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context).await?;
        }
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let user_id = S::User::parse_id(id)?;
        let Some(user) = self.get_user_by_id(id).await? else {
            return Err(AuthError::UserNotFound);
        };
        let hook_context = self.hook_context(None);
        for hook in self.hooks() {
            if hook
                .before_delete_user(&user, &hook_context)
                .await?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user deletion"));
            }
        }
        // API keys reference their owner polymorphically, so they carry no
        // foreign key to cascade from. Without this, a deleted user's keys
        // would outlive them and start working again if the id were reused.
        let transaction = self
            .connection()
            .begin_with_options(sea_orm::TransactionOptions {
                sqlite_transaction_mode: Some(sea_orm::SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        drop(
            <S::User as SeaOrmUserModel>::Entity::find()
                .filter(S::User::id_column().eq(user_id.clone()))
                .lock_exclusive()
                .one(&transaction)
                .await
                .map_err(map_db_err)?,
        );
        super::teams::remove_owned_team_members(&transaction, &user.id(), None).await?;
        super::wallets::remove_owned_wallets(&transaction, &user.id()).await?;
        let _ignored_map_err = super::entities::api_key::Entity::delete_many()
            .filter(super::entities::api_key::Column::ReferenceId.eq(user.id().into_owned()))
            .exec(&transaction)
            .await
            .map_err(map_db_err)?;

        let _ignored_map_err_2 = <S::User as SeaOrmUserModel>::Entity::delete_many()
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .exec(&transaction)
            .await
            .map_err(map_db_err)?;
        transaction.commit().await.map_err(map_db_err)?;
        for hook in self.hooks() {
            hook.after_delete_user(&user, &hook_context).await?;
        }
        Ok(())
    }

    async fn list_users(&self, mut params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        use better_auth_core::UserFilterValue;
        let mut query = <S::User as SeaOrmUserModel>::Entity::find();
        if let Some(value) = &params.filter_value {
            let operator = params.filter_operator.as_deref().unwrap_or("eq");
            if matches!(value, UserFilterValue::Multiple(_)) || matches!(operator, "in" | "not_in")
            {
                let field = params
                    .filter_field
                    .as_deref()
                    .filter(|field| !field.is_empty())
                    .unwrap_or("email");
                let column = S::User::list_users_column(field).ok_or_else(|| {
                    AuthError::bad_request("User filter field has no configured column")
                })?;
                let operands = match value {
                    UserFilterValue::Multiple(values) => values.as_slice(),
                    UserFilterValue::Scalar(value) if operator != "in" => {
                        std::slice::from_ref(value)
                    }
                    UserFilterValue::Scalar(_) => {
                        return Err(AuthError::bad_request("Value must be an array"));
                    }
                };
                // The upstream schema transform coerces a scalar string on a
                // boolean field before the adapter binds it. Array operands
                // retain their original strings. The actual model column type
                // also supports custom boolean fields and physical renames.
                let bindings: Vec<sea_orm::Value> = if matches!(value, UserFilterValue::Scalar(_))
                    && matches!(
                        column.def().get_column_type(),
                        sea_orm::sea_query::ColumnType::Boolean
                    ) {
                    operands
                        .iter()
                        .map(|value_2| (value_2 == "true").into())
                        .collect()
                } else {
                    operands.iter().cloned().map(Into::into).collect()
                };
                let tuple = || Expr::tuple(bindings.iter().cloned().map(Expr::val));
                let condition = match operator {
                    "in" => column.is_in(bindings.iter().cloned()),
                    "not_in" => column.is_not_in(bindings.iter().cloned()),
                    // The pinned adapter interpolates the complete array's
                    // comma-joined value into a bound LIKE pattern. Actual SQL
                    // retains backend case, wildcard and NULL semantics.
                    "contains" => column.like(format!("%{}%", operands.join(","))),
                    "starts_with" => column.like(format!("{}%", operands.join(","))),
                    "ends_with" => column.like(format!("%{}", operands.join(","))),
                    "eq" => Expr::col(column).eq(tuple()),
                    "ne" => Expr::col(column).ne(tuple()),
                    "lt" => Expr::col(column).lt(tuple()),
                    "lte" => Expr::col(column).lte(tuple()),
                    "gt" => Expr::col(column).gt(tuple()),
                    "gte" => Expr::col(column).gte(tuple()),
                    _ => return Err(AuthError::bad_request("Unsupported user filter operator")),
                };
                query = query.filter(condition);
                // Only this already executed filter is removed from the common
                // paging/search helper; other fields and total remain intact.
                params.filter_value = None;
            }
        }
        let models = query.all(self.connection()).await.map_err(map_db_err)?;

        Ok(better_auth_core::user_query::apply_list_users(
            models, &params,
        ))
    }
}

fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}
