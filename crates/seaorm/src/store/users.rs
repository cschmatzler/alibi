use super::ScopedTransaction;
use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use alibi_core::AuthUser;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::store::{NumericTextInput, UserStore};
use alibi_core::types::{CreateUser, ListUsersParams, UpdateUser};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, TransactionTrait,
};

pub(super) fn user_query<M: SeaOrmUserModel>(
    backend: sea_orm::DbBackend,
) -> sea_orm::Select<M::Entity> {
    use sea_orm::{Iden, Iterable};
    let query = M::Entity::find();
    if backend != sea_orm::DbBackend::Sqlite {
        return query;
    }
    let Some(verification) = M::list_users_column("emailVerified") else {
        return query;
    };
    let verification_name = verification.to_string();
    let mut query = query.select_only();
    for column in <M::Entity as EntityTrait>::Column::iter() {
        if column.to_string() == verification_name {
            query = query.column_as(Expr::cust_with_exprs(
                "CASE WHEN typeof(?) IN ('integer', 'real') THEN ? = 1 WHEN ? IS NULL THEN NULL ELSE ? <> '' END",
                [Expr::col(column), Expr::col(column), Expr::col(column), Expr::col(column)],
            ),column);
        } else {
            query = query.column(column);
        }
    }
    query
}

pub(super) async fn provider_verification_output<M: SeaOrmUserModel, C: ConnectionTrait>(
    db: &C,
    id: &str,
) -> AuthResult<Option<serde_json::Value>> {
    use sea_orm::EntityName;
    use sea_orm::sea_query::Query;
    if db.get_database_backend() != sea_orm::DbBackend::Sqlite {
        return Ok(None);
    }
    let Some(column) = M::list_users_column("emailVerified") else {
        return Ok(None);
    };
    let query = Query::select().expr_as(Expr::cust_with_exprs(
        "CASE typeof(?) WHEN 'text' THEN json_quote(?) WHEN 'null' THEN 'null' ELSE CASE WHEN ? = 1 THEN 'true' ELSE 'false' END END",
        [Expr::col(column), Expr::col(column), Expr::col(column)],
    ), sea_orm::sea_query::Alias::new("provider_verification"))
        .from(M::Entity::default().table_ref())
        .and_where(M::id_column().eq(M::parse_id(id)?)).to_owned();
    let row = db
        .query_one_raw(db.get_database_backend().build(&query))
        .await
        .map_err(map_db_err)?;
    row.map(|row| {
        let value: String = row
            .try_get("", "provider_verification")
            .map_err(map_db_err)?;
        alibi_core::utils::json::from_slice(value.as_bytes())
            .map_err(|error| AuthError::internal(error.to_string()))
    })
    .transpose()
}

async fn save_provider_user<M: SeaOrmUserModel, C: ConnectionTrait>(
    mut model: M::ActiveModel,
    db: &C,
    verification: Option<serde_json::Value>,
    id: Option<&str>,
) -> AuthResult<M> {
    use sea_orm::sea_query::Query;
    use sea_orm::{ActiveModelBehavior, ActiveValue, EntityName, Iden, Iterable};
    let insert = id.is_none();
    let Some(verification) =
        verification.filter(|value| !value.is_boolean() && (!insert || !value.is_null()))
    else {
        return if insert {
            model.insert(db).await.map_err(map_db_err)
        } else {
            model.update(db).await.map_err(map_db_err)
        };
    };
    let column = M::list_users_column("emailVerified").ok_or_else(|| {
        AuthError::internal("The user model does not expose its provider verification column")
    })?;
    let value: sea_orm::Value = match verification {
        serde_json::Value::Null => sea_orm::Value::Bool(None),
        serde_json::Value::String(value) => value.into(),
        serde_json::Value::Number(value) => {
            if db.get_database_backend() == sea_orm::DbBackend::Postgres {
                alibi_core::utils::json::number_to_string(&value)
                    .map_err(|error| AuthError::internal(error.to_string()))?
                    .into()
            } else if let Some(value) = value.as_i64() {
                value.into()
            } else {
                value
                    .as_f64()
                    .ok_or_else(|| AuthError::internal("Invalid provider verification number"))?
                    .into()
            }
        }
        _ => {
            return Err(AuthError::internal(
                "Unsupported provider verification SQL parameter",
            ));
        }
    };
    model = ActiveModelBehavior::before_save(model, db, insert)
        .await
        .map_err(map_db_err)?;
    let mut columns = Vec::new();
    let mut values = Vec::new();
    let mut returning = Vec::new();
    for physical in <M::Entity as EntityTrait>::Column::iter() {
        let verification_column = physical.to_string() == column.to_string();
        let staged = match model.take(physical) {
            ActiveValue::Set(original) => Some(original),
            ActiveValue::Unchanged(original) if insert => Some(original),
            _ => None,
        };
        if let Some(original) = staged {
            columns.push(physical);
            let expression = Expr::val(if verification_column {
                value.clone()
            } else {
                original
            });
            let expression = if verification_column
                && db.get_database_backend() == sea_orm::DbBackend::Postgres
            {
                expression.cast_as(sea_orm::sea_query::Alias::new("boolean"))
            } else {
                expression
            };
            values.push(physical.save_as(expression));
        }
        returning.push(if verification_column && db.get_database_backend() == sea_orm::DbBackend::Sqlite {
            Expr::cust_with_exprs("CASE WHEN typeof(?) IN ('integer', 'real') THEN ? = 1 WHEN ? IS NULL THEN NULL ELSE ? <> '' END AS ?",[Expr::col(physical),Expr::col(physical),Expr::col(physical),Expr::col(physical),Expr::col(physical)])
        } else { Expr::col(physical) });
    }
    let statement = if let Some(id) = id {
        let query = Query::update()
            .table(M::Entity::default().table_ref())
            .values(columns.into_iter().zip(values))
            .and_where(M::id_column().eq(M::parse_id(id)?))
            .returning(Query::returning().exprs(returning))
            .to_owned();
        db.get_database_backend().build(&query)
    } else {
        let query = Query::insert()
            .into_table(M::Entity::default().table_ref())
            .columns(columns)
            .values(values)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .returning(Query::returning().exprs(returning))
            .to_owned();
        db.get_database_backend().build(&query)
    };
    let row = db
        .query_one_raw(statement)
        .await
        .map_err(map_db_err)?
        .ok_or_else(|| AuthError::internal("Provider user write returned no row"))?;
    let user = M::from_query_result(&row, "").map_err(map_db_err)?;
    <M::ActiveModel as ActiveModelBehavior>::after_save(user, db, insert)
        .await
        .map_err(map_db_err)
}

async fn stage_provider_text<M: SeaOrmUserModel, C: ConnectionTrait>(
    db: &C,
    active: &mut M::ActiveModel,
    name: Option<serde_json::Value>,
    image: Option<serde_json::Value>,
) -> AuthResult<()> {
    for (field, raw) in [("name", name), ("image", image)] {
        let Some(raw) = raw else {
            continue;
        };
        if raw.is_array() || raw.is_object() {
            return Err(AuthError::internal(
                "Unsupported provider text SQL parameter",
            ));
        }
        let column = if field == "name" {
            Some(M::name_column())
        } else {
            M::list_users_column("image")
        }
        .ok_or_else(|| {
            AuthError::internal("The user model does not expose its provider text column")
        })?;
        let value =
            crate::additional_fields::raw_value(&alibi_core::utils::json::JsValue::from(raw))?;
        let value = crate::additional_fields::prepare_value(db, &column, value).await?;
        // Use the model's physical binding after the configured database has
        // converted the scalar. This keeps ordinary active-model hooks intact.
        M::set_additional_field(active, column, value, db.get_database_backend())?;
    }
    Ok(())
}

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: SeaOrmUserModel,
{
    async fn create_user_with_connection<C>(
        &self,
        db: &C,
        tx: Option<&ScopedTransaction>,
        mut create_user: CreateUser,
        defaults: alibi_core::store::UserCreationDefaults,
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
        if create_user.id.is_none() {
            create_user.id = self
                .generated_id(
                    db,
                    "user",
                    <<S::User as SeaOrmUserModel>::Entity as sea_orm::EntityName>::table_name(
                        &Default::default(),
                    ),
                    &sea_orm::Iden::to_string(&S::User::id_column()),
                )
                .await?;
        }
        let user_id = create_user
            .id
            .as_deref()
            .map(S::User::parse_id)
            .transpose()?;
        let mut fields = std::mem::take(&mut create_user.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        let provider_name = create_user.provider_name.take();
        let provider_image = create_user.provider_image.take();
        let verification = create_user.provider_email_verified.take();
        let mut model = S::User::new_active(user_id, create_user, now);
        stage_provider_text::<S::User, _>(db, &mut model, provider_name, provider_image).await?;
        let backend = db.get_database_backend();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(db, &column, value).await?;
            S::User::set_additional_field(&mut model, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut model, db.get_database_backend())?;

        let user = save_provider_user::<S::User, _>(model, db, verification, None).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_user(&user, &hook_context).await?;
            }
        }
        Ok(user)
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: &ScopedTransaction,
        mut create_user: CreateUser,
    ) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(
            tx,
            Some(tx),
            create_user,
            alibi_core::store::UserCreationDefaults::default(),
        )
        .await
    }

    pub(crate) async fn create_user_prepared_in_tx(
        &self,
        tx: &ScopedTransaction,
        prepared: alibi_core::user_validation::PreparedUserCreation,
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
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        provider_verification_output::<S::User, _>(self.scoped_connection(), id).await
    }

    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(
            self.scoped_connection(),
            None,
            create_user,
            alibi_core::store::UserCreationDefaults::default(),
        )
        .await
    }

    async fn create_user_prepared(
        &self,
        prepared: alibi_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let (data, defaults) = prepared.into_parts();
        self.create_user_with_connection(self.scoped_connection(), None, data, defaults)
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
        let backend = self.scoped_connection().get_database_backend();
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
            .scoped_connection()
            .query_one_raw(Statement::from_sql_and_values(backend, sql, [value]))
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| AuthError::internal("Numeric text coercion returned no value"))?;
        // The configured database's own CAST decides the stored text.
        row.try_get("", "value").map_err(map_db_err)
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        let user_id = S::User::parse_id(id)?;
        user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(self.scoped_connection())
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

        user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids))
            .all(self.scoped_connection())
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
        let query = user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids));
        let backend = self.scoped_connection().get_database_backend();
        let statement = super::bind_page(query.build(backend), Some(limit), None)?;
        user_query::<S::User>(self.scoped_connection().get_database_backend())
            .from_raw_sql(statement)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        let email = normalize_user_email(email);
        user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::email_column().eq(email))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        let Some(col) = <S::User as SeaOrmUserModel>::username_column() else {
            return Ok(None);
        };
        user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(col.eq(username))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::internal("the user schema has no phone-number field"))?;
        user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(column.eq(phone_number))
            .one(self.scoped_connection())
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
                .await
                .map_err(alibi_core::store::adapter::callback_error)?
                .is_cancelled()
            {
                return Err(cancelled_by_hook("user update"));
            }
        }
        if let Some(username) = update.username.as_mut() {
            *username = username.to_lowercase();
        }
        let Some(model) = user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(self.scoped_connection())
            .await
            .map_err(map_db_err)?
        else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active_model();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        let provider_name = update.provider_name.take();
        let provider_image = update.provider_image.take();
        let verification = update.provider_email_verified.take();
        S::User::apply_update(&mut active, update, Utc::now());
        stage_provider_text::<S::User, _>(
            self.scoped_connection(),
            &mut active,
            provider_name,
            provider_image,
        )
        .await?;
        let backend = self.scoped_connection().get_database_backend();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value =
                crate::additional_fields::prepare_value(self.scoped_connection(), &column, value)
                    .await?;
            S::User::set_additional_field(&mut active, column, value, backend)?;
        }
        S::User::prepare_json_metadata(
            &mut active,
            self.scoped_connection().get_database_backend(),
        )?;

        let user = save_provider_user::<S::User, _>(
            active,
            self.scoped_connection(),
            verification,
            Some(id),
        )
        .await?;
        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context)
                .await
                .map_err(alibi_core::store::adapter::callback_error)?;
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
                return Ok(());
            }
        }
        // API keys reference their owner polymorphically, so they carry no
        // foreign key to cascade from. Without this, a deleted user's keys
        // would outlive them and start working again if the id were reused.
        let transaction = self
            .scoped_connection()
            .begin_with_options(sea_orm::TransactionOptions {
                sqlite_transaction_mode: Some(sea_orm::SqliteTransactionMode::Immediate),
                ..Default::default()
            })
            .await
            .map_err(map_db_err)?;
        _ = user_query::<S::User>(self.scoped_connection().get_database_backend())
            .filter(S::User::id_column().eq(user_id.clone()))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(map_db_err)?;
        super::teams::remove_owned_team_members(&transaction, &user.id(), None).await?;
        super::wallets::remove_owned_wallets(&transaction, &user.id()).await?;
        // Keep polymorphic API-key references; redemption rejects absent owners.

        _ = <S::User as SeaOrmUserModel>::Entity::delete_many()
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
        use alibi_core::UserFilterValue;
        let mut query = user_query::<S::User>(self.scoped_connection().get_database_backend());
        if let Some(value) = &params.filter_value {
            let operator = params.filter_operator.as_deref().unwrap_or("eq");
            if matches!(value, UserFilterValue::Multiple(_))
                || matches!(operator, "in" | "not_in")
                || !matches!(
                    params.filter_field.as_deref().unwrap_or("email"),
                    "email"
                        | "name"
                        | "username"
                        | "role"
                        | "banned"
                        | "createdAt"
                        | "updatedAt"
                        | "banExpires"
                )
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
                let numeric_cast = if self.scoped_connection().get_database_backend()
                    == sea_orm::DbBackend::Postgres
                {
                    use sea_orm::sea_query::ColumnType;
                    match column.def().get_column_type() {
                        ColumnType::Integer => Some("int4"),
                        ColumnType::BigInteger => Some("int8"),
                        ColumnType::Float => Some("float4"),
                        ColumnType::Double => Some("float8"),
                        _ => None,
                    }
                } else {
                    None
                };
                let bindings: Vec<sea_orm::Value> = if numeric_cast.is_some() {
                    numeric_filter_text(operands)
                        .into_iter()
                        .map(Into::into)
                        .collect()
                } else if matches!(value, UserFilterValue::Scalar(_))
                    && matches!(
                        column.def().get_column_type(),
                        sea_orm::sea_query::ColumnType::Boolean
                    )
                {
                    operands
                        .iter()
                        .map(|value_2| (value_2 == "true").into())
                        .collect()
                } else {
                    operands.iter().cloned().map(Into::into).collect()
                };
                let tuple = || {
                    Expr::tuple(bindings.iter().map(|value| {
                        numeric_cast.map_or_else(
                            || column.save_as(Expr::val(value.clone())),
                            |cast| Expr::cust_with_values(format!("$1::{cast}"), [value.clone()]),
                        )
                    }))
                };
                let condition = match operator {
                    "in" | "not_in" if numeric_cast.is_some() && bindings.is_empty() => {
                        Expr::cust_with_exprs(
                            if operator == "in" {
                                "$1 IN ()"
                            } else {
                                "$1 NOT IN ()"
                            },
                            [Expr::col(column)],
                        )
                    }
                    "in" | "not_in" if numeric_cast.is_some() => {
                        let values = bindings.iter().cloned().map(|value| {
                            Expr::cust_with_values(
                                format!("$1::{}", numeric_cast.unwrap_or_default()),
                                [value],
                            )
                        });
                        if operator == "in" {
                            Expr::col(column).is_in(values)
                        } else {
                            Expr::col(column).is_not_in(values)
                        }
                    }
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
        // Numeric IDs and application fields retain physical column ordering.
        // The shared projection cannot know the application's column types.
        let physical_sort = params.sort_by.as_deref().filter(|field| {
            !matches!(
                *field,
                "email"
                    | "name"
                    | "username"
                    | "role"
                    | "banned"
                    | "createdAt"
                    | "updatedAt"
                    | "banExpires"
            )
        });
        let presorted = if let Some(field) = physical_sort {
            let column = S::User::list_users_column(field).ok_or_else(|| {
                AuthError::bad_request("User sort field has no configured column")
            })?;
            query = if params.sort_direction.as_deref() == Some("desc") {
                query.order_by_desc(column)
            } else {
                query.order_by_asc(column)
            };
            true
        } else {
            false
        };
        let models = query
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?;

        Ok(if presorted {
            alibi_core::user_query::apply_list_users_presorted(models, &params)
        } else {
            alibi_core::user_query::apply_list_users(models, &params)
        })
    }
}

fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}

// Match Source's scalar/all-or-none array Number coercion before PostgreSQL
// parses the text as the declared numeric column type.
fn numeric_filter_text(values: &[String]) -> Vec<String> {
    let numbers = values
        .iter()
        .map(|value| {
            (!alibi_core::utils::javascript::trim(value).is_empty())
                .then(|| alibi_core::utils::javascript::string_to_number(value))
                .flatten()
                .filter(|number| !number.is_nan())
        })
        .collect::<Option<Vec<_>>>();
    numbers.map_or_else(
        || values.to_vec(),
        |numbers| {
            numbers
                .into_iter()
                .map(|number| ryu_js::Buffer::new().format(number).to_owned())
                .collect()
        },
    )
}
