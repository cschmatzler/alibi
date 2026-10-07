use super::{SqlxStore, lock_exclusive, lock_shared};
use crate::error::record_not_updated;
use crate::model::{self, SqlxModel};
use crate::pool::{Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxUserModel};
use crate::sql::Sql;
use crate::value::{ColumnKind, SqlValue};
use alibi_core::AuthUser;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::store::{NumericTextInput, UserStore};
use alibi_core::types::{CreateUser, ListUsersParams, UpdateUser};
use async_trait::async_trait;
use chrono::Utc;

/// Row lock applied to a user lookup inside a transaction.
#[derive(Clone, Copy)]
pub(super) enum Lock {
    None,
    Shared,
    Exclusive,
}

pub(super) async fn find_user_by_id<M: SqlxUserModel>(
    exec: Exec<'_>,
    id: &str,
    lock: Lock,
) -> AuthResult<Option<M>> {
    let id = M::parse_id(id)?;
    let mut sql = model::select_model::<M>(exec);
    sql.push(" WHERE ");
    sql.compare_model::<M>(M::TABLE, M::id_column(), " = ", id);
    sql.push(" LIMIT 1");
    match lock {
        Lock::None => {}
        Lock::Shared => lock_shared(&mut sql),
        Lock::Exclusive => lock_exclusive(&mut sql),
    }
    exec.fetch_optional(sql).await
}

pub(super) async fn provider_verification_output<M: SqlxUserModel>(
    exec: Exec<'_>,
    id: &str,
) -> AuthResult<Option<serde_json::Value>> {
    if exec.engine() != crate::pool::Engine::Sqlite {
        return Ok(None);
    }
    let Some(column) = M::PROVIDER_VERIFICATION_COLUMN else {
        return Ok(None);
    };
    let mut sql = Sql::new(exec.engine());
    sql.push("SELECT CASE typeof(");
    sql.ident(column);
    sql.push(") WHEN 'text' THEN json_quote(");
    sql.ident(column);
    sql.push(") WHEN 'null' THEN 'null' ELSE CASE WHEN ");
    sql.ident(column);
    sql.push(" = 1 THEN 'true' ELSE 'false' END END FROM ");
    sql.ident(M::TABLE);
    sql.push(" WHERE ");
    sql.compare(M::TABLE, M::id_column(), " = ", M::parse_id(id)?);
    sql.push(" LIMIT 1");
    exec.fetch_scalar::<String>(sql)
        .await?
        .map(|value| {
            alibi_core::utils::json::from_slice(value.as_bytes())
                .map_err(|error| AuthError::internal(error.to_string()))
        })
        .transpose()
}

fn stage_provider_verification<M: SqlxUserModel>(
    active: &mut crate::model::ActiveRow,
    value: Option<serde_json::Value>,
    engine: crate::pool::Engine,
) -> AuthResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    // Boolean inputs retain the ordinary typed-model path on every engine.
    if value.is_boolean() {
        return Ok(());
    }
    let column = M::PROVIDER_VERIFICATION_COLUMN.ok_or_else(|| {
        AuthError::internal("The user model does not expose its provider verification column")
    })?;
    let value = match value {
        serde_json::Value::Null => SqlValue::Bool(None),
        serde_json::Value::String(value) => SqlValue::Text(Some(value)),
        serde_json::Value::Number(value) => {
            if engine == crate::pool::Engine::Postgres {
                SqlValue::Text(Some(
                    alibi_core::utils::json::number_to_string(&value)
                        .map_err(|error| AuthError::internal(error.to_string()))?,
                ))
            } else if let Some(value) = value.as_i64() {
                SqlValue::BigInt(Some(value))
            } else {
                SqlValue::Double(value.as_f64())
            }
        }
        _ => {
            return Err(AuthError::internal(
                "Unsupported provider verification SQL parameter",
            ));
        }
    };
    active.set(column, value);
    Ok(())
}

async fn stage_provider_text<M: SqlxUserModel>(
    exec: Exec<'_>,
    active: &mut crate::model::ActiveRow,
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
        let value =
            crate::additional_fields::prepare_value(exec, M::column_kind(column), value).await?;
        active.set(column, value);
    }
    Ok(())
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: SqlxUserModel,
{
    async fn create_user_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        mut create_user: CreateUser,
        defaults: alibi_core::store::UserCreationDefaults,
    ) -> AuthResult<S::User> {
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
        let provider_name = create_user.provider_name.take();
        let provider_image = create_user.provider_image.take();
        let provider_verification = create_user.provider_email_verified.take();
        let mut active = S::User::new_active(user_id, create_user, now);
        stage_provider_verification::<S::User>(&mut active, provider_verification, exec.engine())?;
        stage_provider_text::<S::User>(exec, &mut active, provider_name, provider_image).await?;
        let backend = exec.engine();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(
                exec,
                <S::User as SqlxModel>::column_kind(column),
                value,
            )
            .await?;
            S::User::set_additional_field(&mut active, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut active, backend)?;

        let user = model::insert::<S::User>(exec, &active).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_user(&user, &hook_context).await?;
            }
        }
        Ok(user)
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: &SqlxTransaction,
        mut create_user: CreateUser,
    ) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(
            Exec::Tx(tx),
            Some(tx),
            create_user,
            alibi_core::store::UserCreationDefaults::default(),
        )
        .await
    }

    pub(crate) async fn create_user_prepared_in_tx(
        &self,
        tx: &SqlxTransaction,
        prepared: alibi_core::user_validation::PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let (data, defaults) = prepared.into_parts();
        self.create_user_with_connection(Exec::Tx(tx), Some(tx), data, defaults)
            .await
    }

    fn user_lookup(&self, column: &str, value: impl Into<SqlValue>) -> Sql {
        let mut sql = model::select_model::<S::User>(self.exec());
        sql.push(" WHERE ");
        sql.compare_model::<S::User>(<S::User as SqlxModel>::TABLE, column, " = ", value);
        sql.push(" LIMIT 1");
        sql
    }
}

#[async_trait]
impl<S> UserStore<S> for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::User: SqlxUserModel,
{
    async fn provider_verification_output(
        &self,
        id: &str,
    ) -> AuthResult<Option<serde_json::Value>> {
        provider_verification_output::<S::User>(self.exec(), id).await
    }

    async fn create_user(&self, mut create_user: CreateUser) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(
            self.exec(),
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
        self.create_user_with_connection(self.exec(), None, data, defaults)
            .await
    }

    async fn coerce_user_text_number(&self, input: NumericTextInput) -> AuthResult<String> {
        let value: SqlValue = match input {
            NumericTextInput::Integer(value) => value.into(),
            NumericTextInput::Real(value) if !value.is_nan() => value.into(),
            NumericTextInput::Real(_) => {
                return Err(AuthError::bad_request("Numeric text input must not be NaN"));
            }
        };
        let backend = self.exec().engine();
        let mut sql = Sql::with(backend, "SELECT CAST(");
        sql.bind(value);
        sql.push(" AS TEXT) AS value");
        // The configured database's own CAST decides the stored text.
        self.exec()
            .fetch_scalar::<String>(sql)
            .await?
            .ok_or_else(|| AuthError::internal("Numeric text coercion returned no value"))
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        find_user_by_id::<S::User>(self.exec(), id, Lock::None).await
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let user_ids = ids
            .iter()
            .map(|id| S::User::parse_id(id))
            .collect::<AuthResult<Vec<_>>>()?;
        let mut sql = model::select_model::<S::User>(self.exec());
        sql.push(" WHERE ");
        sql.column(<S::User as SqlxModel>::TABLE, S::User::id_column());
        sql.push(" IN ");
        sql.bind_list(user_ids);
        self.exec().fetch_all(sql).await
    }

    async fn list_users_by_ids_page(&self, ids: &[String], limit: f64) -> AuthResult<Vec<S::User>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let user_ids = ids
            .iter()
            .map(|id| S::User::parse_id(id))
            .collect::<AuthResult<Vec<_>>>()?;
        let mut sql = model::select_model::<S::User>(self.exec());
        sql.push(" WHERE ");
        sql.column(<S::User as SqlxModel>::TABLE, S::User::id_column());
        sql.push(" IN ");
        sql.bind_list(user_ids);
        super::bind_page(&mut sql, Some(limit), None);
        self.exec().fetch_all(sql).await
    }

    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<S::User>> {
        let email = normalize_user_email(email);
        let sql = self.user_lookup(S::User::email_column(), email);
        self.exec().fetch_optional(sql).await
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        let Some(column) = S::User::username_column() else {
            return Ok(None);
        };
        let sql = self.user_lookup(column, username);
        self.exec().fetch_optional(sql).await
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::internal("the user schema has no phone-number field"))?;
        let sql = self.user_lookup(column, phone_number);
        self.exec().fetch_optional(sql).await
    }

    async fn update_user(&self, id: &str, mut update: UpdateUser) -> AuthResult<S::User> {
        update.email = update.email.map(|email| normalize_user_email(&email));
        drop(S::User::parse_id(id)?);
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
        let Some(model) = find_user_by_id::<S::User>(self.exec(), id, Lock::None).await? else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        let provider_name = update.provider_name.take();
        let provider_image = update.provider_image.take();
        let provider_verification = update.provider_email_verified.take();
        S::User::apply_update(&mut active, update, Utc::now());
        stage_provider_verification::<S::User>(
            &mut active,
            provider_verification,
            self.exec().engine(),
        )?;
        stage_provider_text::<S::User>(self.exec(), &mut active, provider_name, provider_image)
            .await?;
        let backend = self.exec().engine();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(
                self.exec(),
                <S::User as SqlxModel>::column_kind(column),
                value,
            )
            .await?;
            S::User::set_additional_field(&mut active, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut active, backend)?;

        let user = model::update::<S::User>(self.exec(), &active)
            .await?
            .ok_or_else(record_not_updated)?;
        for hook in self.hooks() {
            hook.after_update_user(&user, &hook_context)
                .await
                .map_err(alibi_core::store::adapter::callback_error)?;
        }
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        drop(S::User::parse_id(id)?);
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
        let owner = user.id().into_owned();
        let id = id.to_owned();
        self.in_transaction(true, async move |tx| {
            let exec = Exec::Tx(tx);
            drop(find_user_by_id::<S::User>(exec, &id, Lock::Exclusive).await?);
            super::teams::remove_owned_team_members(tx, &owner, None).await?;
            super::wallets::remove_owned_wallets(tx, &owner).await?;
            // Core-only generated schemas omit this optional table. Check on
            // the held transaction; a present table must still be cleaned even
            // when the API-key plugin is no longer registered.
            if super::migrator::has_table(exec, "api_keys").await? {
                let mut keys = Sql::with(exec.engine(), "DELETE FROM ");
                keys.ident("api_keys");
                keys.push(" WHERE ");
                keys.compare("api_keys", "reference_id", " = ", owner.clone());
                _ = exec.execute(keys).await?;
            }
            let mut users = Sql::with(exec.engine(), "DELETE FROM ");
            users.ident(<S::User as SqlxModel>::TABLE);
            users.push(" WHERE ");
            users.compare_model::<S::User>(
                <S::User as SqlxModel>::TABLE,
                S::User::id_column(),
                " = ",
                S::User::parse_id(&id)?,
            );
            _ = exec.execute(users).await?;
            Ok(())
        })
        .await?;
        for hook in self.hooks() {
            hook.after_delete_user(&user, &hook_context).await?;
        }
        Ok(())
    }

    async fn list_users(&self, mut params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        use alibi_core::UserFilterValue;
        let table = <S::User as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::User>(self.exec());
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
                let numeric_cast = if self.exec().engine() == crate::pool::Engine::Postgres {
                    match <S::User as SqlxModel>::column_kind(column) {
                        ColumnKind::Int => Some("int4"),
                        ColumnKind::BigInt => Some("int8"),
                        ColumnKind::Float => Some("float4"),
                        ColumnKind::Double => Some("float8"),
                        _ => None,
                    }
                } else {
                    None
                };
                let bindings: Vec<SqlValue> = if numeric_cast.is_some() {
                    numeric_filter_text(operands)
                        .into_iter()
                        .map(Into::into)
                        .collect()
                } else if matches!(value, UserFilterValue::Scalar(_))
                    && <S::User as SqlxModel>::column_kind(column) == ColumnKind::Boolean
                {
                    operands
                        .iter()
                        .map(|value_2| (value_2 == "true").into())
                        .collect()
                } else {
                    operands
                        .iter()
                        .cloned()
                        .map(|value| S::User::column_value(column, value.into()))
                        .collect()
                };
                sql.push(" WHERE ");
                match operator {
                    "in" | "not_in" if bindings.is_empty() && numeric_cast.is_none() => {
                        sql.push(if operator == "in" { "1 = 2" } else { "1 = 1" });
                    }
                    "in" => {
                        sql.column(table, column);
                        sql.push(" IN ");
                        bind_filter_values(&mut sql, bindings, numeric_cast);
                    }
                    "not_in" => {
                        sql.column(table, column);
                        sql.push(" NOT IN ");
                        bind_filter_values(&mut sql, bindings, numeric_cast);
                    }
                    // The pinned adapter interpolates the complete array's
                    // comma-joined value into a bound LIKE pattern. Actual SQL
                    // retains backend case, wildcard and NULL semantics.
                    "contains" => {
                        sql.compare_model::<S::User>(
                            table,
                            column,
                            " LIKE ",
                            format!("%{}%", operands.join(",")),
                        );
                    }
                    "starts_with" => {
                        sql.compare_model::<S::User>(
                            table,
                            column,
                            " LIKE ",
                            format!("{}%", operands.join(",")),
                        );
                    }
                    "ends_with" => {
                        sql.compare_model::<S::User>(
                            table,
                            column,
                            " LIKE ",
                            format!("%{}", operands.join(",")),
                        );
                    }
                    "eq" | "ne" | "lt" | "lte" | "gt" | "gte" => {
                        let comparison = match operator {
                            "eq" => " = ",
                            "ne" => " <> ",
                            "lt" => " < ",
                            "lte" => " <= ",
                            "gt" => " > ",
                            _ => " >= ",
                        };
                        sql.ident(column);
                        sql.push(comparison);
                        bind_filter_values(&mut sql, bindings, numeric_cast);
                    }
                    _ => return Err(AuthError::bad_request("Unsupported user filter operator")),
                }
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
            sql.push(" ORDER BY ");
            sql.column(table, column);
            sql.push(if params.sort_direction.as_deref() == Some("desc") {
                " DESC"
            } else {
                " ASC"
            });
            true
        } else {
            false
        };
        let models = self.exec().fetch_all(sql).await?;

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

// Source converts a nonempty numeric scalar, or every numeric array operand,
// to Number before node-postgres serializes the parameter. An invalid array
// keeps all its original strings. PostgreSQL validates the resulting text.
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

fn bind_filter_values(sql: &mut Sql, values: Vec<SqlValue>, cast: Option<&str>) {
    sql.push("(");
    for (index, value) in values.into_iter().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        sql.bind(value);
        if let Some(cast) = cast {
            sql.push("::");
            sql.push(cast);
        }
    }
    sql.push(")");
}
