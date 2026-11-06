use super::{SqlxStore, lock_exclusive, lock_shared};
use crate::error::record_not_updated;
use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::{Engine, Exec, SqlxTransaction};
use crate::schema::{AuthSchema, SqlxUserModel};
use crate::sql::Sql;
use crate::value::{ColumnKind, SqlValue};
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::store::{NumericTextInput, UserCreationDefaults, UserStore};
use alibi_core::types::{CreateUser, ListUsersParams, UpdateUser};
use alibi_core::user_validation::PreparedUserCreation;
use alibi_core::{AuthUser, UserFilterValue};
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
    model::limit_one(&mut sql);
    match lock {
        Lock::None => {}
        Lock::Shared => lock_shared(&mut sql),
        Lock::Exclusive => lock_exclusive(&mut sql),
    }
    exec.fetch_optional(sql).await
}

pub(super) async fn native_user_output<M: SqlxUserModel>(
    exec: Exec<'_>,
    id: &str,
) -> AuthResult<std::collections::BTreeMap<String, serde_json::Value>> {
    let mut output = std::collections::BTreeMap::new();
    if exec.engine() != Engine::Sqlite {
        return Ok(output);
    }
    for field in [
        "emailVerified",
        "banned",
        "twoFactorEnabled",
        "isAnonymous",
        "phoneNumberVerified",
        "createdAt",
        "updatedAt",
        "banExpires",
    ] {
        let Some(column) = M::list_users_column(field) else {
            continue;
        };
        let date = matches!(field, "createdAt" | "updatedAt" | "banExpires");
        let mut sql = Sql::with(exec.engine(), "SELECT ");
        if date {
            sql.push("json_quote(");
            sql.ident(column);
            sql.push(")");
        } else {
            sql.push("CASE typeof(");
            sql.ident(column);
            sql.push(") WHEN 'text' THEN json_quote(");
            sql.ident(column);
            sql.push(") WHEN 'null' THEN 'null' ELSE CASE WHEN ");
            sql.ident(column);
            sql.push(" = 1 THEN 'true' ELSE 'false' END END");
        }
        sql.push(" FROM ");
        sql.ident(M::TABLE);
        sql.push(" WHERE ");
        sql.compare(M::TABLE, M::id_column(), " = ", M::parse_id(id)?);
        sql.push(" LIMIT 1");
        if let Some(value) = exec.fetch_scalar::<String>(sql).await? {
            let mut value: serde_json::Value = serde_json::from_str(&value)?;
            if date && let Some(text) = value.as_str() {
                value = alibi_core::utils::datetime::parse_date_millis(text)
                    .map(alibi_core::utils::datetime::json_date_millis)
                    .map_or(serde_json::Value::Null, serde_json::Value::String);
            }
            _ = output.insert(field.to_owned(), value);
        }
    }
    Ok(output)
}

pub(super) async fn provider_verification_output<M: SqlxUserModel>(
    exec: Exec<'_>,
    id: &str,
) -> AuthResult<Option<serde_json::Value>> {
    if exec.engine() != Engine::Sqlite {
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
    active: &mut ActiveRow,
    value: Option<alibi_core::utils::json::JsValue>,
    engine: Engine,
) -> AuthResult<()> {
    let Some(value) = value.map(|value| value.to_json_value()).transpose()? else {
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
            if engine == Engine::Postgres {
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
    active: &mut ActiveRow,
    name: Option<alibi_core::utils::json::JsValue>,
    image: Option<alibi_core::utils::json::JsValue>,
    email: Option<alibi_core::utils::json::JsValue>,
) -> AuthResult<()> {
    for (field, raw) in [("name", name), ("image", image), ("email", email)] {
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
            M::list_users_column(field)
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
        defaults: UserCreationDefaults,
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
        let now = Utc::now();
        if create_user.id.as_deref() == Some("") {
            _ = create_user
                .adapter_native_fields
                .insert("id".into(), serde_json::json!(""));
            create_user.id = None;
        }
        if create_user
            .adapter_native_fields
            .get("id")
            .is_some_and(serde_json::Value::is_null)
        {
            _ = create_user.adapter_native_fields.remove("id");
        }
        if create_user.id.is_none() && !create_user.adapter_native_fields.contains_key("id") {
            create_user.id = self
                .generated_id(
                    exec,
                    "user",
                    <S::User as SqlxModel>::TABLE,
                    S::User::id_column(),
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
        let provider_email = create_user.provider_email.take();
        let provider_verification = create_user.provider_email_verified.take();
        let native_fields = std::mem::take(&mut create_user.adapter_native_fields);
        if let Some(raw_id) = native_fields.get("id") {
            _ = create_user
                .adapter_native_fields
                .insert("id".into(), raw_id.clone());
        }
        let mut active = S::User::new_active(user_id, create_user, now);
        stage_provider_verification::<S::User>(&mut active, provider_verification, exec.engine())?;
        stage_provider_text::<S::User>(
            exec,
            &mut active,
            provider_name,
            provider_image,
            provider_email,
        )
        .await?;
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
        for (field, raw) in native_fields {
            let Some(column) = S::User::list_users_column(&field) else {
                continue;
            };
            let kind = S::User::column_kind(column);
            if field == "id" && !alibi_core::utils::json::JsValue::from(raw.clone()).is_truthy() {
                continue;
            }
            if (raw.is_object() || raw.is_array()) && kind != ColumnKind::Json {
                return Err(AuthError::internal("Unsupported native user SQL parameter"));
            }
            let value =
                crate::additional_fields::raw_value(&alibi_core::utils::json::JsValue::from(raw))?;
            let value = if matches!(field.as_str(), "createdAt" | "updatedAt" | "banExpires") {
                match value {
                    SqlValue::Text(Some(value)) if backend == Engine::Sqlite => {
                        SqlValue::Text(Some(value))
                    }
                    SqlValue::Text(Some(value)) => chrono::DateTime::parse_from_rfc3339(&value)
                        .map(|date| S::User::timestamp_value(column, date.with_timezone(&Utc)))
                        .map_err(|error| AuthError::internal(error.to_string()))?,
                    SqlValue::Text(None) => SqlValue::Timestamp(None),
                    value => value,
                }
            } else {
                crate::additional_fields::prepare_value(exec, kind, value).await?
            };
            active.set(column, value);
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
            Exec::tx(tx),
            Some(tx),
            create_user,
            alibi_core::store::UserCreationDefaults::default(),
        )
        .await
    }

    pub(crate) async fn create_user_prepared_in_tx(
        &self,
        tx: &SqlxTransaction,
        prepared: PreparedUserCreation,
    ) -> AuthResult<S::User> {
        let (data, defaults) = prepared.into_parts();
        self.create_user_with_connection(Exec::tx(tx), Some(tx), data, defaults)
            .await
    }

    async fn users_by_ids(&self, ids: &[String], limit: Option<f64>) -> AuthResult<Vec<S::User>> {
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
        super::bind_page(&mut sql, limit, None);
        self.exec().fetch_all(sql).await
    }

    /// Bind an admin user-list predicate with the configured SQL semantics.
    fn push_user_filter(
        &self,
        sql: &mut Sql,
        filter_field: Option<&str>,
        operator: &str,
        value: &UserFilterValue,
    ) -> AuthResult<()> {
        let table = <S::User as SqlxModel>::TABLE;
        let field = filter_field
            .filter(|field| !field.is_empty())
            .unwrap_or("email");
        let column = S::User::list_users_column(field)
            .ok_or_else(|| AuthError::bad_request("User filter field has no configured column"))?;
        let native = value.native();
        if operator == "in" && !matches!(native, alibi_core::utils::json::JsValue::Array(_)) {
            return Err(AuthError::bad_request("Value must be an array"));
        }
        let kind = <S::User as SqlxModel>::column_kind(column);
        let numeric = matches!(
            kind,
            ColumnKind::Number
                | ColumnKind::Int
                | ColumnKind::BigInt
                | ColumnKind::Float
                | ColumnKind::Double
        );
        let native = transform_filter_operand(
            native,
            kind == ColumnKind::Boolean,
            numeric,
            self.exec().engine() == Engine::Postgres,
        );
        let pattern = native
            .coerce_js_string()
            .map_err(AuthError::internal)?
            .to_utf8_binding();
        let operands = match native {
            alibi_core::utils::json::JsValue::Array(values) => values,
            value => vec![value],
        };
        let numeric_cast = if self.exec().engine() == Engine::Postgres {
            match kind {
                ColumnKind::Boolean => Some("boolean"),
                ColumnKind::Int => Some("int4"),
                ColumnKind::BigInt => Some("int8"),
                ColumnKind::Float => Some("float4"),
                ColumnKind::Double => Some("float8"),
                _ => None,
            }
        } else {
            None
        };
        let bindings: Vec<SqlValue> = operands
            .into_iter()
            .map(|value| {
                use alibi_core::utils::json::JsValue;
                // node-postgres sends primitives as text with the SQL column's inferred type.
                let value = if self.exec().engine() == Engine::Postgres
                    && (numeric_cast.is_some()
                        || matches!(kind, ColumnKind::Text | ColumnKind::BpChar))
                {
                    value
                        .coerce_js_string()
                        .map_err(AuthError::internal)?
                        .to_utf8_binding()
                        .into()
                } else {
                    match value {
                        JsValue::String(value) => value.to_utf8_binding().into(),
                        JsValue::Number(value) => value.into(),
                        JsValue::Bool(value) => value.into(),
                        _ => return Err(AuthError::bad_request("Unsupported user filter operand")),
                    }
                };
                Ok(S::User::column_value(column, value))
            })
            .collect::<AuthResult<_>>()?;
        match operator {
            "in" | "not_in" if bindings.is_empty() && numeric_cast.is_none() => {
                sql.push(if operator == "in" { "1 = 2" } else { "1 = 1" });
            }
            "in" => {
                sql.column(table, column);
                sql.push(" IN ");
                bind_filter_values(sql, bindings, numeric_cast);
            }
            "not_in" => {
                sql.column(table, column);
                sql.push(" NOT IN ");
                bind_filter_values(sql, bindings, numeric_cast);
            }
            // The pinned adapter interpolates the complete array's
            // comma-joined value into a bound LIKE pattern. Actual SQL
            // retains backend case, wildcard and NULL semantics.
            "contains" => {
                sql.compare_model::<S::User>(table, column, " LIKE ", format!("%{pattern}%"));
            }
            "starts_with" => {
                sql.compare_model::<S::User>(table, column, " LIKE ", format!("{pattern}%"));
            }
            "ends_with" => {
                sql.compare_model::<S::User>(table, column, " LIKE ", format!("%{pattern}"));
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
                bind_filter_values(sql, bindings, numeric_cast);
            }
            _ => return Err(AuthError::bad_request("Unsupported user filter operator")),
        }
        Ok(())
    }

    fn user_list_predicates(&self, sql: &mut Sql, params: &ListUsersParams) -> AuthResult<()> {
        let filtered = if let Some(search) = params
            .search_value
            .as_ref()
            .filter(|search| !search.is_empty())
        {
            sql.push(" WHERE ");
            self.push_user_filter(
                sql,
                params.search_field.as_deref(),
                params.search_operator.as_deref().unwrap_or("contains"),
                &UserFilterValue::Scalar(search.clone()),
            )?;
            true
        } else {
            false
        };
        if let Some(value) = &params.filter_value {
            sql.push(if filtered { " AND " } else { " WHERE " });
            self.push_user_filter(
                sql,
                params.filter_field.as_deref(),
                params.filter_operator.as_deref().unwrap_or("eq"),
                value,
            )?;
        }
        Ok(())
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
    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, serde_json::Value>> {
        native_user_output::<S::User>(self.exec(), id).await
    }

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

    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
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
        // The database's own CAST decides the stored text.
        self.exec()
            .fetch_scalar::<String>(sql)
            .await?
            .ok_or_else(|| AuthError::internal("Numeric text coercion returned no value"))
    }

    async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<S::User>> {
        find_user_by_id::<S::User>(self.exec(), id, Lock::None).await
    }

    async fn list_users_by_ids(&self, ids: &[String]) -> AuthResult<Vec<S::User>> {
        self.users_by_ids(ids, None).await
    }

    async fn list_users_by_ids_page(&self, ids: &[String], limit: f64) -> AuthResult<Vec<S::User>> {
        self.users_by_ids(ids, Some(limit)).await
    }

    async fn get_user_by_email(
        &self,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        self.get_user_by_email_with_connection(self.exec(), email)
            .await
    }

    async fn get_user_by_username(&self, username: &str) -> AuthResult<Option<S::User>> {
        let Some(column) = S::User::username_column() else {
            return Ok(None);
        };
        let sql = self.user_lookup(column, username);
        self.exec().fetch_optional(sql).await
    }

    async fn get_user_by_username_value(
        &self,
        username: &alibi_core::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        self.get_user_by_username_value_with_connection(self.exec(), username)
            .await
    }

    async fn get_user_by_phone_number(&self, phone_number: &str) -> AuthResult<Option<S::User>> {
        let column = S::User::phone_number_column()
            .ok_or_else(|| AuthError::internal("the user schema has no phone-number field"))?;
        let sql = self.user_lookup(column, phone_number);
        self.exec().fetch_optional(sql).await
    }

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        self.update_user_with_connection(self.exec(), None, id, update)
            .await
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        _ = S::User::parse_id(id)?;
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
        // API keys retain their polymorphic reference. Redemption resolves the
        // owner and rejects a missing user with the public identity error.
        let owner = user.id().into_owned();
        let id = id.to_owned();
        self.in_transaction(true, async move |tx| {
            let exec = Exec::tx(tx);
            _ = find_user_by_id::<S::User>(exec, &id, Lock::Exclusive).await?;
            super::teams::remove_owned_team_members(tx, &owner, None).await?;
            super::wallets::remove_owned_wallets(tx, &owner).await?;
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

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        let table = <S::User as SqlxModel>::TABLE;
        let mut sql = model::select_model::<S::User>(self.exec());
        self.user_list_predicates(&mut sql, &params)?;
        let field = params
            .sort_by
            .as_deref()
            .filter(|field| !field.is_empty())
            .unwrap_or("createdAt");
        let column = S::User::list_users_column(field)
            .ok_or_else(|| AuthError::bad_request("User sort field has no configured column"))?;
        sql.push(" ORDER BY ");
        sql.column(table, column);
        let direction = params.sort_direction.as_deref().unwrap_or_else(|| {
            if params.sort_by.is_some() {
                "asc"
            } else {
                "desc"
            }
        });
        sql.push(if direction == "desc" { " DESC" } else { " ASC" });
        let number = |value: usize| value.to_string().parse::<f64>().ok();
        let limit = params
            .source_limit
            .or_else(|| params.limit.and_then(number))
            .or_else(|| self.find_many_limit().to_string().parse().ok());
        let offset = params
            .source_offset
            .or_else(|| params.offset.and_then(number));
        super::bind_page(&mut sql, limit, offset);
        let users = self.exec().fetch_all(sql).await?;
        let mut count = Sql::with(self.exec().engine(), "SELECT COUNT(*) FROM ");
        count.ident(table);
        self.user_list_predicates(&mut count, &params)?;
        let total = usize::try_from(
            self.exec()
                .fetch_scalar::<i64>(count)
                .await?
                .unwrap_or_default(),
        )
        .map_err(|_| AuthError::internal("User count exceeds usize"))?;
        Ok((users, total))
    }
}

fn normalize_user_email(email: &str) -> String {
    email.to_lowercase()
}

// Adapter factory transformations are scalar-only for booleans and
// all-or-none for string arrays on numeric fields.
fn transform_filter_operand(
    value: alibi_core::utils::json::JsValue,
    boolean: bool,
    numeric: bool,
    supports_booleans: bool,
) -> alibi_core::utils::json::JsValue {
    use alibi_core::utils::{
        javascript::{string_to_number, trim},
        json::JsValue,
    };
    if boolean {
        let value = match value {
            JsValue::String(value) => JsValue::Bool(value == "true"),
            value => value,
        };
        return match value {
            JsValue::Bool(value) if !supports_booleans => {
                JsValue::Number(f64::from(u8::from(value)))
            }
            value => value,
        };
    }
    if numeric {
        let parse = |value: &JsValue| {
            value
                .as_str()
                .filter(|value| !trim(value).is_empty())
                .and_then(string_to_number)
                .filter(|value| !value.is_nan())
                .map(JsValue::Number)
        };
        match &value {
            JsValue::String(_) => {
                if let Some(number) = parse(&value) {
                    return number;
                }
            }
            JsValue::Array(values) => {
                if let Some(numbers) = values.iter().map(parse).collect::<Option<Vec<_>>>() {
                    return JsValue::Array(numbers);
                }
            }
            _ => {}
        }
    }
    value
}

fn bind_filter_values(sql: &mut Sql, values: Vec<SqlValue>, cast: Option<&str>) {
    sql.push("(");
    for (index, value) in values.into_iter().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        let cast = cast.filter(|_| matches!(value, SqlValue::Text(_)));
        sql.bind(value);
        if let Some(cast) = cast {
            sql.push("::");
            sql.push(cast);
        }
    }
    sql.push(")");
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: crate::schema::SqlxUserModel,
{
    pub(super) async fn update_user_with_connection(
        &self,
        exec: Exec<'_>,
        tx: Option<&SqlxTransaction>,
        id: &str,
        mut update: UpdateUser,
    ) -> AuthResult<S::User> {
        update.email = update.email.map(|email| normalize_user_email(&email));
        _ = S::User::parse_id(id)?;
        let hook_context = self.hook_context(tx);
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
        let Some(model) = find_user_by_id::<S::User>(exec, id, Lock::None).await? else {
            return Err(AuthError::UserNotFound);
        };

        let mut active = model.into_active();
        let mut fields = std::mem::take(&mut update.additional_fields);
        fields.apply_adapter_transforms_async().await?;
        let provider_name = update.provider_name.take();
        let provider_image = update.provider_image.take();
        let provider_email = update.provider_email.take();
        let provider_verification = update.provider_email_verified.take();
        let native_fields = std::mem::take(&mut update.adapter_native_fields);
        S::User::apply_update(&mut active, update, Utc::now());
        stage_provider_verification::<S::User>(&mut active, provider_verification, exec.engine())?;
        stage_provider_text::<S::User>(
            exec,
            &mut active,
            provider_name,
            provider_image,
            provider_email,
        )
        .await?;
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

        for (field, raw) in native_fields {
            if !matches!(
                field.as_str(),
                "banExpires" | "username" | "displayUsername"
            ) {
                return Err(AuthError::internal("Unsupported native user update field"));
            }
            let Some(column) = S::User::list_users_column(&field) else {
                continue;
            };
            if raw.is_object() || raw.is_array() {
                return Err(AuthError::internal("Unsupported native user SQL parameter"));
            }
            let value =
                crate::additional_fields::raw_value(&alibi_core::utils::json::JsValue::from(raw))?;
            let value = match value {
                SqlValue::Text(Some(value))
                    if field == "banExpires" && backend != Engine::Sqlite =>
                {
                    chrono::DateTime::parse_from_rfc3339(&value)
                        .map(|date| S::User::timestamp_value(column, date.with_timezone(&Utc)))
                        .map_err(|error| AuthError::internal(error.to_string()))?
                }
                SqlValue::Text(None) if field == "banExpires" => SqlValue::Timestamp(None),
                value => value,
            };
            let value = crate::additional_fields::prepare_value(
                exec,
                <S::User as SqlxModel>::column_kind(column),
                value,
            )
            .await?;
            active.set(column, value);
        }
        let user = model::update::<S::User>(exec, &active)
            .await?
            .ok_or_else(record_not_updated)?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_update_user(&user, &hook_context)
                    .await
                    .map_err(alibi_core::store::adapter::callback_error)?;
            }
        }
        Ok(user)
    }
}

impl<S> SqlxStore<S>
where
    S: AuthSchema,
    S::User: crate::schema::SqlxUserModel,
{
    pub(super) async fn get_user_by_username_value_with_connection(
        &self,
        exec: Exec<'_>,
        username: &alibi_core::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        let Some(column) = S::User::username_column() else {
            return Ok(None);
        };
        if matches!(
            username,
            alibi_core::utils::json::JsValue::Array(_)
                | alibi_core::utils::json::JsValue::Object(_)
        ) {
            return Err(AuthError::internal("Unsupported native user SQL parameter"));
        }
        let value = crate::additional_fields::raw_value(username)?;
        exec.fetch_optional(self.user_lookup(column, value)).await
    }

    pub(super) async fn get_user_by_email_with_connection(
        &self,
        exec: Exec<'_>,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        let email = normalize_user_email(&email.to_utf8_binding());
        let sql = self.user_lookup(S::User::email_column(), email);
        exec.fetch_optional(sql).await
    }
}

#[cfg(test)]
mod typed_filter_tests {
    use super::*;
    use serde_json::json;

    #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, crate::AuthEntity)]
    #[auth(role = "user", table = "filter_user")]
    struct FilterUser {
        pub id: String,
        pub name: String,
        pub email: String,
        #[sqlx(rename = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sqlx(rename = "createdAt")]
        pub created_at: chrono::DateTime<Utc>,
        #[sqlx(rename = "updatedAt")]
        pub updated_at: chrono::DateTime<Utc>,
        pub score: f64,
    }

    struct FilterSchema;
    impl AuthSchema for FilterSchema {
        type User = FilterUser;
        type Session = super::super::entities::session::Model;
        type Account = super::super::entities::account::Model;
        type Verification = super::super::entities::verification::Model;
    }

    #[tokio::test]
    async fn typed_user_filter_sqlite_bound_affinity() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        _ = sqlx::query(TABLE).execute(&pool).await.unwrap();
        _ = sqlx::query(ROWS).execute(&pool).await.unwrap();
        let store = SqlxStore::<FilterSchema>::new(alibi_core::AuthConfig::default(), pool);

        for (field, operator, raw, expected) in [
            ("name", "eq", json!(2), "b"),
            ("name", "eq", json!("2"), "a"),
            ("name", "ne", json!(2), "a c d e f"),
            ("name", "eq", json!(true), "d"),
            ("name", "eq", json!("true"), "c"),
            ("name", "eq", json!(false), "e"),
            ("name", "eq", json!("false"), "f"),
            ("name", "in", json!([2, 10]), "b"),
            ("name", "not_in", json!([2, 10]), "a c d e f"),
            ("name", "in", json!(["2", "10"]), "a"),
            ("name", "contains", json!(2), "a b"),
            ("name", "in", json!([]), ""),
            ("name", "not_in", json!([]), "a b c d e f"),
            ("emailVerified", "eq", json!(true), "a c f"),
            ("emailVerified", "eq", json!(false), "b d e"),
            ("emailVerified", "eq", json!("true"), "a c f"),
            ("emailVerified", "eq", json!("nonsense"), "b d e"),
            ("emailVerified", "eq", json!(1), "a c f"),
            ("emailVerified", "in", json!([1]), "a c f"),
            ("emailVerified", "in", json!(["true"]), ""),
            ("emailVerified", "in", json!(["1"]), "a c f"),
            ("emailVerified", "contains", json!("true"), "a c f"),
            ("score", "eq", json!(2), "a"),
            ("score", "eq", json!("0x2"), "a"),
            ("score", "in", json!([2, 10]), "a b"),
            ("score", "not_in", json!([2, 10]), "c d e f"),
            ("score", "in", json!(["0x2", "0xa"]), "a b"),
            ("score", "in", json!(["0x2", "invalid"]), ""),
        ] {
            let (users, count) = store
                .list_users(ListUsersParams {
                    filter_field: Some(field.into()),
                    filter_operator: Some(operator.into()),
                    filter_value: Some(serde_json::from_value(raw.clone()).unwrap()),
                    sort_by: Some("id".into()),
                    sort_direction: Some("asc".into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            let ids = users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(ids.join(" "), expected, "{field} {operator} {raw}");
            assert_eq!(count, ids.len());
        }
    }

    const TABLE: &str = "CREATE TABLE filter_user (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
        emailVerified BOOLEAN NOT NULL, image TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL, score REAL NOT NULL)";
    const ROWS: &str = "INSERT INTO filter_user VALUES
        ('a','2','a@example.test',1,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',2),
        ('b','2.0','b@example.test',0,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',10),
        ('c','true','c@example.test',1,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',3),
        ('d','1','d@example.test',0,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',4),
        ('e','0','e@example.test',0,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',5),
        ('f','false','f@example.test',1,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',6)";
}
