use super::{ScopedTransaction, SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmUserModel};
use alibi_core::AuthUser;
use alibi_core::UserFilterValue;
use alibi_core::error::{AuthError, AuthResult};
use alibi_core::store::adapter::cancelled_by_hook;
use alibi_core::store::{NumericTextInput, UserCreationDefaults, UserStore};
use alibi_core::types::{CreateUser, ListUsersParams, UpdateUser};
use alibi_core::user_validation::PreparedUserCreation;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait,
};

// Only the typed Rust view is bounded to SQLite's printable date range.
// The retained adapter output always reads the original numeric DATE value.
const SQLITE_TYPED_DATE: &str = "CASE WHEN typeof(?) IN ('integer', 'real') THEN strftime('%Y-%m-%dT%H:%M:%fZ', CASE WHEN ? < -8640000000000000 OR ? > 253402300799999 THEN 253402300799999 WHEN ? < -62135596800000 THEN -62135596800000 ELSE CAST(? AS INTEGER) END / 1000.0, 'unixepoch') ELSE CASE WHEN ? IS NULL THEN NULL ELSE COALESCE(strftime('%Y-%m-%dT%H:%M:%fZ', ?), '1970-01-01T00:00:00.000Z') END END";

fn sqlite_date_column<C: sea_orm::Iden + Copy + 'static>(
    column: C,
) -> sea_orm::sea_query::SimpleExpr {
    Expr::cust_with_exprs(
        SQLITE_TYPED_DATE,
        std::iter::repeat_with(|| Expr::col(column)).take(7),
    )
}

pub(super) fn user_query<M: SeaOrmUserModel>(
    backend: sea_orm::DbBackend,
) -> sea_orm::Select<M::Entity> {
    use sea_orm::Iterable;
    let query = M::Entity::find();
    if backend != sea_orm::DbBackend::Sqlite {
        return query;
    }

    let mut query = query.select_only();
    for column in <M::Entity as EntityTrait>::Column::iter() {
        if matches!(
            column.def().get_column_type(),
            sea_orm::sea_query::ColumnType::Boolean
        ) {
            query = query.column_as(Expr::cust_with_exprs(
                "CASE WHEN typeof(?) IN ('integer', 'real') THEN ? = 1 WHEN ? IS NULL THEN NULL ELSE ? <> '' END",
                [Expr::col(column), Expr::col(column), Expr::col(column), Expr::col(column)],
            ),column);
        } else if matches!(
            column.def().get_column_type(),
            sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                | sea_orm::sea_query::ColumnType::Timestamp
                | sea_orm::sea_query::ColumnType::DateTime
        ) {
            query = query.column_as(sqlite_date_column(column), column);
        } else {
            query = query.column(column);
        }
    }
    query
}

pub(super) async fn native_user_output<M: SeaOrmUserModel, C: ConnectionTrait>(
    db: &C,
    id: &str,
) -> AuthResult<std::collections::BTreeMap<String, alibi_core::utils::json::JsValue>> {
    use sea_orm::EntityName;
    use sea_orm::sea_query::{Alias, Query};
    let mut output = std::collections::BTreeMap::new();
    if db.get_database_backend() != sea_orm::DbBackend::Sqlite {
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
        let expression = if date {
            Expr::cust_with_exprs("json_quote(?)", [Expr::col(column)])
        } else {
            Expr::cust_with_exprs(
                "CASE typeof(?) WHEN 'text' THEN json_quote(?) WHEN 'null' THEN 'null' ELSE CASE WHEN ? = 1 THEN 'true' ELSE 'false' END END",
                [Expr::col(column), Expr::col(column), Expr::col(column)],
            )
        };
        let query = Query::select()
            .expr_as(expression, Alias::new("native_scalar"))
            .from(M::Entity::default().table_ref())
            .and_where(M::id_column().eq(M::parse_id(id)?))
            .to_owned();
        if let Some(row) = db
            .query_one_raw(db.get_database_backend().build(&query))
            .await
            .map_err(map_db_err)?
        {
            let value: String = row.try_get("", "native_scalar").map_err(map_db_err)?;
            let mut value = alibi_core::utils::json::parse_value(&value)?;
            if date && let Some(text) = value.as_str() {
                value = alibi_core::utils::datetime::parse_date_millis(text)
                    .map(alibi_core::utils::datetime::json_date_millis)
                    .map_or(alibi_core::utils::json::JsValue::Null, |value| {
                        alibi_core::utils::json::JsValue::String(value.into())
                    });
            }
            _ = output.insert(field.to_owned(), value);
        }
    }
    Ok(output)
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
    verification: Option<alibi_core::utils::json::JsValue>,
    id: Option<&str>,
    native_fields: std::collections::BTreeMap<String, alibi_core::utils::json::JsValue>,
) -> AuthResult<M> {
    use sea_orm::sea_query::Query;
    use sea_orm::{ActiveModelBehavior, ActiveValue, EntityName, Iden, Iterable};
    let insert = id.is_none();
    let verification = verification.filter(|value| !value.is_undefined());
    let verification =
        verification.filter(|value| !value.is_boolean() && (!insert || !value.is_null()));
    if verification.is_none()
        && native_fields.is_empty()
        && (insert || db.get_database_backend() != sea_orm::DbBackend::Sqlite)
    {
        return if insert {
            model.insert(db).await.map_err(map_db_err)
        } else {
            model.update(db).await.map_err(map_db_err)
        };
    };
    let mut native_values = Vec::new();
    for (field, raw) in native_fields
        .into_iter()
        .chain(verification.map(|raw| ("emailVerified".to_owned(), raw)))
    {
        if raw.is_undefined() {
            continue;
        }
        let Some(column) = M::list_users_column(&field) else {
            continue;
        };
        if field == "id" && !alibi_core::utils::json::JsValue::from(raw.clone()).is_truthy() {
            continue;
        }
        if (raw.is_object() || raw.is_array())
            && !matches!(
                column.def().get_column_type(),
                sea_orm::sea_query::ColumnType::Json | sea_orm::sea_query::ColumnType::JsonBinary
            )
        {
            return Err(AuthError::internal("Unsupported native user SQL parameter"));
        }
        let raw =
            crate::additional_fields::raw_value(&alibi_core::utils::json::JsValue::from(raw))?;
        let value = if matches!(
            column.def().get_column_type(),
            sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                | sea_orm::sea_query::ColumnType::Timestamp
                | sea_orm::sea_query::ColumnType::DateTime
        ) {
            match crate::additional_fields::bind_scalar(raw)? {
                sea_orm::Value::String(Some(value))
                    if db.get_database_backend() == sea_orm::DbBackend::Sqlite =>
                {
                    sea_orm::Value::String(Some(value))
                }
                sea_orm::Value::String(Some(value)) => chrono::DateTime::parse_from_rfc3339(&value)
                    .map(|date| sea_orm::Value::ChronoDateTimeUtc(Some(date.with_timezone(&Utc))))
                    .map_err(|error| AuthError::internal(error.to_string()))?,
                sea_orm::Value::String(None) => sea_orm::Value::ChronoDateTimeUtc(None),
                raw => raw,
            }
        } else {
            crate::additional_fields::prepare_value(db, &column, raw).await?
        };
        native_values.push((column, value));
    }
    model = ActiveModelBehavior::before_save(model, db, insert)
        .await
        .map_err(map_db_err)?;
    let mut columns = Vec::new();
    let mut values = Vec::new();
    let mut returning = Vec::new();
    for physical in <M::Entity as EntityTrait>::Column::iter() {
        let native = native_values
            .iter()
            .find(|(column, _)| physical.to_string() == column.to_string());
        let boolean_column = matches!(
            physical.def().get_column_type(),
            sea_orm::sea_query::ColumnType::Boolean
        );
        let staged = match model.take(physical) {
            ActiveValue::Set(original) => Some(original),
            ActiveValue::Unchanged(original) if insert => Some(original),
            _ => None,
        };
        if let Some(original) = native.map(|(_, value)| value.clone()).or(staged) {
            columns.push(physical);
            let expression = Expr::val(original);
            let expression = if boolean_column
                && native.is_some()
                && db.get_database_backend() == sea_orm::DbBackend::Postgres
            {
                expression.cast_as(sea_orm::sea_query::Alias::new("boolean"))
            } else {
                expression
            };
            values.push(physical.save_as(expression));
        }
        returning.push(if boolean_column && db.get_database_backend() == sea_orm::DbBackend::Sqlite {
            Expr::cust_with_exprs("CASE WHEN typeof(?) IN ('integer', 'real') THEN ? = 1 WHEN ? IS NULL THEN NULL ELSE ? <> '' END AS ?",[Expr::col(physical),Expr::col(physical),Expr::col(physical),Expr::col(physical),Expr::col(physical)])
        } else if db.get_database_backend() == sea_orm::DbBackend::Sqlite && matches!(physical.def().get_column_type(), sea_orm::sea_query::ColumnType::TimestampWithTimeZone | sea_orm::sea_query::ColumnType::Timestamp | sea_orm::sea_query::ColumnType::DateTime) {
            Expr::cust_with_exprs("? AS ?", [sqlite_date_column(physical), Expr::col(physical)])
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
    name: Option<alibi_core::utils::json::JsValue>,
    image: Option<alibi_core::utils::json::JsValue>,
    email: Option<alibi_core::utils::json::JsValue>,
) -> AuthResult<()> {
    for (field, raw) in [("name", name), ("image", image), ("email", email)] {
        let Some(raw) = raw.filter(|value| !value.is_undefined()) else {
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
        defaults: UserCreationDefaults,
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
        let now = Utc::now();
        if create_user.id.as_deref() == Some("") {
            _ = create_user
                .adapter_native_fields
                .insert("id".into(), serde_json::json!("").into());
            create_user.id = None;
        }
        if create_user
            .adapter_native_fields
            .get("id")
            .is_some_and(alibi_core::utils::json::JsValue::is_null)
        {
            _ = create_user.adapter_native_fields.remove("id");
        }
        if create_user.id.is_none() && !create_user.adapter_native_fields.contains_key("id") {
            create_user.id = self
                .generated_entity_id::<<S::User as SeaOrmUserModel>::Entity, _>(
                    db,
                    "user",
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
        let verification = create_user.provider_email_verified.take();
        let native_fields = std::mem::take(&mut create_user.adapter_native_fields);
        if let Some(raw_id) = native_fields.get("id") {
            _ = create_user
                .adapter_native_fields
                .insert("id".into(), raw_id.clone());
        }
        let mut model = S::User::new_active(user_id, create_user, now);
        stage_provider_text::<S::User, _>(
            db,
            &mut model,
            provider_name,
            provider_image,
            provider_email,
        )
        .await?;
        let backend = db.get_database_backend();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(db, &column, value).await?;
            S::User::set_additional_field(&mut model, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut model, db.get_database_backend())?;

        let user =
            save_provider_user::<S::User, _>(model, db, verification, None, native_fields).await?;
        if tx.is_none() {
            for hook in self.hooks() {
                hook.after_create_user(&user, &hook_context).await?;
            }
        }
        Ok(user)
    }

    /// The condition for an admin user-list filter the shared projection cannot evaluate.
    fn user_filter(
        &self,
        filter_field: Option<&str>,
        operator: &str,
        value: &UserFilterValue,
    ) -> AuthResult<Expr> {
        let field = filter_field
            .filter(|field| !field.is_empty())
            .unwrap_or("email");
        let column = S::User::list_users_column(field)
            .ok_or_else(|| AuthError::bad_request("User filter field has no configured column"))?;
        let native = value.native();
        if operator == "in" && !matches!(native, alibi_core::utils::json::JsValue::Array(_)) {
            return Err(AuthError::bad_request("Value must be an array"));
        }
        use sea_orm::sea_query::ColumnType;
        let column_type = column.def();
        let column_type = column_type.get_column_type();
        let numeric = matches!(
            column_type,
            ColumnType::Integer | ColumnType::BigInteger | ColumnType::Float | ColumnType::Double
        );
        let native = transform_filter_operand(
            native,
            matches!(column_type, ColumnType::Boolean),
            numeric,
            self.scoped_connection().get_database_backend() == sea_orm::DbBackend::Postgres,
        );
        let pattern = native
            .coerce_js_string()
            .map_err(AuthError::internal)?
            .to_utf8_binding();
        let operands = match native {
            alibi_core::utils::json::JsValue::Array(values) => values,
            value => vec![value],
        };
        let numeric_cast =
            if self.scoped_connection().get_database_backend() == sea_orm::DbBackend::Postgres {
                match column_type {
                    ColumnType::Boolean => Some("boolean"),
                    ColumnType::Integer => Some("int4"),
                    ColumnType::BigInteger => Some("int8"),
                    ColumnType::Float => Some("float4"),
                    ColumnType::Double => Some("float8"),
                    _ => None,
                }
            } else {
                None
            };
        let bindings: Vec<sea_orm::Value> = operands
            .into_iter()
            .map(|value| {
                use alibi_core::utils::json::JsValue;
                // node-postgres sends primitives as text with the SQL column's inferred type.
                Ok(
                    if self.scoped_connection().get_database_backend()
                        == sea_orm::DbBackend::Postgres
                        && (numeric_cast.is_some()
                            || matches!(
                                column_type,
                                ColumnType::String(_) | ColumnType::Text | ColumnType::Char(_)
                            ))
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
                            _ => {
                                return Err(AuthError::bad_request(
                                    "Unsupported user filter operand",
                                ));
                            }
                        }
                    },
                )
            })
            .collect::<AuthResult<_>>()?;
        let bound = |value: &sea_orm::Value| match numeric_cast
            .filter(|_| matches!(value, sea_orm::Value::String(_)))
        {
            Some(cast) => Expr::cust_with_values(format!("$1::{cast}"), [value.clone()]),
            None => column.save_as(Expr::val(value.clone())),
        };
        let tuple = || Expr::tuple(bindings.iter().map(bound));
        Ok(match operator {
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
                let values = bindings.iter().map(bound);
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
            "contains" => column.like(format!("%{pattern}%")),
            "starts_with" => column.like(format!("{pattern}%")),
            "ends_with" => column.like(format!("%{pattern}")),
            "eq" => Expr::col(column).eq(tuple()),
            "ne" => Expr::col(column).ne(tuple()),
            "lt" => Expr::col(column).lt(tuple()),
            "lte" => Expr::col(column).lte(tuple()),
            "gt" => Expr::col(column).gt(tuple()),
            "gte" => Expr::col(column).gte(tuple()),
            _ => return Err(AuthError::bad_request("Unsupported user filter operator")),
        })
    }

    pub(crate) async fn create_user_in_tx(
        &self,
        tx: &ScopedTransaction,
        mut create_user: CreateUser,
    ) -> AuthResult<S::User> {
        create_user.email = create_user.email.map(|email| normalize_user_email(&email));
        self.create_user_with_connection(tx, Some(tx), create_user, UserCreationDefaults::default())
            .await
    }

    pub(crate) async fn create_user_prepared_in_tx(
        &self,
        tx: &ScopedTransaction,
        prepared: PreparedUserCreation,
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
    fn supports_native_json(&self) -> bool {
        self.db.get_database_backend() != sea_orm::DbBackend::Sqlite
    }

    async fn native_user_output(
        &self,
        id: &str,
    ) -> AuthResult<std::collections::BTreeMap<String, alibi_core::utils::json::JsValue>> {
        native_user_output::<S::User, _>(self.scoped_connection(), id).await
    }

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
            UserCreationDefaults::default(),
        )
        .await
    }

    async fn create_user_prepared(&self, prepared: PreparedUserCreation) -> AuthResult<S::User> {
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
        // The database's own CAST decides the stored text.
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
        let backend = self.scoped_connection().get_database_backend();
        let query = user_query::<S::User>(backend)
            .filter(<S::User as SeaOrmUserModel>::id_column().is_in(user_ids));
        let statement = super::bind_page(query.build(backend), Some(limit), None)?;
        user_query::<S::User>(backend)
            .from_raw_sql(statement)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)
    }

    async fn get_user_by_email(
        &self,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        self.get_user_by_email_with_connection(self.scoped_connection(), email)
            .await
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

    async fn get_user_by_username_value(
        &self,
        username: &alibi_core::utils::json::JsValue,
    ) -> AuthResult<Option<S::User>> {
        self.get_user_by_username_value_with_connection(self.scoped_connection(), username)
            .await
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

    async fn update_user(&self, id: &str, update: UpdateUser) -> AuthResult<S::User> {
        self.update_user_with_connection(self.scoped_connection(), None, id, update)
            .await
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
        let transaction = self.scoped_connection().begin_immediate().await?;
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

    async fn list_users(&self, params: ListUsersParams) -> AuthResult<(Vec<S::User>, usize)> {
        let backend = self.scoped_connection().get_database_backend();
        let mut query = user_query::<S::User>(backend);
        if let Some(search) = params
            .search_value
            .as_ref()
            .filter(|search| !search.is_empty())
        {
            query = query.filter(self.user_filter(
                params.search_field.as_deref(),
                params.search_operator.as_deref().unwrap_or("contains"),
                &UserFilterValue::Scalar(search.clone()),
            )?);
        }
        if let Some(value) = &params.filter_value {
            query = query.filter(self.user_filter(
                params.filter_field.as_deref(),
                params.filter_operator.as_deref().unwrap_or("eq"),
                value,
            )?);
        }
        let count = query.clone();
        if let Some(field) = params.sort_by.as_deref().filter(|field| !field.is_empty()) {
            let column = S::User::list_users_column(field).ok_or_else(|| {
                AuthError::bad_request("User sort field has no configured column")
            })?;
            let direction = params.sort_direction.as_deref().unwrap_or("asc");
            query = if direction == "desc" {
                query.order_by_desc(column)
            } else {
                query.order_by_asc(column)
            };
        }
        let number = |value: usize| value.to_string().parse::<f64>().ok();
        let limit = params
            .source_limit
            .or_else(|| params.limit.and_then(number))
            .or_else(|| number(self.config().advanced.database.default_find_many_limit));
        let offset = params
            .source_offset
            .or_else(|| params.offset.and_then(number));
        let statement = super::bind_page(query.build(backend), limit, offset)?;
        let users = <S::User as SeaOrmUserModel>::Entity::find()
            .from_raw_sql(statement)
            .all(self.scoped_connection())
            .await
            .map_err(map_db_err)?;
        let total = usize::try_from(
            count
                .count(self.scoped_connection())
                .await
                .map_err(map_db_err)?,
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

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: crate::schema::SeaOrmUserModel,
{
    pub(super) async fn update_user_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        tx: Option<&ScopedTransaction>,
        id: &str,
        mut update: UpdateUser,
    ) -> AuthResult<S::User> {
        update.email = update.email.map(|email| normalize_user_email(&email));
        let user_id = S::User::parse_id(id)?;
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
        let Some(model) = user_query::<S::User>(connection.get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::id_column().eq(user_id))
            .one(connection)
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
        let provider_email = update.provider_email.take();
        let verification = update.provider_email_verified.take();
        let native_fields = std::mem::take(&mut update.adapter_native_fields);
        if native_fields.keys().any(|field| {
            !matches!(
                field.as_str(),
                "banExpires" | "username" | "displayUsername"
            )
        }) {
            return Err(AuthError::internal("Unsupported native user update field"));
        }
        S::User::apply_update(&mut active, update, Utc::now());
        stage_provider_text::<S::User, _>(
            connection,
            &mut active,
            provider_name,
            provider_image,
            provider_email,
        )
        .await?;
        let backend = connection.get_database_backend();
        for (column, value) in S::User::additional_field_bindings(&fields, backend)? {
            let value = crate::additional_fields::prepare_value(connection, &column, value).await?;
            S::User::set_additional_field(&mut active, column, value, backend)?;
        }
        S::User::prepare_json_metadata(&mut active, connection.get_database_backend())?;

        let user = save_provider_user::<S::User, _>(
            active,
            connection,
            verification,
            Some(id),
            native_fields,
        )
        .await?;
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

impl<S> SeaOrmStore<S>
where
    S: AuthSchema,
    S::User: crate::schema::SeaOrmUserModel,
{
    pub(super) async fn get_user_by_username_value_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
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
        let value =
            crate::additional_fields::bind_scalar(crate::additional_fields::raw_value(username)?)?;
        user_query::<S::User>(connection.get_database_backend())
            .filter(column.eq(value))
            .one(connection)
            .await
            .map_err(map_db_err)
    }

    pub(super) async fn get_user_by_email_with_connection<C: ConnectionTrait>(
        &self,
        connection: &C,
        email: &alibi_core::utils::json::JsString,
    ) -> AuthResult<Option<S::User>> {
        let email = normalize_user_email(&email.to_utf8_binding());
        user_query::<S::User>(connection.get_database_backend())
            .filter(<S::User as SeaOrmUserModel>::email_column().eq(email))
            .one(connection)
            .await
            .map_err(map_db_err)
    }
}

#[cfg(test)]
mod typed_filter_tests {
    use super::*;
    use sea_orm::entity::prelude::*;
    use serde_json::json;

    #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, crate::AuthEntity)]
    #[sea_orm(table_name = "filter_user")]
    #[auth(role = "user")]
    pub(super) struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub name: String,
        pub email: String,
        #[sea_orm(column_name = "emailVerified")]
        pub email_verified: bool,
        pub image: Option<String>,
        #[sea_orm(column_name = "createdAt")]
        pub created_at: chrono::DateTime<Utc>,
        #[sea_orm(column_name = "updatedAt")]
        pub updated_at: chrono::DateTime<Utc>,
        pub score: f64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub(super) enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
    struct FilterSchema;
    impl AuthSchema for FilterSchema {
        type User = Model;
        type Session = super::super::entities::session::Model;
        type Account = super::super::entities::account::Model;
        type Verification = super::super::entities::verification::Model;
    }

    #[tokio::test]
    async fn typed_user_filter_sqlite_bound_affinity() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        _ = db.execute_unprepared(TABLE).await.unwrap();
        _ = db.execute_unprepared(ROWS).await.unwrap();
        let store = SeaOrmStore::<FilterSchema>::new(alibi_core::AuthConfig::default(), db);

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

    #[tokio::test]
    async fn optional_user_sort_sqlite_preserves_natural_order() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        _ = db.execute_unprepared(TABLE).await.unwrap();
        _ = db.execute_unprepared(ORDER_ROWS).await.unwrap();
        let store = SeaOrmStore::<FilterSchema>::new(alibi_core::AuthConfig::default(), db);

        let params = ListUsersParams {
            search_value: Some("@example.test".into()),
            filter_field: Some("emailVerified".into()),
            filter_value: Some("true".into()),
            ..Default::default()
        };
        for sort_by in [None, Some("")] {
            for sort_direction in [None, Some("asc"), Some("desc")] {
                let query = ListUsersParams {
                    sort_by: sort_by.map(str::to_owned),
                    sort_direction: sort_direction.map(str::to_owned),
                    ..params.clone()
                };
                let (users, count) = store.list_users(query.clone()).await.unwrap();
                let ids = users
                    .iter()
                    .map(|user| user.id.as_str())
                    .collect::<Vec<_>>();
                // This SQLite fixture's natural scan order is not a cross-backend contract.
                assert_eq!(ids, ["b", "c", "a"], "{sort_by:?} {sort_direction:?}");
                assert_eq!(count, 3);
                for (offset, limit, expected) in
                    [(0, 2, "b c"), (1, 1, "c"), (2, 2, "a"), (3, 1, "")]
                {
                    let (page, total) = store
                        .list_users(ListUsersParams {
                            offset: Some(offset),
                            limit: Some(limit),
                            ..query.clone()
                        })
                        .await
                        .unwrap();
                    let ids = page.iter().map(|user| user.id.as_str()).collect::<Vec<_>>();
                    assert_eq!(ids.join(" "), expected);
                    assert_eq!(total, 3);
                }
            }
        }
        for (direction, expected) in [
            (None, "c b a"),
            (Some("asc"), "c b a"),
            (Some("desc"), "a b c"),
        ] {
            let (users, count) = store
                .list_users(ListUsersParams {
                    sort_by: Some("createdAt".into()),
                    sort_direction: direction.map(str::to_owned),
                    ..params.clone()
                })
                .await
                .unwrap();
            let ids = users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<Vec<_>>();
            assert_eq!(ids.join(" "), expected, "{direction:?}");
            assert_eq!(count, 3);
        }
    }

    const ORDER_ROWS: &str = "INSERT INTO filter_user VALUES
        ('b','middle','b@example.test',1,NULL,'2020-01-02T00:00:00Z','2020-01-02T00:00:00Z',2),
        ('c','oldest','c@example.test',1,NULL,'2020-01-01T00:00:00Z','2020-01-01T00:00:00Z',1),
        ('a','newest','a@example.test',1,NULL,'2020-01-03T00:00:00Z','2020-01-03T00:00:00Z',3),
        ('d','excluded','d@example.test',0,NULL,'2020-01-04T00:00:00Z','2020-01-04T00:00:00Z',4)";

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
