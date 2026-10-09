//! Application-owned organization plugin tables. Models derive [`crate::SqlxModel`]
//! and use Rust names for plugin fields, with `sqlx(rename)` for physical names.

use crate::model::{self, ActiveRow, SqlxModel};
use crate::pool::Exec;
use crate::sql::Sql;
use crate::store::entities::{invitation, member, organization};
use crate::value::{ColumnKind, SqlValue};
use alibi_core::Invitation;
use alibi_core::Member;
use alibi_core::Organization;
use alibi_core::field_policy::FieldValues;
use alibi_core::{AuthError, AuthResult};
use async_trait::async_trait;
use std::{marker::PhantomData, sync::Arc};

/// Bind the three organization entities to application models and ID factories.
/// This affects every plugin operation, including invitation transactions.
#[derive(Clone)]
pub struct OrganizationModels {
    pub(crate) organization: Binding<organization::Model>,
    pub(crate) member: Binding<member::Model>,
    pub(crate) invitation: Binding<invitation::Model>,
}

impl OrganizationModels {
    /// Models must declare the plugin's Rust field names. `updated_at` on the
    /// organization and `team_id` on the invitation may be omitted. Additional
    /// organization fields are retained and returned by the plugin.
    #[must_use]
    pub fn new<O: SqlxModel, M: SqlxModel, I: SqlxModel>(
        organization_id: fn() -> String,
        member_id: fn() -> String,
        invitation_id: fn() -> String,
    ) -> Self {
        Self {
            organization: Binding::new::<O>(organization_id),
            member: Binding::new::<M>(member_id),
            invitation: Binding::new::<I>(invitation_id),
        }
    }
}

impl Default for OrganizationModels {
    fn default() -> Self {
        fn id() -> String {
            uuid::Uuid::new_v4().to_string()
        }
        Self::new::<organization::Model, member::Model, invitation::Model>(id, id, id)
    }
}

#[async_trait]
trait Backend: Send + Sync {
    fn table(&self) -> &'static str;
    fn columns(&self) -> &'static [&'static str];
    fn fields(&self) -> &'static [(&'static str, &'static str)];
    fn kind(&self, physical: &str) -> ColumnKind;
    async fn fetch(&self, exec: Exec<'_>, sql: Sql) -> AuthResult<Vec<ActiveRow>>;
    async fn insert(&self, exec: Exec<'_>, row: &ActiveRow) -> AuthResult<ActiveRow>;
    async fn update(&self, exec: Exec<'_>, row: &ActiveRow) -> AuthResult<Option<ActiveRow>>;
}
struct TypedBackend<M>(PhantomData<M>);
#[async_trait]
impl<M: SqlxModel> Backend for TypedBackend<M> {
    fn table(&self) -> &'static str {
        M::TABLE
    }
    fn columns(&self) -> &'static [&'static str] {
        M::COLUMN_NAMES
    }
    fn fields(&self) -> &'static [(&'static str, &'static str)] {
        M::FIELD_COLUMNS
    }
    fn kind(&self, physical: &str) -> ColumnKind {
        M::column_kind(physical)
    }
    async fn fetch(&self, exec: Exec<'_>, sql: Sql) -> AuthResult<Vec<ActiveRow>> {
        Ok(exec
            .fetch_all::<M>(sql)
            .await?
            .into_iter()
            .map(SqlxModel::into_active)
            .collect())
    }
    async fn insert(&self, exec: Exec<'_>, row: &ActiveRow) -> AuthResult<ActiveRow> {
        Ok(model::insert::<M>(exec, row).await?.into_active())
    }
    async fn update(&self, exec: Exec<'_>, row: &ActiveRow) -> AuthResult<Option<ActiveRow>> {
        Ok(model::update::<M>(exec, row)
            .await?
            .map(SqlxModel::into_active))
    }
}

#[derive(Clone)]
pub(crate) struct Binding<T> {
    backend: Arc<dyn Backend>,
    generate_id: fn() -> String,
    _canonical: PhantomData<T>,
}

/// Canonical plugin fields and the original loaded write state. Keeping that
/// state prevents an update from overwriting unrelated application columns.
pub(crate) struct Row<T> {
    value: T,
    active: ActiveRow,
}
impl<T> std::ops::Deref for Row<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> Row<T> {
    pub(crate) fn active_role(&self) -> SqlValue {
        self.active
            .get("role")
            .and_then(crate::ActiveValue::value)
            .cloned()
            .unwrap_or(SqlValue::Text(None))
    }
    pub(crate) fn into_active(self) -> ActiveRow {
        self.active
    }
}

impl<T: SqlxModel> Binding<T> {
    fn new<M: SqlxModel>(generate_id: fn() -> String) -> Self {
        Self {
            backend: Arc::new(TypedBackend::<M>(PhantomData)),
            generate_id,
            _canonical: PhantomData,
        }
    }
    pub(crate) async fn set_fields(
        &self,
        exec: Exec<'_>,
        active: &mut ActiveRow,
        fields: &mut FieldValues,
    ) -> AuthResult<()> {
        fields.apply_adapter_transforms_async().await?;
        for (name, value) in &*fields {
            let requested = fields.binding_name(name);
            let column = self.physical(requested).ok_or_else(|| {
                AuthError::config(format!(
                    "configured organization field {name} has no model column"
                ))
            })?;
            let field = self.logical(column);
            if T::COLUMN_NAMES.contains(&field) {
                return Err(AuthError::config(
                    "additional organization fields cannot overwrite plugin fields",
                ));
            }
            let value = crate::additional_fields::prepare_value(
                exec,
                self.backend.kind(column),
                crate::additional_fields::raw_value(value)?,
            )
            .await?;
            active.set(field, value);
        }
        Ok(())
    }
    pub(crate) fn new_id(&self) -> String {
        (self.generate_id)()
    }
    pub(crate) fn table(&self) -> &'static str {
        self.backend.table()
    }
    pub(crate) fn physical(&self, field: &str) -> Option<&'static str> {
        self.backend
            .fields()
            .iter()
            .find(|(logical, _)| *logical == field)
            .map(|(_, physical)| *physical)
            .or_else(|| {
                self.backend
                    .columns()
                    .iter()
                    .copied()
                    .find(|column| *column == field)
            })
    }
    fn logical(&self, physical: &'static str) -> &'static str {
        self.backend
            .fields()
            .iter()
            .find(|(_, column)| *column == physical)
            .map_or(physical, |(logical, _)| *logical)
    }
    fn value(&self, field: &str, value: SqlValue) -> AuthResult<SqlValue> {
        let column = self.physical(field).ok_or_else(|| {
            AuthError::internal(format!("organization model has no {field} column"))
        })?;
        Ok(match (self.backend.kind(column), value) {
            (ColumnKind::BpChar, SqlValue::Text(value)) => SqlValue::BpChar(value),
            (ColumnKind::NaiveTimestamp, SqlValue::Timestamp(value)) => {
                SqlValue::NaiveTimestamp(value.map(|time| time.naive_utc()))
            }
            (ColumnKind::Text, SqlValue::Json(value)) => SqlValue::Text(
                value
                    .map(|value| alibi_core::utils::json::to_string(&*value))
                    .transpose()?,
            ),
            (_, value) => value,
        })
    }
    fn stage(&self, active: &ActiveRow) -> AuthResult<ActiveRow> {
        let mut physical = ActiveRow::new();
        for (field, value) in active.present() {
            let Some(column) = self.physical(field) else {
                if field == "updated_at" || (field == "team_id" && value.is_null()) {
                    continue;
                }
                return Err(AuthError::internal(format!(
                    "organization model has no {field} column"
                )));
            };
            let value = self.value(field, value.clone())?;
            if active.get(field).is_some_and(crate::ActiveValue::is_set) {
                physical.set(column, value);
            } else {
                physical.unchanged(column, value);
            }
        }
        Ok(physical)
    }
    fn row(&self, physical: ActiveRow) -> AuthResult<Row<T>> {
        let mut active = ActiveRow::new();
        for (column, value) in physical.present() {
            let field = self.logical(column);
            let value = match value.clone() {
                SqlValue::NaiveTimestamp(value) => {
                    SqlValue::Timestamp(value.map(|time| time.and_utc()))
                }
                SqlValue::BpChar(value) => SqlValue::Text(value),
                value => value,
            };
            active.unchanged(field, value);
        }
        let mut canonical = active.clone();
        if T::TABLE == organization::Model::TABLE {
            if self.physical("updated_at").is_none()
                && let Some(time) = active.get("created_at").and_then(crate::ActiveValue::value)
            {
                canonical.unchanged("updated_at", time.clone());
            }
            if canonical
                .get("metadata")
                .and_then(crate::ActiveValue::value)
                .is_some_and(SqlValue::is_null)
            {
                canonical.unchanged("metadata", SqlValue::Json(None));
            }
        }
        if T::TABLE == invitation::Model::TABLE {
            if self.physical("team_id").is_none() {
                canonical.unchanged("team_id", None::<String>);
            }
            // The canonical storage row uses a String. The original nullable
            // value remains in the loaded row for its public representation.
            if canonical
                .get("role")
                .and_then(crate::ActiveValue::value)
                .is_some_and(SqlValue::is_null)
            {
                canonical.unchanged("role", "");
            }
        }
        Ok(Row {
            value: T::from_active(canonical)?,
            active,
        })
    }
    pub(crate) fn select(&self, exec: Exec<'_>) -> Sql {
        crate::sql::select(exec.engine(), self.table(), self.backend.columns())
    }
    pub(crate) fn by_id(&self, exec: Exec<'_>, id: impl Into<SqlValue>) -> AuthResult<Sql> {
        let mut sql = self.select(exec);
        sql.push(" WHERE ");
        self.compare(&mut sql, "id", " = ", id)?;
        Ok(sql)
    }
    pub(crate) fn delete_for_organization(&self, exec: Exec<'_>, id: &str) -> AuthResult<Sql> {
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident(self.table());
        sql.push(" WHERE ");
        self.compare(&mut sql, "organization_id", " = ", id)?;
        Ok(sql)
    }
    pub(crate) fn delete_by_id(&self, exec: Exec<'_>, id: impl Into<SqlValue>) -> AuthResult<Sql> {
        let mut sql = Sql::with(exec.engine(), "DELETE FROM ");
        sql.ident(self.table());
        sql.push(" WHERE ");
        self.compare(&mut sql, "id", " = ", id)?;
        Ok(sql)
    }
    pub(crate) fn column(&self, sql: &mut Sql, field: &str) -> AuthResult<()> {
        let column = self.physical(field).ok_or_else(|| {
            AuthError::internal(format!("organization model has no {field} column"))
        })?;
        sql.column(self.table(), column);
        Ok(())
    }
    pub(crate) fn compare(
        &self,
        sql: &mut Sql,
        field: &str,
        operator: &str,
        value: impl Into<SqlValue>,
    ) -> AuthResult<()> {
        self.column(sql, field)?;
        sql.push(operator);
        sql.bind(self.value(field, value.into())?);
        Ok(())
    }
    pub(crate) fn assign(
        &self,
        sql: &mut Sql,
        field: &str,
        value: impl Into<SqlValue>,
    ) -> AuthResult<()> {
        let column = self.physical(field).ok_or_else(|| {
            AuthError::internal(format!("organization model has no {field} column"))
        })?;
        sql.assign(column, self.value(field, value.into())?);
        Ok(())
    }
    pub(crate) fn bind_list<I: IntoIterator<Item = String>>(
        &self,
        sql: &mut Sql,
        field: &str,
        values: I,
    ) -> AuthResult<()> {
        sql.bind_list(
            values
                .into_iter()
                .map(|value| self.value(field, value.into()))
                .collect::<AuthResult<Vec<_>>>()?,
        );
        Ok(())
    }
    pub(crate) fn returning(&self, sql: &mut Sql) {
        sql.push(" RETURNING ");
        sql.column_list(self.backend.columns());
    }
    pub(crate) async fn fetch_all(&self, exec: Exec<'_>, sql: Sql) -> AuthResult<Vec<Row<T>>> {
        self.backend
            .fetch(exec, sql)
            .await?
            .into_iter()
            .map(|active| self.row(active))
            .collect()
    }
    pub(crate) async fn fetch_optional(
        &self,
        exec: Exec<'_>,
        sql: Sql,
    ) -> AuthResult<Option<Row<T>>> {
        Ok(self.fetch_all(exec, sql).await?.into_iter().next())
    }
    pub(crate) async fn insert(&self, exec: Exec<'_>, active: &ActiveRow) -> AuthResult<Row<T>> {
        self.row(self.backend.insert(exec, &self.stage(active)?).await?)
    }
    pub(crate) async fn update(
        &self,
        exec: Exec<'_>,
        active: &ActiveRow,
    ) -> AuthResult<Option<Row<T>>> {
        self.backend
            .update(exec, &self.stage(active)?)
            .await?
            .map(|active| self.row(active))
            .transpose()
    }
}

impl From<&Row<organization::Model>> for Organization {
    fn from(row: &Row<organization::Model>) -> Self {
        let mut organization = Self::from(&row.value);
        for (field, value) in row.active.present() {
            if organization::Model::COLUMN_NAMES.contains(&field) {
                continue;
            }
            if let Some(value) = output_value(value) {
                _ = organization
                    .additional_fields
                    .insert(field.to_owned(), value);
            }
        }
        organization
    }
}
impl From<&Row<member::Model>> for Member {
    fn from(row: &Row<member::Model>) -> Self {
        Self::from(&row.value)
    }
}
impl From<&Row<invitation::Model>> for Invitation {
    fn from(row: &Row<invitation::Model>) -> Self {
        let mut invitation = Self::from(&row.value);
        if row
            .active
            .get("role")
            .and_then(crate::ActiveValue::value)
            .is_some_and(SqlValue::is_null)
        {
            invitation.role = None;
        }
        invitation
    }
}

fn output_value(value: &SqlValue) -> Option<serde_json::Value> {
    if value.is_null() {
        return Some(serde_json::Value::Null);
    }
    match value {
        SqlValue::Text(Some(value)) | SqlValue::BpChar(Some(value)) => Some(value.clone().into()),
        SqlValue::Bool(Some(value)) => Some((*value).into()),
        SqlValue::Int(Some(value)) => Some((*value).into()),
        SqlValue::BigInt(Some(value)) => Some((*value).into()),
        SqlValue::Float(Some(value)) => {
            serde_json::Number::from_f64(f64::from(*value)).map(Into::into)
        }
        SqlValue::Double(Some(value)) => serde_json::Number::from_f64(*value).map(Into::into),
        SqlValue::Json(Some(value)) => Some((**value).clone()),
        _ => None,
    }
}
