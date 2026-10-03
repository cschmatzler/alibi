//! Column-level write staging for `SQLx` models.
//!
//! An [`ActiveRow`] records, per physical column, whether a write sets it,
//! leaves a loaded value unchanged, or omits it. Inserts write every present
//! column; updates write only set columns, so concurrent changes to other
//! columns survive. Both return the stored row.

use crate::error::record_not_inserted;
use crate::pool::{Exec, SqlxRow};
use crate::sql::{Sql, select};
use crate::value::{ColumnKind, SqlValue};
use better_auth_core::error::{AuthError, AuthResult};

/// One column's write state.
#[derive(Clone, Debug, PartialEq)]
pub enum ActiveValue {
    /// Written by the next insert or update.
    Set(SqlValue),
    /// Loaded from the database and not written by an update.
    Unchanged(SqlValue),
    /// Omitted, so the database default applies on insert.
    NotSet,
}

impl ActiveValue {
    #[must_use]
    pub const fn is_set(&self) -> bool {
        matches!(self, Self::Set(_))
    }

    #[must_use]
    pub const fn is_not_set(&self) -> bool {
        matches!(self, Self::NotSet)
    }

    /// The staged or loaded value.
    #[must_use]
    pub const fn value(&self) -> Option<&SqlValue> {
        match self {
            Self::Set(value) | Self::Unchanged(value) => Some(value),
            Self::NotSet => None,
        }
    }

    #[must_use]
    pub fn into_value(self) -> Option<SqlValue> {
        match self {
            Self::Set(value) | Self::Unchanged(value) => Some(value),
            Self::NotSet => None,
        }
    }
}

/// Per-column write state of one model row, in model column order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ActiveRow {
    columns: Vec<(&'static str, ActiveValue)>,
}

impl ActiveRow {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            columns: Vec::new(),
        }
    }

    fn slot(&mut self, column: &'static str) -> &mut ActiveValue {
        let index = self
            .columns
            .iter()
            .position(|(name, _)| *name == column)
            .unwrap_or_else(|| {
                self.columns.push((column, ActiveValue::NotSet));
                self.columns.len() - 1
            });
        // The index was found or pushed above.
        #[expect(
            clippy::indexing_slicing,
            reason = "the slot index was located or appended immediately above"
        )]
        &mut self.columns[index].1
    }

    /// Stage a written value.
    pub fn set(&mut self, column: &'static str, value: impl Into<SqlValue>) {
        *self.slot(column) = ActiveValue::Set(value.into());
    }

    /// Record a loaded value which an update leaves unchanged.
    pub fn unchanged(&mut self, column: &'static str, value: impl Into<SqlValue>) {
        *self.slot(column) = ActiveValue::Unchanged(value.into());
    }

    /// Declare a column omitted from inserts.
    pub fn not_set(&mut self, column: &'static str) {
        *self.slot(column) = ActiveValue::NotSet;
    }

    #[must_use]
    pub fn get(&self, column: &str) -> Option<&ActiveValue> {
        self.columns
            .iter()
            .find(|(name, _)| *name == column)
            .map(|(_, value)| value)
    }

    /// Remove a column's state, leaving it omitted.
    pub fn take(&mut self, column: &str) -> ActiveValue {
        self.columns
            .iter_mut()
            .find(|(name, _)| *name == column)
            .map_or(ActiveValue::NotSet, |(_, value)| {
                std::mem::replace(value, ActiveValue::NotSet)
            })
    }

    pub(crate) fn present(&self) -> impl Iterator<Item = (&'static str, &SqlValue)> {
        self.columns
            .iter()
            .filter_map(|(name, value)| value.value().map(|value| (*name, value)))
    }

    pub(crate) fn changed(&self) -> impl Iterator<Item = (&'static str, &SqlValue)> {
        self.columns.iter().filter_map(|(name, value)| match value {
            ActiveValue::Set(value) => Some((*name, value)),
            ActiveValue::Unchanged(_) | ActiveValue::NotSet => None,
        })
    }
}

/// A physical model column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnDef {
    pub name: &'static str,
    pub kind: ColumnKind,
}

/// A table-backed `SQLx` model.
pub trait SqlxModel: SqlxRow + Clone + Send + Sync + 'static {
    /// Physical table name.
    const TABLE: &'static str;
    /// Physical columns in model field order.
    const COLUMNS: &'static [ColumnDef];
    /// The names of [`COLUMNS`](Self::COLUMNS), for select and returning lists.
    const COLUMN_NAMES: &'static [&'static str];
    /// Physical primary-key column.
    const PRIMARY_KEY: &'static str;

    /// Every column as an unchanged value.
    fn into_active(self) -> ActiveRow;

    /// Materialize a model without a database write. Omitted optional fields
    /// become `None`; other omitted fields fail.
    ///
    /// # Errors
    ///
    /// Returns an error if a required field is omitted or has another type.
    fn from_active(active: ActiveRow) -> AuthResult<Self>;

    #[must_use]
    fn column_kind(column: &str) -> ColumnKind {
        Self::COLUMNS
            .iter()
            .find(|definition| definition.name == column)
            .map_or(ColumnKind::Other, |definition| definition.kind)
    }
}

pub(crate) fn select_model<M: SqlxModel>(exec: Exec<'_>) -> Sql {
    select(exec.engine(), M::TABLE, M::COLUMN_NAMES)
}

pub(crate) fn returning<M: SqlxModel>(sql: &mut Sql) {
    sql.push(" RETURNING ");
    sql.column_list(M::COLUMN_NAMES);
}

/// `INSERT ... RETURNING` every present column.
pub(crate) async fn insert<M: SqlxModel>(exec: Exec<'_>, active: &ActiveRow) -> AuthResult<M> {
    let mut sql = Sql::new(exec.engine());
    sql.push("INSERT INTO ");
    sql.ident(M::TABLE);
    sql.push(" (");
    let present = active.present().collect::<Vec<_>>();
    sql.column_list(&present.iter().map(|(name, _)| *name).collect::<Vec<_>>());
    sql.push(") VALUES ");
    sql.bind_list(present.into_iter().map(|(_, value)| value.clone()));
    returning::<M>(&mut sql);
    exec.fetch_optional::<M>(sql)
        .await?
        .ok_or_else(record_not_inserted)
}

/// `UPDATE ... RETURNING` the set columns of the row with this primary key.
/// `None` means no row matched.
pub(crate) async fn update<M: SqlxModel>(
    exec: Exec<'_>,
    active: &ActiveRow,
) -> AuthResult<Option<M>> {
    let key = active
        .get(M::PRIMARY_KEY)
        .and_then(ActiveValue::value)
        .cloned()
        .ok_or_else(|| AuthError::internal("model update requires its primary key"))?;
    if active.changed().next().is_none() {
        // Nothing to write: return the stored row, as an unchanged model update does.
        let mut sql = select_model::<M>(exec);
        sql.push(" WHERE ");
        sql.compare(M::TABLE, M::PRIMARY_KEY, " = ", key);
        sql.push(" LIMIT 1");
        return exec.fetch_optional::<M>(sql).await;
    }
    let mut sql = Sql::new(exec.engine());
    sql.push("UPDATE ");
    sql.ident(M::TABLE);
    sql.push(" SET ");
    for (index, (column, value)) in active.changed().enumerate() {
        if index > 0 {
            sql.push(", ");
        }
        sql.assign(column, value.clone());
    }
    sql.push(" WHERE ");
    sql.compare(M::TABLE, M::PRIMARY_KEY, " = ", key);
    returning::<M>(&mut sql);
    exec.fetch_optional::<M>(sql).await
}

/// `SELECT ... WHERE "t"."pk" = ? LIMIT 1`, optionally scoped by one more column.
pub(crate) fn by_id<M: SqlxModel>(exec: Exec<'_>, id: impl Into<SqlValue>) -> Sql {
    let mut sql = select_model::<M>(exec);
    sql.push(" WHERE ");
    sql.compare(M::TABLE, M::PRIMARY_KEY, " = ", id);
    sql
}

/// Append ` LIMIT 1`, as a single-row model lookup does.
pub(crate) fn limit_one(sql: &mut Sql) {
    sql.push(" LIMIT 1");
}

/// `DELETE FROM "t" WHERE "t"."pk" = ?`.
pub(crate) fn delete_by_id<M: SqlxModel>(exec: Exec<'_>, id: impl Into<SqlValue>) -> Sql {
    let mut sql = Sql::new(exec.engine());
    sql.push("DELETE FROM ");
    sql.ident(M::TABLE);
    sql.push(" WHERE ");
    sql.compare(M::TABLE, M::PRIMARY_KEY, " = ", id);
    sql
}
