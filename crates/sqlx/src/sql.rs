//! Statement text and its typed arguments, rendered for one backend.

use crate::pool::SqlxBackend;
use crate::value::SqlValue;
use sqlx::Arguments;
use sqlx::error::BoxDynError;
use std::fmt::Write;

/// SQL text with bound arguments. Placeholders follow the backend's syntax.
#[derive(Clone, Debug)]
pub(crate) struct Sql {
    backend: SqlxBackend,
    text: String,
    args: Vec<SqlValue>,
}

impl Sql {
    pub(crate) const fn new(backend: SqlxBackend) -> Self {
        Self {
            backend,
            text: String::new(),
            args: Vec::new(),
        }
    }

    pub(crate) fn with(backend: SqlxBackend, text: &str) -> Self {
        let mut sql = Self::new(backend);
        sql.push(text);
        sql
    }

    pub(crate) const fn backend(&self) -> SqlxBackend {
        self.backend
    }

    pub(crate) fn push(&mut self, text: &str) -> &mut Self {
        self.text.push_str(text);
        self
    }

    /// Append a double-quoted identifier.
    pub(crate) fn ident(&mut self, name: &str) -> &mut Self {
        self.text.push('"');
        self.text.push_str(&name.replace('"', "\"\""));
        self.text.push('"');
        self
    }

    /// Append `"table"."column"`.
    pub(crate) fn column(&mut self, table: &str, column: &str) -> &mut Self {
        self.ident(table).push(".").ident(column)
    }

    /// Append one placeholder bound to `value`.
    pub(crate) fn bind(&mut self, value: impl Into<SqlValue>) -> &mut Self {
        self.args.push(value.into());
        match self.backend {
            SqlxBackend::Sqlite => self.text.push('?'),
            SqlxBackend::Postgres => {
                _ = write!(self.text, "${}", self.args.len());
            }
        }
        self
    }

    /// Append `(?, ?, ...)` for a non-empty list.
    pub(crate) fn bind_list<I>(&mut self, values: I) -> &mut Self
    where
        I: IntoIterator,
        I::Item: Into<SqlValue>,
    {
        self.push("(");
        for (index, value) in values.into_iter().enumerate() {
            if index > 0 {
                self.push(", ");
            }
            self.bind(value);
        }
        self.push(")")
    }

    /// Append the qualified select list `"t"."a", "t"."b"`.
    pub(crate) fn select_list(&mut self, table: &str, columns: &[&str]) -> &mut Self {
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                self.push(", ");
            }
            self.column(table, column);
        }
        self
    }

    /// Append the unqualified list `"a", "b"`.
    pub(crate) fn column_list(&mut self, columns: &[&str]) -> &mut Self {
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                self.push(", ");
            }
            self.ident(column);
        }
        self
    }

    pub(crate) fn into_parts(self) -> (String, Vec<SqlValue>) {
        (self.text, self.args)
    }
}

/// `SELECT "t"."a", ... FROM "t"`.
pub(crate) fn select(backend: SqlxBackend, table: &str, columns: &[&str]) -> Sql {
    let mut sql = Sql::new(backend);
    sql.push("SELECT ")
        .select_list(table, columns)
        .push(" FROM ")
        .ident(table);
    sql
}

pub(crate) fn sqlite_arguments(
    values: Vec<SqlValue>,
) -> Result<sqlx::sqlite::SqliteArguments, BoxDynError> {
    let mut args = sqlx::sqlite::SqliteArguments::default();
    for value in values {
        match value {
            SqlValue::Bool(value) => args.add(value)?,
            SqlValue::Int(value) => args.add(value)?,
            SqlValue::BigInt(value) => args.add(value)?,
            SqlValue::Float(value) => args.add(value)?,
            SqlValue::Double(value) => args.add(value)?,
            SqlValue::Text(value) => args.add(value)?,
            SqlValue::Bytes(value) => args.add(value)?,
            SqlValue::Json(value) => args.add(value.map(|value| *value))?,
            SqlValue::Timestamp(value) => args.add(value)?,
            SqlValue::Uuid(value) => args.add(value)?,
        }
    }
    Ok(args)
}

pub(crate) fn postgres_arguments(
    values: Vec<SqlValue>,
) -> Result<sqlx::postgres::PgArguments, BoxDynError> {
    let mut args = sqlx::postgres::PgArguments::default();
    for value in values {
        match value {
            SqlValue::Bool(value) => args.add(value)?,
            SqlValue::Int(value) => args.add(value)?,
            SqlValue::BigInt(value) => args.add(value)?,
            SqlValue::Float(value) => args.add(value)?,
            SqlValue::Double(value) => args.add(value)?,
            SqlValue::Text(value) => args.add(value)?,
            SqlValue::Bytes(value) => args.add(value)?,
            SqlValue::Json(value) => args.add(value.as_deref())?,
            SqlValue::Timestamp(value) => args.add(value)?,
            SqlValue::Uuid(value) => args.add(value)?,
        }
    }
    Ok(args)
}
