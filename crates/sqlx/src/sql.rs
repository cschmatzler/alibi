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
            SqlValue::NaiveTimestamp(value) => args.add(value)?,
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
            SqlValue::NaiveTimestamp(value) => args.add(value)?,
            SqlValue::Uuid(value) => args.add(value)?,
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    #[expect(
        clippy::panic_in_result_fn,
        reason = "database setup returns errors; protocol assertions must fail the test"
    )]
    #[tokio::test]
    #[ignore = "requires BETTER_AUTH_TEST_POSTGRES_URL"]
    async fn postgres_timestamp_arguments_retain_wire_types_including_nulls()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = std::env::var("BETTER_AUTH_TEST_POSTGRES_URL")?;
        let pool = sqlx::PgPool::connect(&url).await?;
        let instant: chrono::DateTime<chrono::Utc> = "2026-10-04T12:00:00Z".parse()?;
        let args = super::postgres_arguments(vec![
            instant.naive_utc().into(),
            None::<chrono::NaiveDateTime>.into(),
            instant.into(),
            None::<chrono::DateTime<chrono::Utc>>.into(),
        ])?;
        let types: (String, String, String, String) = sqlx::query_as_with(
            "SELECT pg_typeof($1)::text, pg_typeof($2)::text, pg_typeof($3)::text, pg_typeof($4)::text",
            args,
        ).fetch_one(&pool).await?;
        eprintln!("PostgreSQL timestamp parameter types: {types:?}");
        assert_eq!(
            types,
            (
                "timestamp without time zone".into(),
                "timestamp without time zone".into(),
                "timestamp with time zone".into(),
                "timestamp with time zone".into(),
            )
        );
        Ok(())
    }
}
