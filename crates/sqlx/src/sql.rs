//! Statement text and its typed arguments, rendered for one engine.

use crate::pool::Engine;
use crate::value::SqlValue;
use sqlx::Arguments;
use sqlx::error::BoxDynError;
use std::fmt::Write;

/// SQL text with bound arguments. Placeholders follow the engine's syntax.
#[derive(Clone, Debug)]
pub(crate) struct Sql {
    engine: Engine,
    text: String,
    args: Vec<SqlValue>,
}

impl Sql {
    pub(crate) const fn new(engine: Engine) -> Self {
        Self {
            engine,
            text: String::new(),
            args: Vec::new(),
        }
    }

    pub(crate) fn with(engine: Engine, text: &str) -> Self {
        let mut sql = Self::new(engine);
        sql.push(text);
        sql
    }

    pub(crate) const fn engine(&self) -> Engine {
        self.engine
    }

    pub(crate) fn push(&mut self, text: &str) {
        self.text.push_str(text);
    }

    /// Append a double-quoted identifier.
    pub(crate) fn ident(&mut self, name: &str) {
        self.text.push('"');
        self.text.push_str(&name.replace('"', "\"\""));
        self.text.push('"');
    }

    /// Append `"table"."column"`.
    pub(crate) fn column(&mut self, table: &str, column: &str) {
        self.ident(table);
        self.push(".");
        self.ident(column);
    }

    /// Append `"table"."column" <operator> ?`, the predicate of most lookups.
    pub(crate) fn compare(
        &mut self,
        table: &str,
        column: &str,
        operator: &str,
        value: impl Into<SqlValue>,
    ) {
        self.column(table, column);
        self.push(operator);
        self.bind(value);
    }

    /// Append `"column" = ?`, one `SET` assignment.
    pub(crate) fn assign(&mut self, column: &str, value: impl Into<SqlValue>) {
        self.ident(column);
        self.push(" = ");
        self.bind(value);
    }

    /// Append one placeholder bound to `value`.
    pub(crate) fn bind(&mut self, value: impl Into<SqlValue>) {
        self.args.push(value.into());
        match self.engine {
            Engine::Sqlite => self.text.push('?'),
            Engine::Postgres => {
                _ = write!(self.text, "${}", self.args.len());
            }
        }
    }

    /// Append `(?, ?, ...)` for a non-empty list.
    pub(crate) fn bind_list<I>(&mut self, values: I)
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
        self.push(")");
    }

    /// Append the qualified select list `"t"."a", "t"."b"`.
    pub(crate) fn select_list(&mut self, table: &str, columns: &[&str]) {
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                self.push(", ");
            }
            self.column(table, column);
        }
    }

    /// Append the unqualified list `"a", "b"`.
    pub(crate) fn column_list(&mut self, columns: &[&str]) {
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                self.push(", ");
            }
            self.ident(column);
        }
    }

    pub(crate) fn into_parts(self) -> (String, Vec<SqlValue>) {
        (self.text, self.args)
    }
}

/// `SELECT "t"."a", ... FROM "t"`.
pub(crate) fn select(engine: Engine, table: &str, columns: &[&str]) -> Sql {
    let mut sql = Sql::new(engine);
    sql.push("SELECT ");
    sql.select_list(table, columns);
    sql.push(" FROM ");
    sql.ident(table);
    sql
}

#[cfg(feature = "sqlite")]
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

#[cfg(feature = "postgres")]
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
