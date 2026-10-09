//! Statement-level namespace policy, retained across nested transactions.
use alibi_core::config::TwoFactorDatabaseConfig;
use async_trait::async_trait;
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr,
    ExecResult, IsolationLevel, QueryResult, Statement, TransactionError, TransactionOptions,
    TransactionSession, TransactionTrait,
};
use std::{future::Future, pin::Pin};

#[derive(Clone, Debug)]
pub(crate) struct Scoped<C> {
    pub(super) inner: C,
    pub(super) schema: Option<String>,
    pub(super) factor: Option<TwoFactorDatabaseConfig>,
}
pub(super) type ScopedConnection = Scoped<DatabaseConnection>;
pub(super) type ScopedTransaction = Scoped<DatabaseTransaction>;

impl<C: ConnectionTrait> Scoped<C> {
    pub(super) fn get_database_backend(&self) -> DbBackend {
        self.inner.get_database_backend()
    }
    fn sql(&self, mut sql: String) -> Result<String, DbErr> {
        if let Some(mapping) = &self.factor {
            sql = alibi_core::database_sql::map_two_factor(&sql, mapping)
                .map_err(|error| DbErr::Custom(error.to_string()))?;
        }
        if self.inner.get_database_backend() == DbBackend::Postgres
            && let Some(schema) = &self.schema
        {
            return alibi_core::database_sql::qualify_schema(&sql, schema)
                .map_err(|error| DbErr::Custom(error.to_string()));
        }
        Ok(sql)
    }
    fn statement(&self, mut statement: Statement) -> Result<Statement, DbErr> {
        statement.sql = self.sql(statement.sql)?;
        Ok(statement)
    }
}
#[async_trait]
impl<C: ConnectionTrait + Send + Sync> ConnectionTrait for Scoped<C> {
    fn get_database_backend(&self) -> DbBackend {
        self.inner.get_database_backend()
    }
    async fn execute_raw(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.inner.execute_raw(self.statement(stmt)?).await
    }
    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.inner
            .execute_unprepared(&self.sql(sql.to_owned())?)
            .await
    }
    async fn query_one_raw(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.inner.query_one_raw(self.statement(stmt)?).await
    }
    async fn query_all_raw(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.inner.query_all_raw(self.statement(stmt)?).await
    }
    fn support_returning(&self) -> bool {
        self.inner.support_returning()
    }
    fn is_mock_connection(&self) -> bool {
        self.inner.is_mock_connection()
    }
}
#[async_trait]
impl<C> TransactionTrait for Scoped<C>
where
    C: ConnectionTrait + TransactionTrait<Transaction = DatabaseTransaction> + Send + Sync,
{
    type Transaction = ScopedTransaction;
    async fn begin(&self) -> Result<Self::Transaction, DbErr> {
        Ok(Scoped {
            inner: self.inner.begin().await?,
            schema: self.schema.clone(),
            factor: self.factor.clone(),
        })
    }
    async fn begin_with_config(
        &self,
        isolation: Option<IsolationLevel>,
        access: Option<AccessMode>,
    ) -> Result<Self::Transaction, DbErr> {
        Ok(Scoped {
            inner: self.inner.begin_with_config(isolation, access).await?,
            schema: self.schema.clone(),
            factor: self.factor.clone(),
        })
    }
    async fn begin_with_options(
        &self,
        options: TransactionOptions,
    ) -> Result<Self::Transaction, DbErr> {
        Ok(Scoped {
            inner: self.inner.begin_with_options(options).await?,
            schema: self.schema.clone(),
            factor: self.factor.clone(),
        })
    }
    async fn transaction<F, T, E>(&self, callback: F) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c Self::Transaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        self.transaction_with_config(callback, None, None).await
    }
    async fn transaction_with_config<F, T, E>(
        &self,
        callback: F,
        isolation: Option<IsolationLevel>,
        access: Option<AccessMode>,
    ) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c Self::Transaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: std::fmt::Display + std::fmt::Debug + Send,
    {
        let transaction = self
            .begin_with_config(isolation, access)
            .await
            .map_err(TransactionError::Connection)?;
        match callback(&transaction).await {
            Ok(value) => {
                transaction
                    .commit()
                    .await
                    .map_err(TransactionError::Connection)?;
                Ok(value)
            }
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .map_err(TransactionError::Connection)?;
                Err(TransactionError::Transaction(error))
            }
        }
    }
}
#[async_trait]
impl TransactionSession for ScopedTransaction {
    async fn commit(self) -> Result<(), DbErr> {
        self.inner.commit().await
    }
    async fn rollback(self) -> Result<(), DbErr> {
        self.inner.rollback().await
    }
}

impl ScopedTransaction {
    pub(super) async fn commit(self) -> Result<(), DbErr> {
        self.inner.commit().await
    }
    pub(super) async fn rollback(self) -> Result<(), DbErr> {
        self.inner.rollback().await
    }
    pub(super) async fn has_table(&self, table: &str) -> Result<bool, DbErr> {
        if self.get_database_backend() == DbBackend::Postgres {
            let (sql, values) = if let Some(schema) = &self.schema {
                (
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
                    vec![schema.clone().into(), table.to_owned().into()],
                )
            } else {
                (
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1",
                    vec![table.to_owned().into()],
                )
            };
            let row = self
                .inner
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    values,
                ))
                .await?;
            return row
                .map(|row| row.try_get::<i64>("", "count").map(|count| count > 0))
                .transpose()
                .map(|value| value.unwrap_or(false));
        }
        sea_orm_migration::SchemaManager::new(&self.inner)
            .has_table(table)
            .await
    }
}

impl ScopedConnection {
    pub(super) async fn has_table(&self, table: &str) -> Result<bool, DbErr> {
        if self.get_database_backend() == DbBackend::Postgres {
            let (sql, values) = if let Some(schema) = &self.schema {
                (
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
                    vec![schema.clone().into(), table.to_owned().into()],
                )
            } else {
                (
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = CURRENT_SCHEMA() AND table_name = $1",
                    vec![table.to_owned().into()],
                )
            };
            let row = self
                .inner
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    sql,
                    values,
                ))
                .await?;
            return row
                .map(|row| row.try_get::<i64>("", "count").map(|count| count > 0))
                .transpose()
                .map(|value| value.unwrap_or(false));
        }
        sea_orm_migration::SchemaManager::new(&self.inner)
            .has_table(table)
            .await
    }
}
