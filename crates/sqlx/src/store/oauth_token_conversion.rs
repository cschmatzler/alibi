use super::SqlxStore;
use crate::{
    model::SqlxModel,
    pool::Exec,
    schema::{AuthSchema, SqlxAccountModel},
    sql::Sql,
};
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult,
    oauth_token_conversion::{OAuthTokenConversionStore, OAuthTokenSnapshot, OAuthTokenValues},
};

#[async_trait]
impl<S> OAuthTokenConversionStore<S> for SqlxStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Account: SqlxAccountModel,
{
    async fn compare_and_swap_oauth_tokens(
        &self,
        observed: &OAuthTokenSnapshot,
        replacement: &OAuthTokenValues,
    ) -> AuthResult<bool> {
        let columns = S::Account::oauth_token_columns().ok_or_else(|| {
            AuthError::NotImplemented("Account token conversion columns are not configured".into())
        })?;
        let table = <S::Account as SqlxModel>::TABLE;
        let mut sql = Sql::with(self.exec().engine(), "UPDATE ");
        sql.ident(table);
        sql.push(" SET ");
        for (index, (column, value)) in columns
            .iter()
            .zip([
                &replacement.access_token,
                &replacement.refresh_token,
                &replacement.id_token,
            ])
            .enumerate()
        {
            if index > 0 {
                sql.push(", ");
            }
            sql.assign(column, value.clone());
        }
        sql.push(" WHERE ");
        // Validate application ID types, then compare their canonical physical
        // text too: an application NOCASE collation must not admit another owner.
        drop(S::Account::parse_id(&observed.id)?);
        drop(S::Account::parse_user_id(&observed.user_id)?);
        for (index, (column, value)) in [
            (S::Account::id_column(), &observed.id),
            (S::Account::user_id_column(), &observed.user_id),
            (S::Account::provider_id_column(), &observed.provider_id),
            (S::Account::account_id_column(), &observed.account_id),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                sql.push(" AND ");
            }
            sql.push("CAST(");
            sql.column(table, column);
            sql.push(" AS TEXT)");
            exact_collation(&mut sql);
            sql.push(" = ");
            sql.bind(value.clone());
        }
        for (column, value) in columns.iter().zip([
            &observed.tokens.access_token,
            &observed.tokens.refresh_token,
            &observed.tokens.id_token,
        ]) {
            sql.push(" AND ");
            // Override application collations: CAS compares the exact stored text.
            sql.column(table, column);
            exact_collation(&mut sql);
            if let Some(value) = value {
                sql.push(" = ");
                sql.bind(value.clone());
            } else {
                sql.push(" IS NULL");
            }
        }
        self.in_transaction(true, async move |tx| {
            Ok(Exec::Tx(tx).execute(sql).await? == 1)
        })
        .await
    }
}

fn exact_collation(sql: &mut Sql) {
    match sql.engine() {
        crate::pool::Engine::Sqlite => sql.push(" COLLATE BINARY"),
        crate::pool::Engine::Postgres => sql.push(" COLLATE \"C\""),
    }
}
