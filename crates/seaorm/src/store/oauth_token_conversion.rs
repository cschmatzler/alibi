use super::{SeaOrmStore, map_db_err};
use crate::schema::{AuthSchema, SeaOrmAccountModel};
use async_trait::async_trait;
use better_auth_core::{
    AuthError, AuthResult,
    oauth_token_conversion::{OAuthTokenConversionStore, OAuthTokenSnapshot, OAuthTokenValues},
};
use sea_orm::{
    ColumnTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, SimpleExpr},
};

#[async_trait]
impl<S> OAuthTokenConversionStore<S> for SeaOrmStore<S>
where
    S: AuthSchema + Send + Sync,
    S::Account: SeaOrmAccountModel,
{
    async fn compare_and_swap_oauth_tokens(
        &self,
        observed: &OAuthTokenSnapshot,
        replacement: &OAuthTokenValues,
    ) -> AuthResult<bool> {
        let columns = S::Account::oauth_token_columns().ok_or_else(|| {
            AuthError::NotImplemented("Account token conversion columns are not configured".into())
        })?;
        let backend = self.connection().get_database_backend();
        let template = match backend {
            sea_orm::DbBackend::Sqlite => "CAST(? AS TEXT) COLLATE BINARY = ?",
            sea_orm::DbBackend::Postgres => "CAST($1 AS TEXT) COLLATE \"C\" = $2",
            _ => {
                return Err(AuthError::NotImplemented(
                    "OAuth token conversion requires SQLite or PostgreSQL".into(),
                ));
            }
        };
        drop(S::Account::parse_id(&observed.id)?);
        drop(S::Account::parse_user_id(&observed.user_id)?);
        let mut query = <S::Account as SeaOrmAccountModel>::Entity::update_many();
        for (column, value) in [
            (S::Account::id_column(), &observed.id),
            (S::Account::user_id_column(), &observed.user_id),
            (S::Account::provider_id_column(), &observed.provider_id),
            (S::Account::account_id_column(), &observed.account_id),
        ] {
            query = query.filter(Expr::cust_with_exprs(
                template,
                [Expr::col(column), Expr::value(value.clone())],
            ));
        }
        for (column, value) in columns.iter().zip([
            &replacement.access_token,
            &replacement.refresh_token,
            &replacement.id_token,
        ]) {
            query = query.col_expr(*column, Expr::value(value.clone()));
        }
        for (column, value) in columns.iter().zip([
            &observed.tokens.access_token,
            &observed.tokens.refresh_token,
            &observed.tokens.id_token,
        ]) {
            let predicate: SimpleExpr = if let Some(value) = value {
                Expr::cust_with_exprs(template, [Expr::col(*column), Expr::value(value.clone())])
            } else {
                column.is_null()
            };
            query = query.filter(predicate);
        }
        Ok(query
            .exec(self.connection())
            .await
            .map_err(map_db_err)?
            .rows_affected
            == 1)
    }
}
