use super::{map_db_err, scoped_connection::ScopedConnection};
use alibi_core::AuthResult;
use sea_orm::{EntityTrait, QuerySelect, Select, TransactionTrait, UpdateMany};

pub(super) async fn update<E: EntityTrait>(
    database: &ScopedConnection,
    locking: Select<E>,
    readback: Select<E>,
    query: UpdateMany<E>,
) -> AuthResult<Option<E::Model>> {
    let tx = database.begin().await.map_err(map_db_err)?;
    let locked = locking
        .lock_exclusive()
        .one(&tx)
        .await
        .map_err(map_db_err)?;
    let model = if locked.is_some() && query.exec(&tx).await.map_err(map_db_err)?.rows_affected > 0
    {
        readback.one(&tx).await.map_err(map_db_err)?
    } else {
        None
    };
    tx.commit().await.map_err(map_db_err)?;
    Ok(model)
}
