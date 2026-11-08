use super::*;
use alibi_core::store::adapter::RawFieldValue;
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Query};
use sea_orm::{ActiveModelBehavior, ActiveValue, DbBackend, EntityName, Iden, Iterable};

pub(super) async fn stage<M: SeaOrmSessionModel, C: ConnectionTrait>(
    db: &C,
    active: &mut M::ActiveModel,
    fields: &FieldValues,
) -> AuthResult<Vec<(M::Column, sea_orm::Value)>> {
    let backend = db.get_database_backend();
    let prepared = M::additional_field_bindings(&fields.prepared_text_inputs(), backend)?
        .into_iter()
        .map(|(column, _)| column.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    if prepared.is_empty() {
        stage_additional_fields::<M, _>(db, active, fields).await?;
        return Ok(Vec::new());
    }
    let mut native = Vec::new();
    for (column, value) in M::additional_field_bindings(fields, backend)? {
        if prepared.contains(&column.to_string())
            && matches!(
                column.def().get_column_type(),
                sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                    | sea_orm::sea_query::ColumnType::Timestamp
                    | sea_orm::sea_query::ColumnType::DateTime
            )
            && matches!(&value, RawFieldValue::Text(_))
        {
            native.push((column, crate::additional_fields::bind_scalar(value)?));
        } else {
            let value = crate::additional_fields::prepare_value(db, &column, value).await?;
            M::set_additional_field(active, column, value, backend)?;
        }
    }
    Ok(native)
}

pub(super) async fn save<M: SeaOrmSessionModel, C: ConnectionTrait>(
    mut active: M::ActiveModel,
    db: &C,
    token: Option<&str>,
    native: Vec<(M::Column, sea_orm::Value)>,
) -> AuthResult<Option<M>> {
    let insert = token.is_none();
    let changed =
        <M::Entity as EntityTrait>::Column::iter().any(|column| active.get(column).is_set());
    if native.is_empty() && (insert || changed) {
        return if insert {
            active.insert(db).await.map(Some).map_err(map_db_err)
        } else {
            match active.update(db).await {
                Ok(session) => Ok(Some(session)),
                Err(sea_orm::DbErr::RecordNotUpdated) => Ok(None),
                Err(error) => Err(map_db_err(error)),
            }
        };
    }
    active = ActiveModelBehavior::before_save(active, db, insert)
        .await
        .map_err(map_db_err)?;
    let backend = db.get_database_backend();
    let inserted_token = if backend == DbBackend::MySql && insert {
        let column = <M::Entity as EntityTrait>::Column::iter()
            .find(|column| column.to_string() == M::token_column().to_string())
            .ok_or_else(|| AuthError::config("Session entity does not expose its token column"))?;
        active.get(column).into_value()
    } else {
        None
    };
    let mut columns = Vec::new();
    let mut values = Vec::new();
    for column in <M::Entity as EntityTrait>::Column::iter() {
        let override_value = native
            .iter()
            .find(|(physical, _)| physical.to_string() == column.to_string())
            .map(|(_, value)| value.clone());
        let staged = match active.take(column) {
            ActiveValue::Set(value) => Some(value),
            ActiveValue::Unchanged(value) if insert => Some(value),
            _ => None,
        };
        if let Some(value) = override_value.or(staged) {
            let expression = if backend == DbBackend::Postgres {
                match &value {
                    sea_orm::Value::String(Some(value))
                        if matches!(
                            column.def().get_column_type(),
                            sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                                | sea_orm::sea_query::ColumnType::Timestamp
                                | sea_orm::sea_query::ColumnType::DateTime
                        ) =>
                    {
                        Expr::cust(alibi_core::store::postgres_parameter::quoted_literal(value))
                            .cast_as(Alias::new(
                                if matches!(
                                    column.def().get_column_type(),
                                    sea_orm::sea_query::ColumnType::TimestampWithTimeZone
                                ) {
                                    "timestamptz"
                                } else {
                                    "timestamp"
                                },
                            ))
                    }
                    _ => Expr::val(value).into(),
                }
            } else {
                Expr::val(value).into()
            };
            columns.push(column);
            values.push(column.save_as(expression));
        }
    }
    let statement = if let Some(token) = token {
        let mut query = Query::update()
            .table(M::Entity::default().table_ref())
            .values(columns.into_iter().zip(values))
            .and_where(M::token_column().eq(token))
            .to_owned();
        if backend != DbBackend::MySql {
            _ = query
                .returning(Query::returning().columns(<M::Entity as EntityTrait>::Column::iter()));
        }
        backend.build(&query)
    } else {
        let mut query = Query::insert()
            .into_table(M::Entity::default().table_ref())
            .columns(columns)
            .values(values)
            .map_err(|error| AuthError::internal(error.to_string()))?
            .to_owned();
        if backend != DbBackend::MySql {
            _ = query
                .returning(Query::returning().columns(<M::Entity as EntityTrait>::Column::iter()));
        }
        backend.build(&query)
    };
    let session = if backend == DbBackend::MySql {
        let result = db.execute_raw(statement).await.map_err(map_db_err)?;
        if !insert && result.rows_affected() == 0 {
            return Ok(None);
        }
        let lookup = if let Some(token) = token {
            M::token_column().eq(token)
        } else {
            M::token_column().eq(inserted_token
                .ok_or_else(|| AuthError::internal("Inserted session has no token locator"))?)
        };
        let Some(session) = M::Entity::find()
            .filter(lookup)
            .one(db)
            .await
            .map_err(map_db_err)?
        else {
            return Ok(None);
        };
        session
    } else {
        let Some(row) = db.query_one_raw(statement).await.map_err(map_db_err)? else {
            return Ok(None);
        };
        M::from_query_result(&row, "").map_err(map_db_err)?
    };
    <M::ActiveModel as ActiveModelBehavior>::after_save(session, db, insert)
        .await
        .map(Some)
        .map_err(map_db_err)
}
