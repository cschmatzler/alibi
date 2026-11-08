use super::*;

pub(super) async fn update<M: SqlxSessionModel>(
    exec: Exec<'_>,
    current: Option<M>,
    token: &str,
    expires_at: Option<DateTime<Utc>>,
    fields: &FieldValues,
    owns_updated_at: bool,
) -> AuthResult<Option<M>> {
    let missing = current.is_none();
    let mut active = current.map_or_else(ActiveRow::new, SqlxModel::into_active);
    if !owns_updated_at {
        M::set_updated_at(&mut active, Utc::now().trunc_subsecs(3));
    }
    if !fields.is_empty() {
        stage::<M>(exec, &mut active, fields).await?;
    }
    if let Some(expiry) = expires_at {
        M::set_expires_at(&mut active, expiry);
    }
    let (locator, key) = if missing {
        (M::token_column(), token.into())
    } else {
        let key = active
            .get(M::PRIMARY_KEY)
            .and_then(crate::model::ActiveValue::value)
            .cloned()
            .ok_or_else(|| AuthError::internal("model update requires its primary key"))?;
        (M::PRIMARY_KEY, key)
    };
    model::update_by_column::<M>(exec, &active, locator, key).await
}

pub(super) async fn stage<M: SqlxSessionModel>(
    exec: Exec<'_>,
    active: &mut ActiveRow,
    fields: &FieldValues,
) -> AuthResult<()> {
    let backend = exec.engine();
    let prepared = M::additional_field_bindings(&fields.prepared_text_inputs(), backend)?
        .into_iter()
        .map(|(column, _)| column)
        .collect::<std::collections::BTreeSet<_>>();
    for (column, value) in M::additional_field_bindings(fields, backend)? {
        let kind = M::column_kind(column);
        if matches!(
            kind,
            crate::value::ColumnKind::Timestamp | crate::value::ColumnKind::NaiveTimestamp
        ) && (matches!(&value, alibi_core::store::adapter::RawFieldValue::Null)
            || (prepared.contains(column)
                && matches!(&value, alibi_core::store::adapter::RawFieldValue::Text(_))))
        {
            active.set(column, crate::additional_fields::bind_scalar(value)?);
        } else {
            let value = crate::additional_fields::prepare_value(exec, kind, value).await?;
            M::set_additional_field(active, column, value, backend)?;
        }
    }
    Ok(())
}
