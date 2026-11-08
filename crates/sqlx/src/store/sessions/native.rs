use super::*;

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
    if prepared.is_empty() {
        return stage_additional_fields::<M>(exec, active, fields).await;
    }
    for (column, value) in M::additional_field_bindings(fields, backend)? {
        let kind = M::column_kind(column);
        if prepared.contains(column)
            && matches!(
                kind,
                crate::value::ColumnKind::Timestamp | crate::value::ColumnKind::NaiveTimestamp
            )
            && matches!(&value, alibi_core::store::adapter::RawFieldValue::Text(_))
        {
            active.set(column, crate::additional_fields::bind_scalar(value)?);
        } else {
            let value = crate::additional_fields::prepare_value(exec, kind, value).await?;
            M::set_additional_field(active, column, value, backend)?;
        }
    }
    Ok(())
}
