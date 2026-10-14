//! Date-valued application input uses the same durable column on both adapters.
pub(crate) fn configure(config: &mut alibi::AuthConfig) {
    let mut field = alibi::field_policy::FieldConfig::new(serde_json::json!({"type":"date"}));
    field.required = true;
    field.field_name = Some("application_anniversary".into());
    _ = config
        .advanced
        .database
        .sso_provider_fields
        .0
        .insert("anniversary".into(), field);
}
