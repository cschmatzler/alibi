//! Application-owned provider fields exercise real schema and endpoint policies.
pub(crate) fn configure(config: &mut alibi::AuthConfig) {
    use alibi::field_policy::{FieldConfig, FieldDefault};
    use alibi::utils::json::JsValue;
    let fields = &mut config.advanced.database.sso_provider_fields.0;
    let mut label = FieldConfig::new(serde_json::json!({"type":"string"}));
    label.required = true;
    label.field_name = Some("application_label".into());
    _ = fields.insert("label".into(), label);
    let mut hidden = FieldConfig::new(serde_json::json!({"type":"string"}));
    hidden.returned = false;
    _ = fields.insert("privateNote".into(), hidden);
    let mut managed = FieldConfig::new(serde_json::json!({"type":"boolean"}));
    managed.input = false;
    managed.default = Some(FieldDefault::Value(JsValue::Bool(false)));
    _ = fields.insert("managed".into(), managed);
    let mut tier = FieldConfig::new(serde_json::json!({"type":"number"}));
    tier.default = Some(FieldDefault::Value(JsValue::Number(2.0)));
    _ = fields.insert("tier".into(), tier);
    _ = fields.insert(
        "tags".into(),
        FieldConfig::new(serde_json::json!({"type":"string[]"})),
    );
    _ = fields.insert(
        "settings".into(),
        FieldConfig::new(serde_json::json!({"type":"json"})),
    );
}
