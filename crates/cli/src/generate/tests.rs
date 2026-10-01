use super::{generate_schema, list_plugins};

#[test]
fn list_plugins_includes_passkey() {
    assert!(list_plugins().contains(&"passkey"));
}

#[test]
fn generate_schema_with_passkey_emits_entity_and_migration() {
    let schema = generate_schema(&["passkey".to_owned()]);

    assert!(schema.contains("mod passkey"));
    assert!(schema.contains("#[sea_orm(table_name = \"passkeys\")]"));
    assert!(schema.contains("pub credential: String"));
    assert!(schema.contains("pub aaguid: Option<String>"));
    assert!(schema.contains("schema.create_table_from_entity(passkey::Entity)"));
}

#[test]
fn generate_schema_builtin_plugins_emit_required_entities() {
    let schema = generate_schema(&[
        "device-authorization".to_owned(),
        "api-key".to_owned(),
        "organization".to_owned(),
        "passkey".to_owned(),
    ]);

    assert!(schema.contains("mod device_code"));
    assert!(schema.contains("mod api_key"));
    assert!(schema.contains("mod organization"));
    assert!(schema.contains("mod member"));
    assert!(schema.contains("mod invitation"));
    assert!(schema.contains("#[sea_orm(column_name = \"key\")]"));
    assert!(schema.contains("schema.create_table_from_entity(device_code::Entity)"));
    assert!(schema.contains("schema.create_table_from_entity(api_key::Entity)"));
    assert!(schema.contains("schema.create_table_from_entity(organization::Entity)"));
    assert!(schema.contains("schema.create_table_from_entity(member::Entity)"));
    assert!(schema.contains("schema.create_table_from_entity(invitation::Entity)"));
}
